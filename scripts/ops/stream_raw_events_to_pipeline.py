#!/usr/bin/env python3
"""
========================================================================================
WAZUH STREAMING RAW EVENTS WORKER: FLUENT BIT -> POSTGRESQL -> ASOC PIPELINE
========================================================================================
Mengalirkan event mentah yang ditulis oleh Fluent Bit (out_postgre) di telemetry.raw_events
ke seluruh siklus ASOC Pipeline:
  telemetry.raw_events
    -> telemetry.normalized_events (Normalisasi CEM)
    -> suppression.aggregated_alerts & evidence_mapping (Deduplikasi Sliding Window)
    -> correlation.correlated_incidents & stages (Korelasi Rantai Serangan)
    -> risk_engine.calculated_risk_scores & factors (Dynamic Risk Scoring P0-P4)
    -> soc_ops.soc_triage_queue (Tiket Triage Analis SOC + SLA Earliest Deadline First)

Cara pakai:
  python scripts/ops/stream_raw_events_to_pipeline.py --once
  python scripts/ops/stream_raw_events_to_pipeline.py --continuous --interval 2
"""

import os
import sys
import time
import json
import signal
import argparse
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

# Tambahkan root directory ke sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from pipeline.database import DatabaseManager
from pipeline.ingest import AlertStreamReader
from pipeline.deduplicate import SlidingWindowAggregator
from pipeline.correlate import CorrelationEngine
from pipeline.score import RiskScorer
from pipeline.update_edf_view import update_queue_view_edf
from pipeline.p4_sla_worker import process_expired_p4_tickets


CHECKPOINT_SOURCE = "fluentbit_raw_events"


def get_streaming_checkpoint(db: DatabaseManager) -> tuple[Optional[datetime], Optional[str], int]:
    """Mengambil checkpoint terakhir dari telemetry.ingest_checkpoints."""
    query = """
    SELECT last_processed_timestamp, last_processed_event_id, records_processed_total
    FROM telemetry.ingest_checkpoints
    WHERE source_name = %s;
    """
    try:
        with db.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query, (CHECKPOINT_SOURCE,))
                row = cur.fetchone()
                if row:
                    return row[0], row[1], row[2] or 0
    except Exception as e:
        # Fallback jika kolom source_name adalah tenant_id di skema lama
        try:
            with db.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT last_timestamp, last_event_id, cursor_offset
                        FROM telemetry.ingest_checkpoints
                        WHERE tenant_id = %s;
                    """, (CHECKPOINT_SOURCE,))
                    row = cur.fetchone()
                    if row:
                        return row[0], row[1], row[2] or 0
        except Exception:
            pass
    return None, None, 0


def save_streaming_checkpoint(db: DatabaseManager, last_ts: datetime, last_eid: str, processed_count: int):
    """Menyimpan checkpoint pemrosesan telemetri mentah."""
    query = """
    INSERT INTO telemetry.ingest_checkpoints (source_name, last_processed_timestamp, last_processed_event_id, records_processed_total, updated_at)
    VALUES (%s, %s, %s, %s, NOW())
    ON CONFLICT (source_name) DO UPDATE SET
        last_processed_timestamp = EXCLUDED.last_processed_timestamp,
        last_processed_event_id = EXCLUDED.last_processed_event_id,
        records_processed_total = telemetry.ingest_checkpoints.records_processed_total + EXCLUDED.records_processed_total,
        updated_at = NOW();
    """
    try:
        with db.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query, (CHECKPOINT_SOURCE, last_ts, last_eid, processed_count))
    except Exception:
        # Fallback kompatibilitas dengan skema lama (tenant_id)
        try:
            with db.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO telemetry.ingest_checkpoints (tenant_id, last_timestamp, last_event_id, cursor_offset, updated_at)
                        VALUES (%s, %s, %s, %s, NOW())
                        ON CONFLICT (tenant_id) DO UPDATE SET
                            last_timestamp = EXCLUDED.last_timestamp,
                            last_event_id = EXCLUDED.last_event_id,
                            cursor_offset = telemetry.ingest_checkpoints.cursor_offset + EXCLUDED.cursor_offset,
                            updated_at = NOW();
                    """, (CHECKPOINT_SOURCE, last_ts, last_eid, processed_count))
        except Exception as e:
            print(f"[-] Gagal menyimpan checkpoint: {e}")


def process_raw_stream_batch(
    db: DatabaseManager,
    reader: AlertStreamReader,
    dedup: SlidingWindowAggregator,
    correlation: CorrelationEngine,
    scorer: RiskScorer,
    batch_size: int = 5000,
    from_start: bool = False
) -> int:
    """Mengambil batch event baru dari telemetry.raw_events dan memprosesnya ke pipeline."""
    last_ts, last_eid, total_prev = (None, None, 0) if from_start else get_streaming_checkpoint(db)

    # Query event mentah baru dari PostgreSQL
    if last_ts is not None:
        sql = """
        SELECT event_id, timestamp, agent_id, tenant_id, agent_name, agent_ip,
               source_ip, destination_ip, source_port, destination_port,
               protocol, username, location, decoder_name, raw_payload
        FROM telemetry.raw_events
        WHERE timestamp > %s
        ORDER BY timestamp ASC
        LIMIT %s;
        """
        params = (last_ts, batch_size)
    else:
        sql = """
        SELECT event_id, timestamp, agent_id, tenant_id, agent_name, agent_ip,
               source_ip, destination_ip, source_port, destination_port,
               protocol, username, location, decoder_name, raw_payload
        FROM telemetry.raw_events
        ORDER BY timestamp ASC
        LIMIT %s;
        """
        params = (batch_size,)

    raw_rows = []
    with db.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            raw_rows = cur.fetchall()

    if not raw_rows:
        return 0

    print(f"[*] Menemukan {len(raw_rows):,} raw alert baru dari Fluent Bit di telemetry.raw_events...")

    norm_batch = []
    agg_batch = []
    evidence_batch = []
    new_incidents = []

    last_processed_ts = None
    last_processed_eid = None

    for row in raw_rows:
        eid, ts, agent_id, tenant_id, agent_name, agent_ip = row[0], row[1], row[2], row[3], row[4], row[5]
        src_ip, dst_ip, src_port, dst_port, protocol, username = row[6], row[7], row[8], row[9], row[10], row[11]
        location, decoder_name, raw_payload_str = row[12], row[13], row[14]

        last_processed_ts = ts
        last_processed_eid = eid

        # Parse JSON payload asli
        raw_dict = {}
        if raw_payload_str:
            try:
                raw_dict = json.loads(raw_payload_str)
            except Exception:
                pass

        if not raw_dict:
            raw_dict = {
                "id": eid,
                "timestamp": ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
                "agent": {"id": agent_id, "name": agent_name, "ip": agent_ip},
                "data": {
                    "srcip": src_ip, "dstip": dst_ip,
                    "srcport": src_port, "dstport": dst_port,
                    "proto": protocol, "user": username
                },
                "rule": {"id": "0", "level": 0, "description": "Raw Stream Ingested Event"},
                "location": location,
                "decoder": {"name": decoder_name}
            }

        # 1. Normalisasi ke CommonEventModel
        cem = reader.normalize_record(raw_dict)
        if cem is None:
            continue

        # 2. Siapkan baris normalized_events
        norm_batch.append({
            "normalized_event_id": f"NORM-{cem.event_id}",
            "raw_event_id": cem.event_id,
            "event_timestamp": cem.timestamp,
            "rule_id": int(cem.rule_id) if str(cem.rule_id).isdigit() else 0,
            "rule_level": cem.rule_level,
            "rule_description": cem.rule_description,
            "classification_groups": cem.classification_groups or [],
            "mitre_attack_ids": cem.mitre_attack_ids or [],
            "mitre_tactics": cem.mitre_tactics or [],
            "mitre_techniques": cem.mitre_techniques or [],
            "compliance_frameworks": cem.compliance_frameworks or {},
            "asset_criticality_tier": cem.host_criticality,
            "is_asset_internet_exposed": cem.is_internet_exposed,
            "is_privileged_user": cem.is_privileged_user,
            "is_service_account": cem.is_service_account,
            "threat_intel_match": False,
            "threat_intel_confidence": 0
        })

        # 3. Deduplikasi Sliding-Window (Reduksi Kebisingan)
        ready_aggs = []
        closed_agg = dedup.process_event(cem)
        if closed_agg:
            ready_aggs.append(closed_agg)
        drained = dedup.drain_completed_aggregates()
        if drained:
            ready_aggs.extend(drained)

        # 4. Korelasi Rantai Serangan & Scoring
        for c_agg in ready_aggs:
            c_agg["is_suppressed"] = False
            c_agg["status"] = "CLOSED"
            agg_batch.append(c_agg)

            agg_id = c_agg.get("aggregation_id")
            for (ev_id, ev_ts) in c_agg.get("raw_evidence", []):
                evidence_batch.append((agg_id, ev_id, ev_ts))

            incs = correlation.process_aggregate(c_agg)
            for inc in incs:
                if inc.get("_ticket_action") == "APPEND":
                    continue
                score_rec, factors, triage = scorer.evaluate_incident_risk(inc)
                inc["calculated_score"] = score_rec
                inc["risk_factors"] = factors
                inc["triage_queue"] = triage
                new_incidents.append(inc)

    # Simpan ke Database
    if norm_batch:
        try:
            db.bulk_insert_normalized_events(norm_batch)
        except Exception as e:
            print(f"[-] Error insert normalized_events: {e}")

    if agg_batch:
        try:
            db.bulk_upsert_aggregated_alerts(agg_batch)
            if evidence_batch:
                db.bulk_insert_evidence_mapping(evidence_batch)
        except Exception as e:
            print(f"[-] Error insert aggregated_alerts: {e}")

    if new_incidents:
        try:
            db.bulk_insert_incidents_and_triage(new_incidents)
            print(f"[+] Berhasil menerbitkan {len(new_incidents)} tiket insiden baru ke soc_ops.soc_triage_queue!")
        except Exception as e:
            print(f"[-] Error insert correlated_incidents / triage_queue: {e}")

    # Update Checkpoint
    if last_processed_ts and last_processed_eid:
        save_streaming_checkpoint(db, last_processed_ts, last_processed_eid, len(raw_rows))

    return len(raw_rows)


def run_worker(continuous: bool = False, interval_sec: int = 2, batch_size: int = 5000, from_start: bool = False):
    print("=" * 85)
    print("[*] ASOC STREAMING WORKER: TELEMETRY.RAW_EVENTS -> PIPELINE -> TRIAGE QUEUE")
    print(f"[*] Mode: {'CONTINUOUS DAEMON' if continuous else 'SINGLE PASS'} | Batch Size: {batch_size:,}")
    print("=" * 85)

    db = DatabaseManager()
    if not db.initialize_pool():
        print("[-] Gagal terhubung ke database PostgreSQL. Pastikan database aktif.")
        return

    reader = AlertStreamReader()
    dedup = SlidingWindowAggregator()
    correlation = CorrelationEngine(db_manager=db)
    scorer = RiskScorer()

    stop_requested = False

    def sig_handler(signum, frame):
        nonlocal stop_requested
        print("\n[!] Signal stop diterima. Menghentikan streaming worker secara aman...")
        stop_requested = True

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    total_processed = 0

    while not stop_requested:
        try:
            processed = process_raw_stream_batch(
                db=db,
                reader=reader,
                dedup=dedup,
                correlation=correlation,
                scorer=scorer,
                batch_size=batch_size,
                from_start=from_start and total_processed == 0
            )
            total_processed += processed

            if processed > 0:
                print(f"[+] Total telemetri diproses: {total_processed:,} events")

            if not continuous:
                break

            if processed < batch_size:
                time.sleep(interval_sec)
        except Exception as e:
            print(f"[-] Error pada iterasi worker: {e}")
            if continuous:
                time.sleep(interval_sec)
            else:
                break

    # Flush sisa aggregate di window memory sebelum shutdown
    remaining = dedup.flush_all()
    if remaining:
        print(f"[*] Flushing {len(remaining)} in-flight aggregates ke database...")
        db.bulk_upsert_aggregated_alerts(remaining)

    # Perbarui view EDF SLA
    try:
        update_queue_view_edf(db)
        process_expired_p4_tickets(db)
    except Exception:
        pass

    print(f"\n[+] Streaming worker selesai. Total event diproses sesi ini: {total_processed:,}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Streaming raw_events from Fluent Bit to ASOC Pipeline")
    parser.add_argument("--continuous", action="store_true", help="Jalankan secara terus menerus memantau telemetry.raw_events")
    parser.add_argument("--interval", type=int, default=2, help="Interval polling dalam detik jika continuous")
    parser.add_argument("--batch-size", type=int, default=5000, help="Jumlah raw event per batch query")
    parser.add_argument("--from-start", action="store_true", help="Abaikan checkpoint dan mulai dari event paling awal")
    parser.add_argument("--once", action="store_true", help="Jalankan satu kali pass lalu keluar")
    args = parser.parse_args()

    run_worker(
        continuous=args.continuous,
        interval_sec=args.interval,
        batch_size=args.batch_size,
        from_start=args.from_start
    )
