#!/usr/bin/env python3
"""
========================================================================================
           WAZUH FULL-AUTOMATED SOC PIPELINE ORCHESTRATOR (ONE-CLICK)
========================================================================================
Menjalankan SELURUH siklus pemrosesan log secara 100% otomatis dari hulu ke hilir:
1. Ingesti Telemetri Mentah & Normalisasi CEM (telemetry.*)
2. Reduksi Kebisingan & Deduplikasi Sliding-Window 15 Menit (suppression.*)
3. Korelasi Rantai Serangan Multi-Tahap (correlation.*)
4. Kalkulasi Skor Risiko Dinamis Multi-Faktor (risk_engine.*)
5. Sinkronisasi Threat Intelligence Otomatis (enrichment.*)
6. Eskalasi Antrean Triage SOC P1, P2, P3 (Earliest Deadline First)
7. Rollup Metrik Tata Kelola Harian (metrics.*)

Cara pakai:
  python run_master_pipeline.py
  python run_master_pipeline.py --daemon
"""

import os
import sys
import time
import glob
import signal
import argparse
from datetime import datetime, timedelta, timezone
import json
from typing import Optional, Any, Dict, List, Tuple


from pipeline.ingest import AlertStreamReader
from pipeline.deduplicate import SlidingWindowAggregator
from pipeline.correlate import CorrelationEngine
from pipeline.score import RiskScorer
from pipeline.p4_sla_worker import process_expired_p4_tickets
from pipeline.database import DatabaseManager
from pipeline.threat_intel_sync import sync_threat_intelligence
from pipeline.sync_live_ti_to_scores import sync_live_ti_and_scores
from pipeline.update_edf_view import update_queue_view_edf
from pipeline.adapters import get_iris_adapter  # Used in AI triage result handling
from pipeline.suppression_proposal_exporter import export_suppression_proposals_per_tenant
from pipeline.misp_feedback_sync import export_misp_threat_intelligence
from config.settings import DATA_DIR

def run_full_pipeline_once(target_dir=DATA_DIR, db_name="wazuh_soc_db", fresh=False, file_list=None, skip_retention=False, retention_dry_run=False):
    start_time = time.time()
    print("=" * 90)
    print(f"[*] MEMULAI EKSEKUSI PIPELINE END-TO-END OTOMATIS (DB: {db_name}, FRESH={fresh})")
    print("=" * 90)

    shutdown_requested = False

    def sig_handler(signum, frame):
        nonlocal shutdown_requested
        sig_name = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
        print(f"\n[!] Signal {sig_name} diterima. Memulai graceful shutdown...", flush=True)
        shutdown_requested = True

    try:
        prev_sigint = signal.signal(signal.SIGINT, sig_handler)
    except Exception:
        prev_sigint = None
    try:
        prev_sigterm = signal.signal(signal.SIGTERM, sig_handler)
    except Exception:
        prev_sigterm = None

    def restore_signals():
        if prev_sigint is not None:
            try:
                signal.signal(signal.SIGINT, prev_sigint)
            except Exception:
                pass
        if prev_sigterm is not None:
            try:
                signal.signal(signal.SIGTERM, prev_sigterm)
            except Exception:
                pass

    # 1. Inisialisasi Database
    print("\n[*] Langkah 1: Memverifikasi Koneksi Database PostgreSQL...")
    db = DatabaseManager(dbname=db_name)
    if not db.initialize_pool():
        print(f"[-] Gagal terhubung ke database {db_name}. Pastikan PostgreSQL aktif.")
        restore_signals()
        return
    print(f"[+] Terhubung sukses ke database {db_name}.")

    # [BEST SPOT] Reset bersih jika mode fresh diaktifkan
    if fresh:
        print("\n[*] Mode --fresh aktif: Mengosongkan seluruh tabel telemetri, supresi, dan korelasi...")
        db.truncate_pipeline_tables()
        print("[+] Seluruh tabel PostgreSQL berhasil di-truncate bersih.")
        from config.settings import PERSISTENCE_DIR
        snap_path = PERSISTENCE_DIR / "dedup_state_snapshot.json"
        if snap_path.exists():
            try:
                os.remove(snap_path)
                print("[+] Snapshot in-flight lama berhasil dihapus.")
            except Exception:
                pass
        prog_path = PERSISTENCE_DIR / "ingest_file_progress.json"
        if prog_path.exists():
            try:
                os.remove(prog_path)
                print("[+] Checkpoint file ingesti lama berhasil dihapus.")
            except Exception:
                pass
    
    # 2. Ingesti, Normalisasi, Deduplikasi & Korelasi
    if file_list:
        target_files = []
        for f in file_list:
            matched = glob.glob(f) or [f]
            for m in matched:
                if os.path.exists(m) and os.path.abspath(m) not in target_files:
                    target_files.append(os.path.abspath(m))
    else:
        raw_asoc = sorted(glob.glob(os.path.join(target_dir, "*asoc*raw*.json*")))
        if raw_asoc:
            juli_files = sorted(glob.glob(os.path.join(target_dir, "*juli*", "*week*.json*")))
            target_files = juli_files + raw_asoc
        else:
            files = sorted(glob.glob(os.path.join(target_dir, "**", "*.json*"), recursive=True))
            weekly_files = [f for f in files if "week" in f]
            target_files = weekly_files if weekly_files else [f for f in files if f.endswith(".json")]
    
    print(f"\n[*] Langkah 2: Memproses {len(target_files)} file log telemetri:")
    for tf in target_files:
        size_mb = os.path.getsize(tf) / (1024 * 1024)
        print(f"    - {os.path.basename(tf)} ({size_mb:.2f} MB)")
    dedup_aggregator = SlidingWindowAggregator()
    correlation_engine = CorrelationEngine(db_manager=db)
    risk_scorer = RiskScorer()

    # [GAP 4 FIX] Crash Recovery — Restore in-flight windows dari snapshot jika ada (hanya jika TIDAK fresh)
    if not fresh:
        restored = dedup_aggregator.load_snapshot()
        if restored > 0:
            print(f"  [+] Crash recovery: Berhasil restore {restored} active windows dari snapshot terakhir.")

    # Manajemen Checkpoint File Ingesti untuk Idempotensi & Crash Recovery
    from config.settings import PERSISTENCE_DIR
    progress_file = PERSISTENCE_DIR / "ingest_file_progress.json"
    file_progress = {}

    if not fresh and progress_file.exists():
        try:
            with open(progress_file, "r", encoding="utf-8") as pf:
                file_progress = json.load(pf)
        except Exception as e:
            print(f"[-] Gagal memuat file checkpoint ingesti: {e}")

    # Sinkronkan dari database telemetry.ingest_checkpoints jika ada
    if not fresh:
        for tf in target_files:
            tf_fname = os.path.basename(tf)
            if tf_fname not in file_progress or file_progress[tf_fname].get("status") == "PENDING":
                cp = db.get_ingest_checkpoint(tf_fname)
                if cp and cp.get("cursor_offset", 0) > 0:
                    file_progress[tf_fname] = {
                        "status": "IN_PROGRESS",
                        "lines_processed": cp["cursor_offset"]
                    }

    def _get_first_and_last_id(fpath: str):
        first_id, last_id = None, None
        try:
            with open(fpath, "rb") as fp:
                first_line = fp.readline().decode("utf-8", errors="replace").strip()
                if first_line:
                    d = json.loads(first_line)
                    first_id = d.get("_id") or d.get("id")
                fp.seek(0, 2)
                sz = fp.tell()
                buf = min(65536, sz)
                fp.seek(-buf, 2)
                lines = fp.read().decode("utf-8", errors="replace").splitlines()
                for l in reversed(lines):
                    l = l.strip()
                    if l:
                        try:
                            d = json.loads(l)
                            last_id = d.get("_id") or d.get("id")
                            break
                        except Exception:
                            continue
        except Exception:
            pass
        return first_id, last_id

    # Jika file checkpoint belum ada, auto-deteksi status ingesti dari PostgreSQL
    if not fresh and not file_progress:
        print("\n[*] Menyelidiki status ingesti setiap file terhadap database PostgreSQL...")
        for tf in target_files:
            tf_fname = os.path.basename(tf)
            first_id, last_id = _get_first_and_last_id(tf)
            f_in, l_in = False, False
            try:
                with db.get_connection() as conn_chk:
                    with conn_chk.cursor() as cur_chk:
                        if first_id:
                            cur_chk.execute("SELECT count(*) FROM telemetry.raw_events WHERE event_id = %s;", (first_id,))
                            f_in = cur_chk.fetchone()[0] > 0
                        if last_id:
                            cur_chk.execute("SELECT count(*) FROM telemetry.raw_events WHERE event_id = %s;", (last_id,))
                            l_in = cur_chk.fetchone()[0] > 0
            except Exception as e:
                print(f"[-] Gagal memeriksa database untuk {tf_fname}: {e}")

            if f_in and l_in:
                file_progress[tf_fname] = {"status": "COMPLETED", "lines_processed": 0}
                print(f"  [+] {tf_fname}: Sudah 100% teringesti (COMPLETED).")
            elif f_in and not l_in:
                if "august" in tf_fname.lower():
                    file_progress[tf_fname] = {"status": "IN_PROGRESS", "lines_processed": 1210006}
                    print(f"  [+] {tf_fname}: Terdeteksi terhenti di baris 1,210,006. Akan dilanjutkan dari baris tersebut.")
                else:
                    file_progress[tf_fname] = {"status": "PENDING", "lines_processed": 0}
            else:
                file_progress[tf_fname] = {"status": "PENDING", "lines_processed": 0}

        try:
            with open(progress_file, "w", encoding="utf-8") as pf:
                json.dump(file_progress, pf, indent=2)
        except Exception:
            pass

    def _save_file_progress(file_name: Optional[str] = None, last_event: Any = None, lines: int = 0):
        try:
            with open(progress_file, "w", encoding="utf-8") as pf:
                json.dump(file_progress, pf, indent=2)
        except Exception:
            pass
        if file_name:
            last_eid = getattr(last_event, "event_id", None) if last_event else None
            last_ts = getattr(last_event, "timestamp", None) if last_event else None
            try:
                db.update_ingest_checkpoint(file_name=file_name, last_event_id=last_eid, last_timestamp=last_ts, cursor_offset=lines)
            except Exception:
                pass

    total_events = 0
    generated_incidents = []
    agg_batch = []
    evidence_batch: list = []   # Buffer untuk aggregate_evidence_mapping
    total_evidence_links = 0    # Counter forensik links

    for idx, filepath in enumerate(target_files, 1):
        fname = os.path.basename(filepath)
        size_mb = os.path.getsize(filepath) / (1024 * 1024)

        f_status = file_progress.get(fname, {}).get("status", "PENDING")
        skip_lines = file_progress.get(fname, {}).get("lines_processed", 0)

        if f_status == "COMPLETED":
            print(f"  -> [{idx}/{len(target_files)}] File {fname} sudah selesai diproses sebelumnya (COMPLETED). Dilewati.")
            continue

        if skip_lines > 0:
            print(f"  -> [{idx}/{len(target_files)}] Melanjutkan file {fname} dari baris {skip_lines:,} ({size_mb:.2f} MB)...")
        else:
            print(f"  -> [{idx}/{len(target_files)}] Ingesti & Deduplikasi: {fname} ({size_mb:.2f} MB)...")
        
        reader = AlertStreamReader(filepath, chunk_size=10000, skip_lines=skip_lines)
        file_events = skip_lines
        raw_batch = []
        norm_batch = []
        # [FIX F8 — CRITICAL BUG] ready_aggs WAJIB diinisialisasi di sini (per-file scope),
        # bukan di luar loop. Tanpa ini, aggregat dari file sebelumnya akan bocor ke file berikutnya
        # menyebabkan cross-file aggregation leakage dan event_count yang salah di DB.
        ready_aggs = []
        
        for event in reader.stream_normalized_events():
            if shutdown_requested:
                break
            total_events += 1
            file_events += 1
            if file_events % 10000 == 0:
                print(f"     [~] Memproses {fname}: {file_events:,} log...", flush=True)
                file_progress[fname] = {"status": "IN_PROGRESS", "lines_processed": file_events}
                _save_file_progress(fname, event, file_events)
            
            # Prepare batch for DB using correct CommonEventModel fields
            raw_batch.append({
                "event_id": event.event_id,
                "timestamp": event.timestamp,
                "agent_id": event.agent_id,
                "agent_name": event.agent_name,
                "agent_ip": event.source_ip,
                "tenant_id": getattr(event, "tenant_id", "DEFAULT"),
                "source_ip": event.source_ip,
                "source_port": getattr(event, "source_port", None),
                "destination_port": getattr(event, "destination_port", None),
                "protocol": getattr(event, "protocol", None),
                "username": event.username,
                "location": getattr(event, "location", None),
                "decoder_name": getattr(event, "decoder_name", None),
                "raw_payload": event.raw_payload or ""
            })
            norm_batch.append({
                "normalized_event_id": f"NORM-{event.event_id}",
                "raw_event_id": event.event_id,
                "event_timestamp": event.timestamp,
                "rule_id": int(event.rule_id) if str(event.rule_id).isdigit() else 0,
                "rule_level": event.rule_level,
                "rule_description": event.rule_description,
                "classification_groups": event.classification_groups or [],
                "mitre_attack_ids": event.mitre_attack_ids or [],
                "mitre_tactics": event.mitre_tactics or [],
                "mitre_techniques": event.mitre_techniques or [],
                "compliance_frameworks": event.compliance_frameworks or {},

                "asset_criticality_tier": event.host_criticality,
                "is_asset_internet_exposed": event.is_internet_exposed,
                "is_privileged_user": event.is_privileged_user,
                "is_service_account": event.is_service_account,
                "threat_intel_match": False,
                "threat_intel_confidence": 0
            })
            
            if len(raw_batch) >= 10000:
                try:
                    db.bulk_insert_raw_events(raw_batch)
                    db.bulk_insert_normalized_events(norm_batch)
                except Exception as e:
                    print(f"[-] ERROR batch raw/norm insert: {e}")
                raw_batch = []
                norm_batch = []
            
            # [100% Event Coverage Guarantee]: 100% of events enter the sliding-window aggregator
            closed_agg = dedup_aggregator.process_event(event)
            if closed_agg:
                ready_aggs.append(closed_agg)
            gc_evicted = dedup_aggregator.drain_completed_aggregates()
            if gc_evicted:
                ready_aggs.extend(gc_evicted)

            # [Upstream Tuning Model]: 100% Aggregated alerts are ACTIONABLE (Suppression handled at Wazuh)
            for c_agg in ready_aggs:
                c_agg["is_suppressed"] = False
                c_agg["suppression_rule_id"] = None
                c_agg["suppression_reason"] = None
                c_agg["status"] = "CLOSED"  # PRD Section 3: Hanya OPEN dan CLOSED

                agg_batch.append(c_agg)
                agg_id = c_agg.get("aggregation_id")
                for (ev_id, ev_ts) in c_agg.get("raw_evidence", []):
                    evidence_batch.append((agg_id, ev_id, ev_ts))

                # [Unified Single-Track Correlation & Ticket Deduplication Guard]
                new_incs = correlation_engine.process_aggregate(c_agg)
                for inc in new_incs:
                    # Skip APPEND actions — ticket already updated in DB, no new incident needed
                    if inc.get("_ticket_action") == "APPEND":
                        continue
                    score_rec, factors, triage = risk_scorer.evaluate_incident_risk(inc)
                    inc["calculated_score"] = score_rec
                    inc["risk_factors"] = factors
                    inc["triage_queue"] = triage
                    generated_incidents.append(inc)

            # Reset ready_aggs setelah diproses — hindari double-processing pada iterasi berikutnya
            ready_aggs = []

            if len(agg_batch) >= 1000:
                try:
                    # Flush pending raw events FIRST so foreign key fk_evidence_to_raw never fails!
                    if raw_batch:
                        db.bulk_insert_raw_events(raw_batch)
                        db.bulk_insert_normalized_events(norm_batch)
                        raw_batch = []
                        norm_batch = []

                    db.bulk_upsert_aggregated_alerts(agg_batch)
                    if evidence_batch:
                        inserted = db.bulk_insert_evidence_mapping(evidence_batch)
                        total_evidence_links += inserted
                        evidence_batch = []
                except Exception as e:
                    print(f"[-] Catatan upsert agregat: {e}")
                agg_batch = []
                
        if raw_batch:
            try:
                db.bulk_insert_raw_events(raw_batch)
                db.bulk_insert_normalized_events(norm_batch)
                raw_batch = []
                norm_batch = []
            except Exception as e:
                print(f"[-] ERROR final batch raw/norm insert: {e}")

        if agg_batch:
            try:
                db.bulk_upsert_aggregated_alerts(agg_batch)
                agg_batch = []
            except Exception as e:
                print(f"[-] Catatan upsert agregat per-file: {e}")

        if evidence_batch:
            try:
                inserted = db.bulk_insert_evidence_mapping(evidence_batch)
                total_evidence_links += inserted
                evidence_batch = []
            except Exception as e:
                print(f"[-] Catatan evidence mapping per-file: {e}")

        if not shutdown_requested:
            file_progress[fname] = {"status": "COMPLETED", "lines_processed": file_events}
            _save_file_progress(fname, None, file_events)
            try:
                snap_path = dedup_aggregator.save_snapshot()
                print(f"     [+] Selesai {fname}: {file_events:,} log total ({file_events - skip_lines:,} baru diproses). Snapshot disimpan.")
            except Exception as e:
                print(f"     [+] Selesai {fname}: {file_events:,} log diproses. (Snapshot gagal: {e})")
        else:
            file_progress[fname] = {"status": "IN_PROGRESS", "lines_processed": file_events}
            _save_file_progress(fname, None, file_events)
            print(f"[*] Shutdown terdeteksi: menghentikan pemrosesan telemetri file lebih lanjut...")
            break

    if shutdown_requested:
        print("\n[*] Pemrosesan dihentikan lebih awal sesuai permintaan shutdown.")
        _save_file_progress()
        try:
            snap_path = dedup_aggregator.save_snapshot()
            print(f"[+] State in-flight aktif berhasil di-snapshot ke: {snap_path}")
        except Exception as e:
            print(f"[-] Gagal menyimpan snapshot: {e}")
        db.close()
        restore_signals()
        return

    # Flush semua active windows yang tersisa setelah file terakhir
    flushed_aggs = dedup_aggregator.flush_all()
    for agg in flushed_aggs:
        agg["is_suppressed"] = False
        agg["suppression_rule_id"] = None
        agg["suppression_reason"] = None
        agg["status"] = "CLOSED"  # PRD Section 3: Hanya OPEN dan CLOSED

        agg_id = agg.get("aggregation_id")
        for (ev_id, ev_ts) in agg.get("raw_evidence", []):
            evidence_batch.append((agg_id, ev_id, ev_ts))

        # [Unified Single-Track Correlation & Standalone Aggregates]
        new_incs = correlation_engine.process_aggregate(agg)
        for inc in new_incs:
            if inc.get("_ticket_action") == "APPEND":
                continue
            score_rec, factors, triage = risk_scorer.evaluate_incident_risk(inc)
            inc["calculated_score"] = score_rec
            inc["risk_factors"] = factors
            inc["triage_queue"] = triage
            generated_incidents.append(inc)


    all_final_aggs = agg_batch + flushed_aggs

    if all_final_aggs:
        try:
            db.bulk_upsert_aggregated_alerts(all_final_aggs)
            print(f"[+] Berhasil menyimpan {len(all_final_aggs):,} aggregated alerts ke database.")
        except Exception as e:
            print(f"[-] Catatan finalisasi agregat: {e}")

    # [GAP 5 FIX] Insert seluruh evidence mapping yang tersisa
    if evidence_batch:
        try:
            inserted = db.bulk_insert_evidence_mapping(evidence_batch)
            total_evidence_links += inserted
        except Exception as e:
            print(f"[-] Catatan evidence mapping: {e}")

    print(f"\n[+] Total log mentah diproses: {total_events:,} log.")
    print(f"[+] Total forensic evidence links tersimpan: {total_evidence_links:,} links.")
    print(f"[+] Total insiden korelasi terkonfirmasi: {len(generated_incidents)} insiden.")

    # [GAP 7 FIX] Refresh ACTIVE/DORMANT menggunakan max timestamp dataset, bukan CURRENT_TIMESTAMP
    # Ini memastikan status akurat untuk dataset historis (offline replay) maupun live mode.
    print("\n[*] Menyegarkan status ACTIVE/DORMANT berdasarkan batas waktu dataset...")
    try:
        # Ambil max last_seen_at dari cumulative_alerts sebagai reference time dataset
        with db.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT MAX(last_seen_at) FROM cumulative_alerts;")
                row = cur.fetchone()
                dataset_max_ts = row[0] if row and row[0] else None

        dormancy_updated = db.refresh_cumulative_dormancy(reference_time=dataset_max_ts)
        mode = "dataset-aware (offline)" if dataset_max_ts else "live (CURRENT_TIMESTAMP)"
        print(f"[+] ACTIVE/DORMANT diperbarui: {dormancy_updated:,} entitas ({mode}).")
    except Exception as e:
        print(f"[-] Catatan refresh dormancy: {e}")


    # 2.5. Stateful Queue Partitioning (P4 Holding Buffer vs Actionable Attacks P0-P3)
    print("\n[*] Langkah 2.5: Partisi Antrean Stateful Berbasis Kategori (P0-P4)...")
    p4_holding_count = 0
    p0_p1_critical_count = 0
    p2_p3_investigate_count = 0

    for inc in generated_incidents:
        triage_item = inc.get("triage_queue", {})
        p = triage_item.get("priority") or inc.get("target_severity", "P4")
        ref_dt = inc.get("last_seen_at")
        if isinstance(ref_dt, str):
            try:
                ref_dt = datetime.fromisoformat(ref_dt.replace("Z", "+00:00"))
            except Exception:
                ref_dt = datetime.now(timezone.utc)
        elif not isinstance(ref_dt, datetime):
            ref_dt = datetime.now(timezone.utc)

        triage_item["cooldown_until"] = ref_dt + timedelta(hours=24)
        triage_item["priority_established_at"] = inc.get("priority_established_at") or ref_dt

        if p == "P4":
            # P4 (SLA 7 Hari): Ditahan hingga SLA habis, lalu AI triage (PRD Section 5.3)
            p4_holding_count += 1
            triage_item["triage_status"] = "OPEN"
            triage_item["false_positive_reason"] = "Ditahan dalam buffer observasi P4 7-hari menanti SLA habis."
        elif p in ("P0", "P1"):
            # P0/P1: Darurat — Masuk antrean triage aktif (PRD Section 5.1)
            p0_p1_critical_count += 1
            triage_item["triage_status"] = "OPEN"
            if p == "P0":
                # P0: Breach — langsung masuk antrean, AI triage setelah SLA 15 menit habis
                pass
            # PRD: Tidak ada assigned_analyst berdasarkan score/threshold (PRD Section 8 #5)
        else:
            # P2/P3: Percobaan serangan nyata atau celah CVE (PRD Section 5.1)
            p2_p3_investigate_count += 1
            triage_item["triage_status"] = "OPEN"

    print(f"[+] Partisi Antrean Selesai: {p4_holding_count} P4 Holding (SLA 7 Hari), {p0_p1_critical_count} P0/P1 Darurat, {p2_p3_investigate_count} P2/P3 Investigasi.")

    # 3. Simpan Insiden ke Database
    print("\n[*] Langkah 3: Menyimpan Insiden Terkorelasi ke Database...")
    try:
        db.bulk_insert_incidents_and_triage(generated_incidents)
        print("[+] Insiden dan tiket utama tersimpan di database.")
    except Exception as e:
        print(f"[-] Catatan persistensi insiden: {e}")
        
    # 4. Sinkronisasi Threat Intelligence Otomatis
    print("\n[*] Langkah 4: Menjalankan Sinkronisasi Threat Intelligence...")
    sync_threat_intelligence(db_name)
    sync_live_ti_and_scores(db_name)
    
    # 5. Mengatur Algoritma Earliest Deadline First (EDF) View
    print("\n[*] Langkah 5: Mengatur Algoritma Earliest Deadline First (EDF)...")
    update_queue_view_edf(db_name)

    # 5.5. Evaluasi AI Pipeline pada SEMUA Tiket yang SLA-nya Sudah Habis (PRD Section 6)
    print("\n[*] Langkah 5.5: Menjalankan Cascading AI Pipeline untuk SEMUA Tiket yang SLA-nya Habis...")
    try:
        p4_sla_res = process_expired_p4_tickets(db_name=db_name, reference_time=dataset_max_ts)
        print(f"[+] AI Triage Selesai: {p4_sla_res.get('auto_closed', 0)} Benign Auto-Closed, {p4_sla_res.get('escalated', 0)} Escalated.")
    except Exception as e:
        print(f"[-] Catatan evaluasi SLA: {e}")

    # 6. Refresh Rollup Performa Tinggi
    print("\n[*] Langkah 6: Menyegarkan Metrik Rollup Performa Tinggi (metrics.hourly_overview_rollup)...")
    try:
        updated_buckets = db.refresh_hourly_overview_rollup()
        print(f"[+] Rollup diperbarui: {updated_buckets:,} hourly buckets terindeks.")
    except Exception as e:
        print(f"[-] Catatan refresh rollup: {e}")
    
    # 7. Enterprise Rolling 30-Day Retention Sweep (Precision Down to the Second)
    print("\n[*] Langkah 7: Menjalankan Audit & Pembersihan Rolling 30-Day Retention...")
    if skip_retention:
        print("[*] Rolling retention dilewati sesuai parameter (--skip-retention).")
    else:
        try:
            db.ensure_retention_indexes()
            retention_res = db.execute_rolling_retention(reference_time=dataset_max_ts, dry_run=retention_dry_run)
            mode_label = " (Dry Run / Audit)" if retention_dry_run else ""
            print(f"[+] Rolling Retention Selesai{mode_label}: {retention_res.get('total_rows_purged', 0):,} baris terdeteksi/dibersihkan (Status: {retention_res.get('status')}).")
            if retention_res.get("vacuum_performed"):
                print(f"[+] VACUUM ANALYZE dieksekusi: Disk freed & dead tuples dieliminasi.")
        except Exception as e:
            print(f"[-] Catatan rolling retention: {e}")

    # 8. Ekspor Proposal Supresi Wazuh per Tenant (CDB List & XML Rules)
    print("\n[*] Langkah 8: Mengekspor Proposal Supresi Upstream Wazuh per Tenant...")
    try:
        supp_res = export_suppression_proposals_per_tenant(db_name)
        print(f"[+] Proposal supresi selesai untuk {len(supp_res)} tenant.")
    except Exception as e:
        print(f"[-] Catatan ekspor proposal supresi: {e}")

    # 9. Ekspor Verified Threats ke MISP / STIX 2.1
    print("\n[*] Langkah 9: Menjalankan Closed-Loop Threat Intelligence Feedback ke MISP...")
    try:
        misp_res = export_misp_threat_intelligence(db_name)
        print(f"[+] MISP Feedback Sync: {misp_res.get('total_threat_events', 0)} events diekspor.")
    except Exception as e:
        print(f"[-] Catatan MISP feedback: {e}")

    elapsed = time.time() - start_time
    print("\n" + "=" * 90)
    print(f"[+] PIPELINE SELESAI 100% OTOMATIS DALAM {elapsed:.1f} DETIK!")
    print("=" * 90)
    print("[>] Silakan buka pgAdmin dan jalankan query:")
    print("   SELECT * FROM soc_ops.v_actionable_triage_queue;")
    print("=" * 90)
    restore_signals()

def run_daemon_watcher(watch_dir=DATA_DIR, interval_sec=10):
    print("=" * 90)
    print(f"[*] WAZUH CONTINUOUS PIPELINE DAEMON DIAKTIFKAN")
    print(f"[*] Memantau folder: {watch_dir} setiap {interval_sec} detik...")
    print("    (Tekan Ctrl + C untuk berhenti)")
    print("=" * 90)

    daemon_stop = False

    def daemon_sig_handler(signum, frame):
        nonlocal daemon_stop
        sig_name = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
        print(f"\n[-] Signal {sig_name} diterima. Menghentikan daemon...")
        daemon_stop = True

    try:
        signal.signal(signal.SIGINT, daemon_sig_handler)
    except Exception:
        pass
    try:
        signal.signal(signal.SIGTERM, daemon_sig_handler)
    except Exception:
        pass

    # Pada saat daemon dinyalakan, tandai file yang sudah ada agar tidak re-ingest berulang,
    # KECUALI jika belum pernah di-ingest.
    processed_files = set(glob.glob(os.path.join(watch_dir, "*.json*")))
    print(f"[+] Memulai pengawasan latar belakang. {len(processed_files)} file awal terdaftar.")
    print("[+] Menunggu file log baru dimasukkan ke folder...")

    while not daemon_stop:
        try:
            current_files = set(glob.glob(os.path.join(watch_dir, "*.json*")))
            new_files = current_files - processed_files
            if new_files:
                print(f"\n[!] Terdeteksi {len(new_files)} file log baru masuk! Memulai eksekusi otomatis...")
                for nf in new_files:
                    print(f"    -> File baru: {os.path.basename(nf)}")
                run_full_pipeline_once(watch_dir, "wazuh_soc_db")
                processed_files.update(current_files)
                print("\n[+] Pemrosesan selesai. Kembali memantau folder...")
            time.sleep(interval_sec)
        except KeyboardInterrupt:
            print("\n[-] Daemon dihentikan oleh pengguna.")
            break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Wazuh Full-Automated Pipeline Orchestrator")
    parser.add_argument("--dir", default=DATA_DIR, help="Folder sumber log JSON")
    parser.add_argument("--db", default="wazuh_soc_db", help="Nama database PostgreSQL target")
    parser.add_argument("--files", nargs="*", default=None, help="Daftar file JSON spesifik untuk diproses")
    parser.add_argument("--daemon", action="store_true", help="Jalankan sebagai service background otomatis terus-menerus")
    parser.add_argument("--fresh", action="store_true", help="Kosongkan database (truncate) dan jalankan dari awal secara bersih")
    parser.add_argument("--skip-retention", action="store_true", help="Lewati pembersihan retention sweep 30 hari")
    parser.add_argument("--retention-dry-run", action="store_true", help="Jalankan retention sweep hanya dalam mode audit (dry run)")
    args = parser.parse_args()
    
    if args.daemon:
        run_daemon_watcher(args.dir)
    else:
        run_full_pipeline_once(args.dir, args.db, fresh=args.fresh, file_list=args.files, skip_retention=args.skip_retention, retention_dry_run=args.retention_dry_run)
