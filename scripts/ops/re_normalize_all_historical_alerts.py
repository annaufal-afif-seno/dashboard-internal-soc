#!/usr/bin/env python3
"""
ASOC Enterprise SecOps - Historical Alert Re-normalization Worker
Migrates all historical raw_events and normalized_events to Apex v4.0 Compact Standard.
Features:
  - 100% RFC 8259 Sparse (0% null clutter)
  - Duck-Typing Feature Introspection (HTTP, PROCESS, FIM, VULN, CLOUD, AUTH)
  - Resumable (WHERE apex_data IS NULL)
  - Temporary Table Batch Join Updates (High Performance, Zero-Downtime, Zero-Touch to Track 1)
  - Progress Tracking with ETA and throughput rate
"""

import sys
import os
import json
import time
import signal
from datetime import datetime

# Setup project root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import psycopg2
from psycopg2.extras import execute_values
from config.settings import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
from pipeline.apex_normalizer import ApexNormalizerV40

BATCH_SIZE = 2500

def run_migration():
    print("=" * 80)
    print(f"[{datetime.now().strftime('%H:%M:%S')}] ASOC HISTORICAL ALERT RE-NORMALIZATION WORKER (APEX V4.0 COMPACT)")
    print("=" * 80)
    
    stop_requested = False
    def sig_handler(signum, frame):
        nonlocal stop_requested
        print("\n[!] Signal interrupt diterima. Menyelesaikan batch saat ini sebelum berhenti...")
        stop_requested = True

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    conn = psycopg2.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD
    )
    conn.autocommit = False
    cur = conn.cursor()

    # 1. Pastikan kolom apex_data ada
    cur.execute("ALTER TABLE telemetry.raw_events ADD COLUMN IF NOT EXISTS apex_data JSONB;")
    cur.execute("ALTER TABLE telemetry.normalized_events ADD COLUMN IF NOT EXISTS apex_data JSONB;")
    conn.commit()

    # 2. Buat partial index untuk mempercepat query batch
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Mempersiapkan partial index untuk pencarian cepat data pending...")
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_raw_events_apex_null 
        ON telemetry.raw_events (timestamp ASC) 
        WHERE apex_data IS NULL;
    """)
    conn.commit()

    # 3. Hitung jumlah alert yang belum dinormalisasi
    cur.execute("SELECT count(*) FROM telemetry.raw_events WHERE apex_data IS NULL;")
    total_pending = cur.fetchone()[0]

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Total alert yang belum dinormalisasi: {total_pending:,}")

    if total_pending == 0:
        print("[+] Seluruh data alert di database sudah 100% ternormalisasi dengan Apex v4.0 Compact!")
        cur.execute("DROP INDEX IF EXISTS telemetry.idx_raw_events_apex_null;")
        conn.commit()
        conn.close()
        return

    processed = 0
    start_time = time.time()
    batch_idx = 0

    while not stop_requested:
        t_batch_start = time.time()

        # Ambil batch data yang belum dinormalisasi
        cur.execute("""
            SELECT event_id, timestamp, raw_payload
            FROM telemetry.raw_events
            WHERE apex_data IS NULL
            ORDER BY timestamp ASC
            LIMIT %s;
        """, (BATCH_SIZE,))
        rows = cur.fetchall()

        if not rows:
            print("\n[+] Semua baris data telah selesai diproses!")
            break

        batch_idx += 1
        update_data = []

        for eid, ts, raw_payload in rows:
            try:
                if isinstance(raw_payload, str):
                    raw_dict = json.loads(raw_payload)
                else:
                    raw_dict = raw_payload or {}
            except Exception:
                raw_dict = {"full_log": raw_payload} if raw_payload else {}

            if "id" not in raw_dict:
                raw_dict["id"] = eid
            if "timestamp" not in raw_dict:
                raw_dict["timestamp"] = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
            if "full_log" not in raw_dict and isinstance(raw_payload, str):
                raw_dict["full_log"] = raw_payload

            # Normalisasi ke format Apex v4.0 Compact
            apex_res = ApexNormalizerV40.normalize_compact(raw_dict)
            net = apex_res.get("network") or {}
            src_ip = net.get("src_ip")
            dst_ip = net.get("dst_ip")
            dst_port = net.get("dst_port")
            transport = net.get("transport") or "ip"

            json_str = json.dumps(apex_res).replace('\\u0000', '').replace('\x00', '')

            update_data.append((
                src_ip,
                dst_ip,
                dst_port,
                transport,
                json_str,
                eid,
                ts
            ))

        # Buat temporary table di memori transaksi untuk update massal
        cur.execute("""
            CREATE TEMP TABLE tmp_apex_batch (
                src_ip varchar,
                dst_ip varchar,
                dst_port int,
                protocol varchar,
                apex_data jsonb,
                event_id varchar,
                timestamp timestamptz
            ) ON COMMIT DROP;
        """)

        execute_values(
            cur,
            """
            INSERT INTO tmp_apex_batch (src_ip, dst_ip, dst_port, protocol, apex_data, event_id, timestamp)
            VALUES %s;
            """,
            update_data
        )

        # Update telemetry.raw_events
        cur.execute("""
            UPDATE telemetry.raw_events r
            SET 
                source_ip = COALESCE(t.src_ip, r.source_ip),
                destination_ip = COALESCE(t.dst_ip, r.destination_ip),
                destination_port = COALESCE(t.dst_port, r.destination_port),
                protocol = t.protocol,
                apex_data = t.apex_data
            FROM tmp_apex_batch t
            WHERE r.event_id = t.event_id AND r.timestamp = t.timestamp;
        """)

        # Update telemetry.normalized_events
        cur.execute("""
            UPDATE telemetry.normalized_events n
            SET apex_data = t.apex_data
            FROM tmp_apex_batch t
            WHERE n.raw_event_id = t.event_id AND n.event_timestamp = t.timestamp;
        """)

        conn.commit()

        processed += len(rows)
        elapsed = time.time() - start_time
        batch_dur = time.time() - t_batch_start
        rate = processed / max(elapsed, 0.001)
        remaining = max(0, total_pending - processed)
        eta_sec = remaining / max(rate, 1)

        pct = (processed / total_pending) * 100
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Batch {batch_idx:03d}: {processed:,}/{total_pending:,} ({pct:.1f}%) | Speed: {rate:,.0f} alerts/s | Batch: {batch_dur:.2f}s | ETA: {eta_sec:.0f}s", flush=True)

    # Bersihkan partial index setelah selesai
    try:
        cur.execute("DROP INDEX IF EXISTS telemetry.idx_raw_events_apex_null;")
        conn.commit()
    except Exception:
        pass

    total_time = time.time() - start_time
    print("=" * 80)
    print(f"[+] SELESAI: Berhasil menormalisasi {processed:,} alert ke Apex v4.0 Compact dalam {total_time:.2f} detik ({processed/max(total_time, 0.001):,.0f} alerts/detik)!")
    print("=" * 80)
    conn.close()

if __name__ == "__main__":
    run_migration()
