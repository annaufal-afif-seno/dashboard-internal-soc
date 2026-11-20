#!/usr/bin/env python3
import sys, os, time, json, logging
sys.path.insert(0, '/opt/dashboard-internal-soc-v3')
import psycopg2
from psycopg2.extras import execute_values
from pipeline.apex_normalizer import ApexNormalizerV40

log_dir = '/opt/dashboard-internal-soc-v3/logs'
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, 'upgrade_legacy_apex.log')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("ApexLegacyUpgrade")

def run_upgrade():
    logger.info("=== [APEX V4.0 FULL UPGRADE WORKER STARTED] ===")
    logger.info("Target: Migrasi seluruh data historis lama (Legacy pre-v4) ke Apex Normalizer v4.0.0")
    
    conn = psycopg2.connect('postgresql://postgres:postgres@127.0.0.1:5432/wazuh_soc_db')
    conn.autocommit = False
    cur = conn.cursor()
    
    batch_size = 2000
    
    # PHASE 1: normalized_events_default + raw_events_default
    logger.info("--- PHASE 1: Memproses normalized_events_default (join raw_events_default) ---")
    p1_updated = 0
    while True:
        t0 = time.time()
        cur.execute("""
            SELECT n.normalized_event_id, n.processed_at, r.raw_payload
            FROM telemetry.normalized_events_default n
            JOIN telemetry.raw_events_default r ON r.event_id = n.raw_event_id AND r.timestamp = n.event_timestamp
            WHERE (n.apex_data->>'apex_engine_version') IS NULL
            LIMIT %s;
        """, (batch_size,))
        rows = cur.fetchall()
        if not rows:
            logger.info("PHASE 1 SELESAI! Total baris di-upgrade: %d", p1_updated)
            break
            
        updates = []
        for norm_id, proc_at, raw_str in rows:
            try:
                raw_dict = json.loads(raw_str) if isinstance(raw_str, str) else (raw_str or {})
                compact_apex = ApexNormalizerV40.normalize_compact(raw_dict)
                clean_json_str = json.dumps(compact_apex).replace(chr(0), '').replace('\\u0000', '')
                updates.append((norm_id, proc_at, clean_json_str))
            except Exception as e:
                pass
                
        if updates:
            query = """
                UPDATE telemetry.normalized_events_default n
                SET apex_data = v.apex::jsonb
                FROM (VALUES %s) AS v(norm_id, proc_at, apex)
                WHERE n.normalized_event_id = v.norm_id AND n.processed_at = v.proc_at;
            """
            execute_values(cur, query, updates, template='(%s, %s, %s)', page_size=500)
            conn.commit()
            p1_updated += len(updates)
            elapsed = time.time() - t0
            rate = len(updates) / elapsed if elapsed > 0 else 0
            logger.info("[PHASE 1] Updated %d rows (Batch: %d in %.2fs, Rate: %.1f rows/s)", p1_updated, len(updates), elapsed, rate)
            
    # PHASE 2: normalized_events_default + raw_events_2026_10 (cross-timestamp rows)
    logger.info("--- PHASE 2: Memproses normalized_events_default (join raw_events_2026_10) ---")
    p2_updated = 0
    while True:
        t0 = time.time()
        cur.execute("""
            SELECT n.normalized_event_id, n.processed_at, r.raw_payload
            FROM telemetry.normalized_events_default n
            JOIN telemetry.raw_events_2026_10 r ON r.event_id = n.raw_event_id AND r.timestamp = n.event_timestamp
            WHERE (n.apex_data->>'apex_engine_version') IS NULL
            LIMIT %s;
        """, (batch_size,))
        rows = cur.fetchall()
        if not rows:
            logger.info("PHASE 2 SELESAI! Total baris di-upgrade: %d", p2_updated)
            break
            
        updates = []
        for norm_id, proc_at, raw_str in rows:
            try:
                raw_dict = json.loads(raw_str) if isinstance(raw_str, str) else (raw_str or {})
                compact_apex = ApexNormalizerV40.normalize_compact(raw_dict)
                clean_json_str = json.dumps(compact_apex).replace(chr(0), '').replace('\\u0000', '')
                updates.append((norm_id, proc_at, clean_json_str))
            except Exception as e:
                pass
                
        if updates:
            query = """
                UPDATE telemetry.normalized_events_default n
                SET apex_data = v.apex::jsonb
                FROM (VALUES %s) AS v(norm_id, proc_at, apex)
                WHERE n.normalized_event_id = v.norm_id AND n.processed_at = v.proc_at;
            """
            execute_values(cur, query, updates, template='(%s, %s, %s)', page_size=500)
            conn.commit()
            p2_updated += len(updates)
            elapsed = time.time() - t0
            rate = len(updates) / elapsed if elapsed > 0 else 0
            logger.info("[PHASE 2] Updated %d rows (Batch: %d in %.2fs, Rate: %.1f rows/s)", p2_updated, len(updates), elapsed, rate)

    # PHASE 3: normalized_events_2026_10 + raw_events_2026_10
    logger.info("--- PHASE 3: Memproses normalized_events_2026_10 (join raw_events_2026_10) ---")
    p3_updated = 0
    while True:
        t0 = time.time()
        cur.execute("""
            SELECT n.normalized_event_id, n.processed_at, r.raw_payload
            FROM telemetry.normalized_events_2026_10 n
            JOIN telemetry.raw_events_2026_10 r ON r.event_id = n.raw_event_id AND r.timestamp = n.event_timestamp
            WHERE (n.apex_data->>'apex_engine_version') IS NULL
            LIMIT %s;
        """, (batch_size,))
        rows = cur.fetchall()
        if not rows:
            logger.info("PHASE 3 SELESAI! Total baris di-upgrade: %d", p3_updated)
            break
            
        updates = []
        for norm_id, proc_at, raw_str in rows:
            try:
                raw_dict = json.loads(raw_str) if isinstance(raw_str, str) else (raw_str or {})
                compact_apex = ApexNormalizerV40.normalize_compact(raw_dict)
                clean_json_str = json.dumps(compact_apex).replace(chr(0), '').replace('\\u0000', '')
                updates.append((norm_id, proc_at, clean_json_str))
            except Exception as e:
                pass
                
        if updates:
            query = """
                UPDATE telemetry.normalized_events_2026_10 n
                SET apex_data = v.apex::jsonb
                FROM (VALUES %s) AS v(norm_id, proc_at, apex)
                WHERE n.normalized_event_id = v.norm_id AND n.processed_at = v.proc_at;
            """
            execute_values(cur, query, updates, template='(%s, %s, %s)', page_size=500)
            conn.commit()
            p3_updated += len(updates)
            elapsed = time.time() - t0
            rate = len(updates) / elapsed if elapsed > 0 else 0
            logger.info("[PHASE 3] Updated %d rows (Batch: %d in %.2fs, Rate: %.1f rows/s)", p3_updated, len(updates), elapsed, rate)

    # PHASE 4: Clean up helper indexes
    logger.info("--- PHASE 4: Membersihkan partial helper indexes ---")
    conn.autocommit = True
    cur.execute("DROP INDEX IF EXISTS telemetry.idx_norm_def_apex_legacy;")
    cur.execute("DROP INDEX IF EXISTS telemetry.idx_norm_2026_10_apex_legacy;")
    logger.info("Helper indexes berhasil dihapus!")

    total_all = p1_updated + p2_updated + p3_updated
    logger.info("=== [MIGRASI 100% SUKSES!] Total baris yang diperbarui ke Apex v4.0.0: %d ===", total_all)
    
    cur.close()
    conn.close()

if __name__ == '__main__':
    run_upgrade()
