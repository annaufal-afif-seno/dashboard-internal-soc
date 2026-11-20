#!/usr/bin/env python3
import sys, os, time, json, logging
sys.path.insert(0, '/opt/dashboard-internal-soc-v3')
import psycopg2
from psycopg2.extras import execute_values
from pipeline.apex_normalizer import ApexNormalizerV40

log_dir = '/opt/dashboard-internal-soc-v3/logs'
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, 'backfill_apex.log')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("ApexBackfill")

def run_backfill():
    logger.info("=== [APEX V4.0 BACKFILL WORKER] Memulai proses pengisian apex_data pada baris null (Immune to Null-Byte) ===")
    conn = psycopg2.connect('postgresql://postgres:postgres@127.0.0.1:5432/wazuh_soc_db')
    cur = conn.cursor()
    
    total_updated = 0
    batch_size = 2000
    
    while True:
        t0 = time.time()
        cur.execute('''
            SELECT n.normalized_event_id, n.processed_at, r.raw_payload
            FROM telemetry.normalized_events_default n
            JOIN telemetry.raw_events_default r ON r.event_id = n.raw_event_id AND r.timestamp = n.event_timestamp
            WHERE n.apex_data IS NULL
            LIMIT %s;
        ''', (batch_size,))
        rows = cur.fetchall()
        
        if not rows:
            logger.info("=== [SELESAI] 100% baris di database telah memiliki apex_data Apex v4.0 Kanonikal! ===")
            break
            
        updates = []
        for norm_id, proc_at, raw_str in rows:
            try:
                raw_dict = json.loads(raw_str) if isinstance(raw_str, str) else (raw_str or {})
                compact_apex = ApexNormalizerV40.normalize_compact(raw_dict)
                # Extra guard against null bytes in json string
                clean_json_str = json.dumps(compact_apex).replace('\\u0000', '').replace('\x00', '')
                updates.append((norm_id, proc_at, clean_json_str))
            except Exception as e:
                pass
                
        if updates:
            try:
                query = '''
                    UPDATE telemetry.normalized_events_default n
                    SET apex_data = v.apex::jsonb
                    FROM (VALUES %s) AS v(norm_id, proc_at, apex)
                    WHERE n.normalized_event_id = v.norm_id AND n.processed_at = v.proc_at;
                '''
                execute_values(cur, query, updates, template='(%s, %s, %s)')
                conn.commit()
                total_updated += len(updates)
                elapsed = time.time() - t0
                rate = len(updates) / elapsed if elapsed > 0 else 0
                logger.info(f"[PROGRESS] Berhasil memperbarui {len(updates):,} baris ({total_updated:,} total) dalam {elapsed:.2f}s ({rate:.0f} rows/s)")
            except Exception as ex:
                logger.error(f"[ERROR BATCH] Exception: {ex}, skipping bad items...")
                conn.rollback()
                # Process row by row for this small batch to isolate any malformed row
                for norm_id, proc_at, clean_json_str in updates:
                    try:
                        cur.execute('''
                            UPDATE telemetry.normalized_events_default
                            SET apex_data = %s::jsonb
                            WHERE normalized_event_id = %s AND processed_at = %s;
                        ''', (clean_json_str, norm_id, proc_at))
                        conn.commit()
                        total_updated += 1
                    except Exception as row_ex:
                        conn.rollback()
                        logger.warning(f"[ROW SKIPPED] {norm_id}: {row_ex}")
            
        time.sleep(0.05)
        
    cur.close()
    conn.close()

if __name__ == '__main__':
    run_backfill()
