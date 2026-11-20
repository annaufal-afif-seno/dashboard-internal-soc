#!/usr/bin/env python3
import sys, os, time, datetime, logging
sys.path.insert(0, '/opt/dashboard-internal-soc-v3')
import psycopg2

log_dir = '/opt/dashboard-internal-soc-v3/logs'
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, 'strip_timestamps.log')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("StripTimestamps")

def run():
    conn = psycopg2.connect('postgresql://postgres:postgres@127.0.0.1:5432/wazuh_soc_db')
    cur = conn.cursor()
    
    logger.info("=== [STRIP TIMESTAMPS WORKER STARTED] ===")
    
    # Pastikan 2026_10 bersih
    cur.execute("""
        UPDATE telemetry.normalized_events_2026_10 
        SET apex_data = apex_data - 'timestamps'
        WHERE apex_data ? 'timestamps';
    """)
    conn.commit()
    logger.info("Partisi 2026_10 dipastikan 100% bersih.")
    
    # Day by day chunk update for normalized_events_default
    start_dt = datetime.date(2026, 11, 1)
    end_dt = datetime.date(2026, 11, 17)
    current = start_dt
    
    total_cleaned = 0
    while current <= end_dt:
        day_str = current.strftime("%Y-%m-%d")
        next_day_str = (current + datetime.timedelta(days=1)).strftime("%Y-%m-%d")
        t0 = time.time()
        cur.execute("""
            UPDATE telemetry.normalized_events_default
            SET apex_data = apex_data - 'timestamps'
            WHERE processed_at >= %s AND processed_at < %s
              AND apex_data ? 'timestamps';
        """, (day_str, next_day_str))
        cnt = cur.rowcount
        conn.commit()
        dur = time.time() - t0
        total_cleaned += cnt
        logger.info("Day %s: Cleaned %d rows in %.2fs (Total cleaned: %d)", day_str, cnt, dur, total_cleaned)
        current += datetime.timedelta(days=1)
        
    cur.execute("""
        SELECT COUNT(*) 
        FROM telemetry.normalized_events 
        WHERE apex_data ? 'timestamps';
    """)
    rem = cur.fetchone()[0]
    logger.info("=== [SELESAI!] Total baris dibersihkan: %d. Sisa dengan timestamps: %d ===", total_cleaned, rem)
    
    cur.close()
    conn.close()

if __name__ == '__main__':
    run()
