import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import psycopg2
import config.settings as s

conn = psycopg2.connect(host=s.DB_HOST, port=s.DB_PORT, dbname=s.DB_NAME, user=s.DB_USER, password=s.DB_PASSWORD)
cur = conn.cursor()

print("=== 1. OVERALL RESOLUTION OUTCOME ===")
cur.execute("SELECT triage_status, resolution_outcome, COUNT(*) FROM soc_ops.soc_triage_queue GROUP BY triage_status, resolution_outcome ORDER BY COUNT(*) DESC;")
for r in cur.fetchall():
    print(f"  {r[0]:<12} | {str(r[1]):<25} | {r[2]:,}")

print("\n=== 2. BREAKDOWN BY PRIORITY ===")
cur.execute("""
    SELECT priority, 
           COUNT(*) FILTER (WHERE resolution_outcome = 'TRUE_POSITIVE_ACTIONABLE') as threat,
           COUNT(*) FILTER (WHERE resolution_outcome = 'BENIGN') as benign,
           COUNT(*) as total
    FROM soc_ops.soc_triage_queue 
    GROUP BY priority 
    ORDER BY priority;
""")
for r in cur.fetchall():
    print(f"  {r[0]}: Total {r[3]:7,d} | THREAT: {r[1]:7,d} ({r[1]/r[3]*100:5.1f}%) | BENIGN: {r[2]:7,d} ({r[2]/r[3]*100:5.1f}%)")

print("\n=== 3. FORENSIC VERIFICATION ON CRITICAL ALERT TYPES ===")
test_queries = [
    ("SQL Injection", "i.title ILIKE '%sql injection%'"),
    ("Brute Force", "i.title ILIKE '%brute force%'"),
    ("Sudo to ROOT", "i.title ILIKE '%sudo to root%'"),
    ("Cloudflare HTTP 400", "i.title ILIKE '%400 error%' AND (i.attacker_source_ip LIKE '172.69.%' OR i.attacker_source_ip LIKE '162.158.%')"),
    ("P4 HTTP 400 Errors", "q.priority = 'P4' AND i.title ILIKE '%400 error%'"),
]

for name, cond in test_queries:
    cur.execute(f"""
        SELECT 
            COUNT(*) FILTER (WHERE q.resolution_outcome = 'TRUE_POSITIVE_ACTIONABLE') as threat,
            COUNT(*) FILTER (WHERE q.resolution_outcome = 'BENIGN') as benign,
            COUNT(*) as total
        FROM soc_ops.soc_triage_queue q
        JOIN correlation.correlated_incidents i ON q.incident_id = i.incident_id
        WHERE {cond};
    """)
    res = cur.fetchone()
    print(f"  {name:<22}: Total {res[2]:7,d} | Threat: {res[0]:7,d} ({res[0]/res[2]*100:5.1f}%) | Benign: {res[1]:7,d} ({res[1]/res[2]*100:5.1f}%)")

cur.close()
conn.close()
