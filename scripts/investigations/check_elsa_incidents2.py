import psycopg2
from psycopg2 import extras
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

conn = psycopg2.connect(host="localhost", port=5432, dbname="wazuh_soc_db", user="postgres", password="postgres")
cur = conn.cursor()
cur.execute("""
    SELECT column_name FROM information_schema.columns 
    WHERE table_schema = 'correlation' AND table_name = 'correlated_incidents';
""")
print([r[0] for r in cur.fetchall()])

cur.execute("""
    SELECT incident_id, title, first_seen_at, last_seen_at, total_events, correlation_rule_id
    FROM correlation.correlated_incidents
    WHERE target_host = 'ELSA_INSTIKIBALI'
    ORDER BY first_seen_at DESC;
""")
for r in cur.fetchall():
    print(r)

conn.close()
