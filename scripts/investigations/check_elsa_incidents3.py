import psycopg2
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

conn = psycopg2.connect(host="localhost", port=5432, dbname="wazuh_soc_db", user="postgres", password="postgres")
cur = conn.cursor()

cur.execute("""
    SELECT incident_id, title, first_seen_at, last_seen_at, attacker_source_ip, correlation_rule_id
    FROM correlation.correlated_incidents
    WHERE target_host = 'ELSA_INSTIKIBALI'
    ORDER BY first_seen_at DESC;
""")
for r in cur.fetchall():
    print(r)

conn.close()
