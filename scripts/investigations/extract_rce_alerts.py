import psycopg2
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

conn = psycopg2.connect(host="localhost", port=5432, dbname="wazuh_soc_db", user="postgres", password="postgres")
cur = conn.cursor()

cur.execute("""
    SELECT r.timestamp, n.rule_id, n.rule_description, n.rule_level, r.source_ip, r.raw_payload
    FROM telemetry.raw_events r
    JOIN telemetry.normalized_events n ON r.event_id = n.raw_event_id
    WHERE r.agent_name = 'ELSA_INSTIKIBALI'
      AND r.raw_payload::text ILIKE '%2629721%'
    ORDER BY r.timestamp ASC;
""")
rows = cur.fetchall()
print(f"Events for 2629721: {len(rows)}")
for r in rows:
    ts, rid, desc, lvl, sip, payload = r
    print(f"[{ts}] Rule {rid} (Lvl {lvl}) | IP: {sip} | {desc} | {str(payload)[:160]}")

conn.close()
