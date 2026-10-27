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
      AND r.source_ip IN ('114.10.12.151', '114.5.208.145', '103.171.183.71')
    ORDER BY r.timestamp ASC;
""")
rows = cur.fetchall()
print(f"Events from attacker IPs: {len(rows)}")
for r in rows[:15]:
    ts, rid, desc, lvl, sip, payload = r
    print(f"[{ts}] Rule {rid} (Lvl {lvl}) | IP: {sip} | {desc} | {str(payload)[:130]}")

conn.close()
