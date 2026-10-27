import psycopg2
from pipeline.api import reconstruct_attack_paths

# Let's inspect raw_events for ELSA_INSTIKIBALI in local DB
conn = psycopg2.connect(host="localhost", port=5432, dbname="wazuh_soc_db", user="postgres", password="postgres")
cur = conn.cursor()

cur.execute("""
    SELECT count(*), min(timestamp), max(timestamp)
    FROM telemetry.raw_events
    WHERE agent_name = 'ELSA_INSTIKIBALI';
""")
print("Raw events for ELSA_INSTIKIBALI:", cur.fetchall())

cur.execute("""
    SELECT r.timestamp, n.rule_id, n.rule_description, n.rule_level, r.raw_payload
    FROM telemetry.raw_events r
    LEFT JOIN telemetry.normalized_events n ON r.event_id = n.raw_event_id
    WHERE r.agent_name = 'ELSA_INSTIKIBALI'
      AND r.timestamp >= '2026-09-21' AND r.timestamp <= '2026-09-27'
    ORDER BY r.timestamp ASC
    LIMIT 20;
""")
rows = cur.fetchall()
print(f"Events between Sep 21 - Sep 27: {len(rows)}")
for r in rows[:10]:
    print(r[0], r[1], r[2], r[3], str(r[4])[:100])

conn.close()
