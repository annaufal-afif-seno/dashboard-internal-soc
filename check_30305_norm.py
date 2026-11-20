
import psycopg2
import json

conn = psycopg2.connect(
    host="localhost",
    port=5432,
    dbname="wazuh_soc_db",
    user="postgres",
    password="postgres"
)
cur = conn.cursor()

cur.execute("""
    SELECT n.raw_event_id, r.raw_payload
    FROM telemetry.normalized_events n
    JOIN telemetry.raw_events r ON n.raw_event_id = r.event_id
    WHERE n.rule_id = 30305
    LIMIT 1;
""")
row = cur.fetchone()
if row:
    payload = json.loads(row[1])
    print("Exact Rule 30305 payload:")
    print("Rule:", payload.get("rule"))
    print("Decoder:", payload.get("decoder"))
    print("Data:", payload.get("data"))
    print("Full log:", payload.get("full_log"))
else:
    print("Rule 30305 not found in join")

conn.close()
