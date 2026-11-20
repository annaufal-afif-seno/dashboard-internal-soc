
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
    SELECT raw_payload
    FROM telemetry.raw_events
    WHERE raw_payload LIKE '%30305%'
    LIMIT 1;
""")
row = cur.fetchone()
if row:
    payload = json.loads(row[0])
    print("Sample Rule 30305 raw payload:")
    print("Rule:", payload.get("rule"))
    print("Decoder:", payload.get("decoder"))
    print("Data:", payload.get("data"))
    print("Full log:", payload.get("full_log"))
else:
    print("Rule 30305 not found in raw_events")

conn.close()
