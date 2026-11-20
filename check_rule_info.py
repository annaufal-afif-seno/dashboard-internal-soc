
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

for r_id in [100025, 30305, 5715, 5501]:
    cur.execute("""
        SELECT rule_id, rule_level, rule_description, classification_groups
        FROM telemetry.normalized_events
        WHERE rule_id = %s
        LIMIT 1;
    """, (r_id,))
    row = cur.fetchone()
    if row:
        print(f"Rule {row[0]}: Level {row[1]} | Desc: {row[2]} | Groups: {row[3]}")
    else:
        print(f"Rule {r_id}: Not found in normalized_events")

conn.close()
