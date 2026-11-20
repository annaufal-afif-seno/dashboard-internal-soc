
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

# Query the most recent 10 generic_rule groups and their sample fingerprints
cur.execute("""
    SELECT group_id, fingerprint_body, event_count, last_seen_at
    FROM telemetry.apex_activity_groups
    WHERE category_code = 'generic_rule'
    ORDER BY last_seen_at DESC
    LIMIT 10;
""")
print("Top recent generic_rule groups:")
print("-" * 80)
for r in cur.fetchall():
    print(f"Group: {r[0]} | Count: {r[2]} | Last: {str(r[3])[:19]} | Body: {r[1]}")

conn.close()
