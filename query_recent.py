
import psycopg2

conn = psycopg2.connect(
    host="localhost",
    port=5432,
    dbname="wazuh_soc_db",
    user="postgres",
    password="postgres"
)
cur = conn.cursor()

cur.execute("""
    SELECT group_id, category_code, category_domain, quality, event_count, first_seen_at, last_seen_at
    FROM telemetry.apex_activity_groups
    ORDER BY last_seen_at DESC
    LIMIT 15;
""")
print("Latest 15 Apex Activity Groups in VM DB:")
print("-" * 105)
for r in cur.fetchall():
    print(f"{r[0]:<22} | {r[1]:<18} | {r[2]:<18} | {r[3]:<8} | Count: {r[4]:<5} | Last: {str(r[6])[:19]}")

conn.close()
