
import psycopg2
import os

conn = psycopg2.connect(
    host="localhost",
    port=5432,
    dbname="wazuh_soc_db",
    user="postgres",
    password="postgres"
)
cur = conn.cursor()

# 1. Total apex activity groups
cur.execute("SELECT count(*) FROM telemetry.apex_activity_groups;")
total_groups = cur.fetchone()[0]
print(f"Total telemetry.apex_activity_groups: {total_groups}")

# 2. Breakdown by category_code and category_domain
cur.execute("""
    SELECT category_code, category_domain, count(*), min(first_seen_at), max(last_seen_at)
    FROM telemetry.apex_activity_groups
    GROUP BY category_code, category_domain
    ORDER BY count(*) DESC;
""")
print("\nCategory Code | Domain | Groups Count | Min First Seen | Max Last Seen")
print("-" * 80)
for r in cur.fetchall():
    print(f"{r[0]:<20} | {r[1]:<18} | {r[2]:<12} | {str(r[3])[:19]} | {str(r[4])[:19]}")

# 3. Check check constraint on suppression.aggregated_alerts
cur.execute("""
    SELECT conname, pg_get_constraintdef(oid)
    FROM pg_constraint
    WHERE conrelid = 'suppression.aggregated_alerts'::regclass;
""")
print("\nConstraints on suppression.aggregated_alerts:")
for r in cur.fetchall():
    print(f"{r[0]}: {r[1]}")

conn.close()
