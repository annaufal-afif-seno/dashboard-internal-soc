
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

# Query distinct quality counts
cur.execute("""
    SELECT quality, count(*)
    FROM telemetry.apex_activity_groups
    GROUP BY quality
    ORDER BY count(*) DESC;
""")
print("Quality Distribution in telemetry.apex_activity_groups:")
for r in cur.fetchall():
    print(f"  {r[0]:<12}: {r[1]:<8} groups")

# Sample fingerprints across different categories
cur.execute("""
    SELECT category_code, quality, fingerprint_hash, fingerprint_body, tracked_samples, tracked_counts
    FROM telemetry.apex_activity_groups
    WHERE category_code IN ('web_attack', 'web_client_error', 'fim_change', 'vuln_detected', 'app_error_log', 'system_event')
    ORDER BY last_seen_at DESC
    LIMIT 6;
""")
print("\nSample Fingerprint Data in VM DB:")
print("-" * 100)
for r in cur.fetchall():
    cat, qual, f_hash, body, t_samples, t_counts = r
    print(f"Cat: {cat:<18} | Qual: {qual:<8} | Hash: {f_hash[:16]}...")
    print(f"  Body: {body}")
    print(f"  Tracked Samples: {t_samples}")
    print(f"  Tracked Counts:  {t_counts}")
    print()

conn.close()
