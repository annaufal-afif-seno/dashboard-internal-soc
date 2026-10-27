import psycopg2

conn = psycopg2.connect(host="localhost", port=5432, dbname="wazuh_soc_db", user="postgres", password="postgres")
cur = conn.cursor()

cur.execute("""
    SELECT DATE(r.timestamp), count(*)
    FROM telemetry.raw_events r
    WHERE r.agent_name = 'ELSA_INSTIKIBALI'
    GROUP BY 1
    ORDER BY 1;
""")
print("=== ELSA_INSTIKIBALI EVENTS BY DAY ===")
for r in cur.fetchall():
    print(r)

conn.close()
