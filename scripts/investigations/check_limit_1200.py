import psycopg2

conn = psycopg2.connect(host="localhost", port=5432, dbname="wazuh_soc_db", user="postgres", password="postgres")
cur = conn.cursor()

# Check total events for ELSA_INSTIKIBALI in last 30 days of data (e.g. September)
cur.execute("""
    SELECT count(*) 
    FROM telemetry.raw_events 
    WHERE agent_name = 'ELSA_INSTIKIBALI' 
      AND timestamp >= '2026-09-01';
""")
print("Total events on ELSA in September:", cur.fetchone()[0])

# Check what the latest 1200 events contain
cur.execute("""
    SELECT min(timestamp), max(timestamp)
    FROM (
        SELECT timestamp 
        FROM telemetry.raw_events 
        WHERE agent_name = 'ELSA_INSTIKIBALI' 
          AND timestamp >= '2026-09-01'
        ORDER BY timestamp DESC
        LIMIT 1200
    ) sub;
""")
print("Time span of the 1200 events fetched:", cur.fetchone())

conn.close()
