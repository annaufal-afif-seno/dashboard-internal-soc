import psycopg2

conn = psycopg2.connect(host="localhost", port=5432, dbname="wazuh_soc_db", user="postgres", password="postgres")
cur = conn.cursor()

q_like = "%ELSA_INSTIKIBALI%"
t_start = "2026-09-21 00:00:00+07"
t_end = "2026-09-27 00:00:00+07"

cur.execute("""
    SELECT count(*), array_agg(DISTINCT r.agent_name)
    FROM telemetry.raw_events r
    WHERE r.timestamp >= %s AND r.timestamp <= %s
      AND r.agent_name ILIKE %s;
""", (t_start, t_end, q_like))

row = cur.fetchone()
print(f"Events for ELSA_INSTIKIBALI between Sep 21 - Sep 27: Count={row[0]} | Agents={row[1]}")
conn.close()
