import psycopg2

passwords = ["postgres", "admin", "root", "test", "password", "123456"]
for p in passwords:
    try:
        conn = psycopg2.connect(host="localhost", port=5432, dbname="wazuh_soc_db", user="postgres", password=p)
        cur = conn.cursor()
        print("Connected with password:", p)
        cur.execute("SELECT DISTINCT agent_name FROM telemetry.raw_events;")
        print("Agents in local DB:", cur.fetchall())
        cur.execute("SELECT MIN(timestamp), MAX(timestamp), count(*) FROM telemetry.raw_events;")
        print("Date range in local DB:", cur.fetchall())
        cur.execute("SELECT DISTINCT target_host FROM correlation.correlated_incidents;")
        print("Correlated incident victims:", cur.fetchall())
        conn.close()
        break
    except Exception as e:
        print(f"Failed with {p}: {e}")
