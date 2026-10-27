import psycopg2
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

conn = psycopg2.connect(host="localhost", port=5432, dbname="wazuh_soc_db", user="postgres", password="postgres")
cur = conn.cursor()

# Check distinct rules on ELSA_INSTIKIBALI
cur.execute("""
    SELECT n.rule_id, n.rule_description, n.rule_level, count(*)
    FROM telemetry.raw_events r
    JOIN telemetry.normalized_events n ON r.event_id = n.raw_event_id
    WHERE r.agent_name = 'ELSA_INSTIKIBALI'
    GROUP BY n.rule_id, n.rule_description, n.rule_level
    ORDER BY count(*) DESC;
""")
print("=== RULES ON ELSA_INSTIKIBALI ===")
for r in cur.fetchall():
    print(f"Rule {r[0]} (Lvl {r[2]}): {r[1]} | Count: {r[3]}")

# Check specific IPs from the report: 114.10.12.151, 114.5.208.145, 103.171.183.71, 51.79.230.178
ips = ['114.10.12.151', '114.5.208.145', '103.171.183.71', '51.79.230.178', '103.186.30.22', '139.162.1.138']
print("\n=== CHECKING ATTACKER IPS FROM REPORT IN DB ===")
for ip in ips:
    cur.execute("""
        SELECT count(*), min(timestamp), max(timestamp), array_agg(DISTINCT agent_name)
        FROM telemetry.raw_events
        WHERE source_ip = %s;
    """, (ip,))
    row = cur.fetchone()
    print(f"IP {ip}: Count={row[0]} | Range={row[1]} to {row[2]} | Agents={row[3]}")

# Check specific payloads / keywords from report: 'uid.html', 'cf.py', 'test_aead', 'gs-netcat', 'packagekitd', 'kekuatananime'
keywords = ['uid.html', 'cf.py', 'test_aead', 'gs-netcat', 'packagekitd', 'kcached', 'kekuatananime28', '2629721']
print("\n=== CHECKING KEYWORDS FROM REPORT IN RAW_EVENTS ===")
for kw in keywords:
    cur.execute("""
        SELECT count(*), array_agg(DISTINCT agent_name)
        FROM telemetry.raw_events
        WHERE raw_payload::text ILIKE %s;
    """, (f"%{kw}%",))
    row = cur.fetchone()
    print(f"Keyword '{kw}': Count={row[0]} | Agents={row[1]}")

conn.close()
