import psycopg2
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

conn = psycopg2.connect(host="localhost", port=5432, dbname="wazuh_soc_db", user="postgres", password="postgres")
cur = conn.cursor()

# Query attack-related events on ELSA_INSTIKIBALI between Sep 21 - Sep 26
cur.execute("""
    SELECT r.timestamp, n.rule_id, n.rule_description, n.rule_level, r.source_ip, r.raw_payload
    FROM telemetry.raw_events r
    JOIN telemetry.normalized_events n ON r.event_id = n.raw_event_id
    WHERE r.agent_name = 'ELSA_INSTIKIBALI'
      AND r.timestamp >= '2026-09-21 00:00:00+00'
      AND r.timestamp <= '2026-09-26 23:59:59+00'
      AND (
          n.rule_level >= 6
          OR n.rule_id IN (5402, 5407, 2832, 550, 554, 5301, 31106, 31514, 31516, 31103, 31164)
          OR r.source_ip IN ('114.10.12.151', '114.5.208.145', '103.171.183.71', '175.16.80.24')
          OR r.raw_payload::text ILIKE '%uid.html%'
          OR r.raw_payload::text ILIKE '%cf.py%'
          OR r.raw_payload::text ILIKE '%test_aead%'
          OR r.raw_payload::text ILIKE '%gs-netcat%'
          OR r.raw_payload::text ILIKE '%packagekitd%'
          OR r.raw_payload::text ILIKE '%2629721%'
      )
    ORDER BY r.timestamp ASC;
""")
rows = cur.fetchall()
print(f"Total attack-related alerts found: {len(rows)}")
for r in rows[:25]:
    ts, rid, desc, lvl, sip, payload = r
    print(f"[{ts}] Rule {rid} (Lvl {lvl}) | IP: {sip} | Desc: {desc} | Payload sample: {str(payload)[:120]}")

conn.close()
