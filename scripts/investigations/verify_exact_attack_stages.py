import psycopg2
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

conn = psycopg2.connect(host="localhost", port=5432, dbname="wazuh_soc_db", user="postgres", password="postgres")
cur = conn.cursor()

# Query attack-related events specifically on ELSA_INSTIKIBALI
cur.execute("""
    SELECT 
        r.event_id, r.timestamp, n.rule_id, n.rule_description, n.rule_level, r.source_ip,
        CASE
            WHEN r.raw_payload::text ILIKE '%installaddon%' OR r.raw_payload::text ILIKE '%question/question.php%' THEN 'Stage 1: Reconnaissance & Dual-Path Probing (T1595)'
            WHEN r.raw_payload::text ILIKE '%uid.html%' OR r.raw_payload::text ILIKE '%cf.py%' THEN 'Stage 2: Initial Access & Payload Download/Execution (T1190/T1105)'
            WHEN r.raw_payload::text ILIKE '%test_aead%' OR r.raw_payload::text ILIKE '%-perm -4000%' OR r.raw_payload::text ILIKE '%whoami%' OR r.raw_payload::text ILIKE '%x=id%' THEN 'Stage 3: System Discovery & PrivEsc Check (T1083/T1033/T1068)'
            WHEN r.raw_payload::text ILIKE '%gs-netcat%' OR r.raw_payload::text ILIKE '%packagekitd%' OR n.rule_id = 2832 THEN 'Stage 4: Persistence & Backdoor Deployment (T1105/T1053.003)'
            WHEN r.raw_payload::text ILIKE '%mdl_user%' OR n.rule_id IN (31103, 31164) THEN 'Stage 5: Data Exfiltration (T1041)'
            ELSE 'Supporting Log'
        END AS attack_stage,
        r.raw_payload
    FROM telemetry.raw_events r
    JOIN telemetry.normalized_events n ON r.event_id = n.raw_event_id
    WHERE r.agent_name = 'ELSA_INSTIKIBALI'
      AND r.timestamp >= '2026-09-21 00:00:00+00' AND r.timestamp <= '2026-09-26 23:59:59+00'
      AND (
          r.raw_payload::text ILIKE '%uid.html%'
          OR r.raw_payload::text ILIKE '%cf.py%'
          OR r.raw_payload::text ILIKE '%test_aead%'
          OR r.raw_payload::text ILIKE '%gs-netcat%'
          OR r.raw_payload::text ILIKE '%packagekitd%'
          OR r.raw_payload::text ILIKE '%-perm -4000%'
          OR r.raw_payload::text ILIKE '%whoami%'
          OR r.raw_payload::text ILIKE '%x=id%'
          OR r.raw_payload::text ILIKE '%installaddon%'
          OR n.rule_id IN (2832, 5402, 5407, 31106, 31514)
      )
    ORDER BY r.timestamp ASC;
""")
rows = cur.fetchall()
print(f"Total precise attack events matching report: {len(rows)}")
stages_found = {}
for r in rows:
    stage = r[6]
    stages_found[stage] = stages_found.get(stage, 0) + 1

for s, c in stages_found.items():
    print(f"  * {s}: {c} events")

conn.close()
