import psycopg2
from psycopg2 import extras
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

conn = psycopg2.connect(host="localhost", port=5432, dbname="wazuh_soc_db", user="postgres", password="postgres")
cur = conn.cursor(cursor_factory=extras.RealDictCursor)

t_start = "2026-09-01 00:00:00+07"
t_end = "2026-10-01 00:00:00+07"
q_like = "%ELSA_INSTIKIBALI%"

# Stratified Forensic Query
query = """
    WITH critical_attack_events AS (
        -- Prioritize ALL high/critical security alerts across the entire window
        SELECT 
            r.event_id AS id,
            r.timestamp,
            to_char(r.timestamp AT TIME ZONE 'Asia/Jakarta', 'Mon DD, HH24:MI:SS') || ' WIB' AS timestamp_formatted,
            COALESCE(n.rule_id, 0) AS rule_id,
            COALESCE(n.rule_level, 3) AS rule_level,
            COALESCE(n.rule_description, 'Security event') AS rule_description,
            COALESCE(r.agent_name, r.destination_ip, 'unknown') AS target,
            COALESCE(r.source_ip, 'proc:' || COALESCE(r.decoder_name, 'internal')) AS actor,
            COALESCE(r.tenant_id, 'DEFAULT') AS tenant_id,
            COALESCE(r.raw_payload::text, '') AS full_log,
            1 AS priority_tier
        FROM telemetry.raw_events r
        LEFT JOIN telemetry.normalized_events n ON r.event_id = n.raw_event_id
        WHERE r.timestamp >= %s AND r.timestamp <= %s
          AND r.agent_name ILIKE %s
          AND (n.rule_id < 19000 OR n.rule_id > 19999)
          AND n.rule_id > 0
          AND (
              n.rule_level >= 6
              OR n.rule_id IN (510, 550, 554, 591, 2832, 2902, 2904, 5301, 5402, 5403, 5406, 5407, 5501, 5502, 5503, 5715, 5760, 31103, 31104, 31106, 31164, 31430, 31514, 31516)
              OR r.raw_payload::text ILIKE '%%question.php%%'
              OR r.raw_payload::text ILIKE '%%uid.html%%'
              OR r.raw_payload::text ILIKE '%%cf.py%%'
              OR r.raw_payload::text ILIKE '%%test_aead%%'
              OR r.raw_payload::text ILIKE '%%gs-netcat%%'
              OR r.raw_payload::text ILIKE '%%packagekitd%%'
              OR r.raw_payload::text ILIKE '%%kcached%%'
              OR r.raw_payload::text ILIKE '%%mdl_user%%'
              OR r.raw_payload::text ILIKE '%%/tmp%%'
          )
        ORDER BY n.rule_level DESC, r.timestamp ASC
        LIMIT 1000
    ),
    recon_sample AS (
        -- Sample recon & probing activity
        SELECT 
            r.event_id AS id,
            r.timestamp,
            to_char(r.timestamp AT TIME ZONE 'Asia/Jakarta', 'Mon DD, HH24:MI:SS') || ' WIB' AS timestamp_formatted,
            COALESCE(n.rule_id, 0) AS rule_id,
            COALESCE(n.rule_level, 3) AS rule_level,
            COALESCE(n.rule_description, 'Security event') AS rule_description,
            COALESCE(r.agent_name, r.destination_ip, 'unknown') AS target,
            COALESCE(r.source_ip, 'proc:' || COALESCE(r.decoder_name, 'internal')) AS actor,
            COALESCE(r.tenant_id, 'DEFAULT') AS tenant_id,
            COALESCE(r.raw_payload::text, '') AS full_log,
            2 AS priority_tier
        FROM telemetry.raw_events r
        LEFT JOIN telemetry.normalized_events n ON r.event_id = n.raw_event_id
        WHERE r.timestamp >= %s AND r.timestamp <= %s
          AND r.agent_name ILIKE %s
          AND (n.rule_id < 19000 OR n.rule_id > 19999)
          AND n.rule_id > 0
          AND n.rule_id IN (31151, 31533, 31101, 31301)
        ORDER BY r.timestamp ASC
        LIMIT 500
    )
    SELECT * FROM critical_attack_events
    UNION ALL
    SELECT * FROM recon_sample
    ORDER BY timestamp ASC;
"""

cur.execute(query, (t_start, t_end, q_like, t_start, t_end, q_like))
rows = cur.fetchall()
print(f"Total forensic-stratified events: {len(rows)}")

# Let's run classify_stage on these rows
def classify_stage(rule_id, desc, log):
    desc_l = (desc or '').lower()
    log_l = (log or '').lower()
    if 'mdl_user' in log_l or rule_id in (31103, 31164):
        return 5, 'Data Exfiltration (MySQL & Accounts)', 'T1041', 'red'
    if 'crontab' in desc_l or 'packagekitd' in log_l or 'gs-netcat' in log_l or rule_id in (2832, 550, 40704):
        return 4, 'Persistence & Backdoor Deployment', 'T1543.002', 'rose'
    if 'rootcheck' in desc_l or 'sudo' in desc_l or 'test_aead' in log_l or '-perm -4000' in log_l or rule_id in (510, 5402, 5407, 5301):
        return 3, 'Execution & Privilege Escalation', 'T1548.003', 'indigo'
    if 'uid.html' in log_l or 'cf.py' in log_l or 'question.php' in log_l or rule_id in (31106, 31514, 31104):
        return 2, 'Initial Access & Web Exploitation', 'T1190', 'amber'
    return 1, 'Reconnaissance & Vulnerability Scanning', 'T1595', 'purple'

stage_counts = {}
for r in rows:
    s_num, s_name, mitre, col = classify_stage(r['rule_id'], r['rule_description'], r['full_log'])
    stage_counts[s_name] = stage_counts.get(s_name, 0) + 1

print("\nReconstructed Kill Chain across 30 days:")
for s, c in stage_counts.items():
    print(f"  * {s}: {c} events")

conn.close()
