import psycopg2
from psycopg2 import extras
import json
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

conn = psycopg2.connect(host="localhost", port=5432, dbname="wazuh_soc_db", user="postgres", password="postgres")
cur = conn.cursor(cursor_factory=extras.RealDictCursor)

t_start = "2026-09-01 00:00:00+07"
t_end = "2026-10-01 00:00:00+07"
q_clean = "ELSA_INSTIKIBALI"
q_like = f"%{q_clean}%"

where_sql = """
    r.timestamp >= %s AND r.timestamp <= %s
    AND r.agent_name ILIKE %s
    AND (n.rule_id < 19000 OR n.rule_id > 19999)
    AND n.rule_id > 0
"""
params = [t_start, t_end, q_like]

query = f"""
    WITH tagged_events AS (
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
            COALESCE(
                (SELECT array_to_string(n.mitre_attack_ids, ', ') WHERE array_length(n.mitre_attack_ids, 1) > 0),
                CASE 
                    WHEN n.rule_id IN (31103, 31164) OR r.raw_payload::text ILIKE '%%mdl_user%%' THEN 'T1041'
                    WHEN n.rule_id IN (2832, 550, 40704, 2902, 2904) OR r.raw_payload::text ILIKE '%%packagekitd%%' OR r.raw_payload::text ILIKE '%%gs-netcat%%' THEN 'T1543.002'
                    WHEN n.rule_id IN (510, 5402, 5403, 5407, 5301, 5501, 5502, 5503, 5715, 5760) OR r.raw_payload::text ILIKE '%%test_aead%%' OR r.raw_payload::text ILIKE '%%-perm -4000%%' THEN 'T1548.003'
                    WHEN n.rule_id IN (31106, 31514, 31104, 31516, 31430, 31110, 31101, 31301) OR r.raw_payload::text ILIKE '%%uid.html%%' OR r.raw_payload::text ILIKE '%%cf.py%%' OR r.raw_payload::text ILIKE '%%question.php%%' THEN 'T1190'
                    WHEN n.rule_id IN (31533, 533, 31151) THEN 'T1595'
                    ELSE 'T1082'
                END
            ) AS mitre,
            COALESCE(
                (SELECT a2.category FROM suppression.aggregated_alerts a2 WHERE a2.rule_id = n.rule_id LIMIT 1),
                CASE 
                    WHEN n.rule_id IN (31103, 31164) OR r.raw_payload::text ILIKE '%%mdl_user%%' THEN 'EXFILTRATION'
                    WHEN n.rule_id IN (2832, 550, 40704) THEN 'PERSISTENCE'
                    WHEN n.rule_id IN (5402, 5407, 5301, 510) THEN 'PRIVILEGE_ESCALATION'
                    WHEN n.rule_id IN (31106, 31514, 31104, 31516) THEN 'WEB_ATTACK'
                    WHEN n.rule_id IN (31533, 31151) THEN 'DISCOVERY'
                    ELSE 'WEB_OPERATIONAL'
                END
            ) AS category,
            COALESCE(r.raw_payload::text, '') AS full_log,
            ROW_NUMBER() OVER (
                PARTITION BY (
                    CASE 
                        WHEN n.rule_id IN (31103, 31164) OR r.raw_payload::text ILIKE '%%mdl_user%%' THEN 5
                        WHEN n.rule_id IN (2832, 550, 40704, 2902, 2904) OR r.raw_payload::text ILIKE '%%packagekitd%%' OR r.raw_payload::text ILIKE '%%gs-netcat%%' THEN 4
                        WHEN n.rule_id IN (510, 5402, 5403, 5407, 5301, 5501, 5502, 5503, 5715, 5760) OR r.raw_payload::text ILIKE '%%test_aead%%' OR r.raw_payload::text ILIKE '%%-perm -4000%%' THEN 3
                        WHEN n.rule_id IN (31106, 31514, 31104, 31516, 31430, 31110, 31101, 31301) OR r.raw_payload::text ILIKE '%%uid.html%%' OR r.raw_payload::text ILIKE '%%cf.py%%' OR r.raw_payload::text ILIKE '%%question.php%%' THEN 2
                        ELSE 1
                    END
                ), n.rule_id
                ORDER BY r.timestamp ASC
            ) as rank_in_stage
        FROM telemetry.raw_events r
        LEFT JOIN telemetry.normalized_events n ON r.event_id = n.raw_event_id
        WHERE {where_sql}
    )
    SELECT * FROM tagged_events
    WHERE rank_in_stage <= 60
    ORDER BY timestamp ASC
    LIMIT %s;
"""
params.append(1500)
cur.execute(query, params)
rows = cur.fetchall()
print(f"Loaded {len(rows)} events")

def classify_stage(rule_id, desc, cat, full_log):
    desc_l = (desc or '').lower()
    cat_l = (cat or '').lower()
    log_l = (full_log or '').lower()
    if 'mdl_user' in log_l or rule_id in (31103, 31164) or 'exfiltration' in cat_l:
        return 5, 'Data Exfiltration (Database Query)', 'T1041', 'red'
    if any(k in desc_l for k in ['cron', 'persist', 'checksum', 'integrity', 'syscheck', 'dpkg', 'rotated']) or any(k in log_l for k in ['packagekitd', 'gs-netcat', 'kcached']) or rule_id in (2832, 550, 40704, 2902, 2904):
        return 4, 'Persistence & Backdoor Deployment', 'T1543.002', 'rose'
    if any(k in desc_l for k in ['sudo', 'rootcheck', 'missed the password', 'change uid', 'authentication success', 'root', 'privilege']) or any(k in log_l for k in ['test_aead', '-perm -4000', 'whoami', 'x=id']) or rule_id in (510, 5402, 5407, 5301, 5501, 5502, 5503, 5715):
        return 3, 'Execution & Privilege Escalation', 'T1548.003', 'indigo'
    if any(k in desc_l for k in ['attack', 'shell.php', 'cgi-bin', 'web', 'nginx', 'apache', 'injection']) or any(k in log_l for k in ['uid.html', 'cf.py', 'question.php']) or rule_id in (31106, 31514, 31104, 31516, 31430, 31110):
        return 2, 'Initial Access & Web Exploitation', 'T1190', 'amber'
    return 1, 'Reconnaissance & Vulnerability Scanning', 'T1595', 'purple'

stages = {}
for r in rows:
    s_num, s_name, mitre, col = classify_stage(r['rule_id'], r['rule_description'], r['category'], r['full_log'])
    stages[s_name] = stages.get(s_name, 0) + 1

print("\nFinal Stratified Kill-Chain Stages:")
for s, c in sorted(stages.items()):
    print(f"  * {s}: {c} events")

conn.close()
