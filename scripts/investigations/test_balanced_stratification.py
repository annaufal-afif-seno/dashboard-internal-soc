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

# Stratified by Attack Stage / Rule Diversity!
query = """
    WITH stage_tagged AS (
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
            CASE
                WHEN n.rule_id IN (31103, 31164) OR r.raw_payload::text ILIKE '%%mdl_user%%' THEN 5
                WHEN n.rule_id IN (2832, 550, 40704, 2902, 2904) OR r.raw_payload::text ILIKE '%%crontab%%' OR r.raw_payload::text ILIKE '%%packagekitd%%' OR r.raw_payload::text ILIKE '%%gs-netcat%%' THEN 4
                WHEN n.rule_id IN (510, 5402, 5403, 5407, 5301, 5501, 5502, 5503, 5715, 5760) OR r.raw_payload::text ILIKE '%%test_aead%%' OR r.raw_payload::text ILIKE '%%-perm -4000%%' OR r.raw_payload::text ILIKE '%%whoami%%' OR r.raw_payload::text ILIKE '%%x=id%%' THEN 3
                WHEN n.rule_id IN (31106, 31514, 31104, 31516, 31430, 31110) OR r.raw_payload::text ILIKE '%%uid.html%%' OR r.raw_payload::text ILIKE '%%cf.py%%' OR r.raw_payload::text ILIKE '%%question.php%%' THEN 2
                ELSE 1
            END AS stage_num,
            ROW_NUMBER() OVER (
                PARTITION BY (
                    CASE
                        WHEN n.rule_id IN (31103, 31164) OR r.raw_payload::text ILIKE '%%mdl_user%%' THEN 5
                        WHEN n.rule_id IN (2832, 550, 40704, 2902, 2904) OR r.raw_payload::text ILIKE '%%crontab%%' OR r.raw_payload::text ILIKE '%%packagekitd%%' OR r.raw_payload::text ILIKE '%%gs-netcat%%' THEN 4
                        WHEN n.rule_id IN (510, 5402, 5403, 5407, 5301, 5501, 5502, 5503, 5715, 5760) OR r.raw_payload::text ILIKE '%%test_aead%%' OR r.raw_payload::text ILIKE '%%-perm -4000%%' OR r.raw_payload::text ILIKE '%%whoami%%' OR r.raw_payload::text ILIKE '%%x=id%%' THEN 3
                        WHEN n.rule_id IN (31106, 31514, 31104, 31516, 31430, 31110) OR r.raw_payload::text ILIKE '%%uid.html%%' OR r.raw_payload::text ILIKE '%%cf.py%%' OR r.raw_payload::text ILIKE '%%question.php%%' THEN 2
                        ELSE 1
                    END
                ), n.rule_id
                ORDER BY r.timestamp ASC
            ) as rank_in_rule
        FROM telemetry.raw_events r
        LEFT JOIN telemetry.normalized_events n ON r.event_id = n.raw_event_id
        WHERE r.timestamp >= %s AND r.timestamp <= %s
          AND r.agent_name ILIKE %s
          AND (n.rule_id < 19000 OR n.rule_id > 19999)
          AND n.rule_id > 0
    )
    SELECT * FROM stage_tagged
    WHERE rank_in_rule <= 50
    ORDER BY timestamp ASC;
"""

cur.execute(query, (t_start, t_end, q_like))
rows = cur.fetchall()
print(f"Total balanced stratified events loaded across 30 days: {len(rows)}")

stage_names = {
    1: 'Reconnaissance & Vulnerability Scanning (T1595)',
    2: 'Initial Access & Web Exploitation (T1190)',
    3: 'Execution & Privilege Escalation (T1548.003)',
    4: 'Persistence & Defense Evasion (T1543.002)',
    5: 'Data Exfiltration (T1041)'
}

stage_counts = {}
for r in rows:
    sn = stage_names.get(r['stage_num'], 'Other')
    stage_counts[sn] = stage_counts.get(sn, 0) + 1

print("\nReconstructed Kill-Chain across the whole month of September:")
for s, c in sorted(stage_counts.items()):
    print(f"  * {s}: {c} events")

conn.close()
