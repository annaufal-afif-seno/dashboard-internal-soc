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

query = """
    WITH critical_events AS (
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
              OR n.rule_id IN (510, 550, 554, 591, 2832, 2902, 2904, 5301, 5402, 5403, 5406, 5407, 5501, 5502, 5503, 5715, 5760, 31103, 31104, 31106, 31164, 31430, 31514, 31516, 31533)
              OR r.raw_payload::text ILIKE '%%question.php%%'
              OR r.raw_payload::text ILIKE '%%uid.html%%'
              OR r.raw_payload::text ILIKE '%%cf.py%%'
              OR r.raw_payload::text ILIKE '%%test_aead%%'
              OR r.raw_payload::text ILIKE '%%gs-netcat%%'
              OR r.raw_payload::text ILIKE '%%packagekitd%%'
              OR r.raw_payload::text ILIKE '%%kcached%%'
              OR r.raw_payload::text ILIKE '%%/tmp%%'
          )
        ORDER BY r.timestamp DESC
        LIMIT 1000
    ),
    background_events AS (
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
          AND r.event_id NOT IN (SELECT id FROM critical_events)
        ORDER BY r.timestamp DESC
        LIMIT 500
    )
    SELECT * FROM critical_events
    UNION ALL
    SELECT * FROM background_events
    ORDER BY timestamp ASC;
"""

cur.execute(query, (t_start, t_end, q_like, t_start, t_end, q_like))
rows = cur.fetchall()
print(f"Total smart stratified events loaded: {len(rows)}")

ts_list = [r['timestamp'] for r in rows]
print(f"Span: {min(ts_list)} to {max(ts_list)}")

rules = {}
for r in rows:
    rid = (r['rule_id'], r['rule_description'], r['rule_level'])
    rules[rid] = rules.get(rid, 0) + 1

for (rid, desc, lvl), c in sorted(rules.items(), key=lambda x: (x[0][2], x[1]), reverse=True)[:15]:
    print(f"  Level {lvl} | Rule {rid}: {desc} | Count: {c}")

conn.close()
