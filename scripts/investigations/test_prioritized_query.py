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

cur.execute("""
    SELECT 
        r.event_id AS id,
        r.timestamp,
        COALESCE(n.rule_id, 0) AS rule_id,
        COALESCE(n.rule_level, 3) AS rule_level,
        COALESCE(n.rule_description, 'Security event') AS rule_description,
        r.source_ip AS actor,
        r.raw_payload::text AS full_log
    FROM telemetry.raw_events r
    LEFT JOIN telemetry.normalized_events n ON r.event_id = n.raw_event_id
    WHERE r.timestamp >= %s AND r.timestamp <= %s
      AND r.agent_name ILIKE %s
      AND (n.rule_id < 19000 OR n.rule_id > 19999)
      AND n.rule_id > 0
    ORDER BY n.rule_level DESC, r.timestamp DESC
    LIMIT 1200;
""", (t_start, t_end, q_like))

rows = cur.fetchall()
print(f"Loaded {len(rows)} prioritized events across whole September")

# Check min and max timestamp
timestamps = [r['timestamp'] for r in rows]
print(f"Span: {min(timestamps)} to {max(timestamps)}")

# Check rules found
rules = {}
for r in rows:
    rid = (r['rule_id'], r['rule_description'], r['rule_level'])
    rules[rid] = rules.get(rid, 0) + 1

for (rid, desc, lvl), c in sorted(rules.items(), key=lambda x: (x[0][2], x[1]), reverse=True):
    print(f"  Level {lvl} | Rule {rid}: {desc} | Count: {c}")

conn.close()
