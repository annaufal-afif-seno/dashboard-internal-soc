import psycopg2
from psycopg2 import extras
import json
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

conn = psycopg2.connect(host="localhost", port=5432, dbname="wazuh_soc_db", user="postgres", password="postgres")
cur = conn.cursor(cursor_factory=extras.RealDictCursor)

t_start = "2026-09-21 00:00:00+07"
t_end = "2026-09-27 00:00:00+07"
q_like = "%ELSA_INSTIKIBALI%"

cur.execute("""
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
        COALESCE(r.raw_payload::text, '') AS full_log
    FROM telemetry.raw_events r
    LEFT JOIN telemetry.normalized_events n ON r.event_id = n.raw_event_id
    WHERE r.timestamp >= %s AND r.timestamp <= %s
      AND r.agent_name ILIKE %s
      AND (n.rule_id < 19000 OR n.rule_id > 19999)
      AND n.rule_id > 0
    ORDER BY r.timestamp DESC
    LIMIT 1200;
""", (t_start, t_end, q_like))

rows = cur.fetchall()
print(f"Loaded {len(rows)} events for ELSA_INSTIKIBALI")

# Check rule breakdown in these 1200 rows
rules = {}
actors = {}
for r in rows:
    rid = (r['rule_id'], r['rule_description'], r['rule_level'])
    rules[rid] = rules.get(rid, 0) + 1
    actors[r['actor']] = actors.get(r['actor'], 0) + 1

print("\nRules in sample:")
for (rid, desc, lvl), c in sorted(rules.items(), key=lambda x: x[1], reverse=True)[:10]:
    print(f"  Rule {rid} (Lvl {lvl}): {desc} | Count: {c}")

print("\nTop Actors:")
for a, c in sorted(actors.items(), key=lambda x: x[1], reverse=True)[:5]:
    print(f"  Actor {a}: {c}")

conn.close()
