import psycopg2
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
from pipeline.api import reconstruct_attack_paths

conn = psycopg2.connect(host="localhost", port=5432, dbname="wazuh_soc_db", user="postgres", password="postgres")

res = reconstruct_attack_paths(
    entity_type="victim",
    q="ELSA_INSTIKIBALI",
    tenant_id=None,
    time_range="kustom",
    custom_start="2026-09-22",
    custom_end="2026-09-24",
    limit_events=1200,
    conn=conn
)

print("Status:", res.get("status"))
print("Patterns found:", res.get("patterns_found"))
for pat in res.get("top_patterns", []):
    print(f"\n--- PATTERN {pat.get('rank')}: {pat.get('title')} ({pat.get('score_display')}) ---")
    print(f"Target: {pat.get('target_asset')} | Actor: {pat.get('primary_actor')}")
    print("Steps count:", len(pat.get("steps", [])))
    for s in pat.get("steps", []):
        print(f"  Step {s.get('step')}: [{s.get('stage_name')}] Mitre: {s.get('mitre_id')} | Rule: {s.get('rule_id')} - {s.get('rule_desc')} | Count: {s.get('event_count')}")

conn.close()
