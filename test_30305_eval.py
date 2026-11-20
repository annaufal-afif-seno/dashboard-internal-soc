
import sys
sys.path.insert(0, '/opt/dashboard-internal-soc-v3')
import json
import psycopg2
from pipeline.category_catalog import classify_alert, match_alert_against_criteria, APEX_33_CATEGORIES
from pipeline.fingerprint_engine import generate_fingerprint

conn = psycopg2.connect(
    host="localhost",
    port=5432,
    dbname="wazuh_soc_db",
    user="postgres",
    password="postgres"
)
cur = conn.cursor()
cur.execute("""
    SELECT n.raw_event_id, r.raw_payload
    FROM telemetry.normalized_events n
    JOIN telemetry.raw_events r ON n.raw_event_id = r.event_id
    WHERE n.rule_id = 30305
    LIMIT 1;
""")
row = cur.fetchone()
alert = json.loads(row[1])

print("Testing alert Rule 30305...")
pol = classify_alert(alert)
print("classify_alert returned:", pol.code, pol.domain)

app_err_pol = next(c for c in APEX_33_CATEGORIES if c.code == "app_error_log")
print("Evaluating against app_error_log criteria:", app_err_pol.match_criteria)
matched = match_alert_against_criteria(alert, app_err_pol.match_criteria)
print("Did it match app_error_log?", matched)

# Check why
print("Decoder name in alert:", alert.get("decoder", {}).get("name"))

conn.close()
