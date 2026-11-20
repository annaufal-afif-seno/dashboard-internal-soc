
import sys
sys.path.insert(0, '/opt/dashboard-internal-soc-v3')
import json
from pipeline.category_catalog import classify_alert
from pipeline.fingerprint_engine import generate_fingerprint

# 1. Test Rule 30305 (Apache Error / Forbidden)
alert_30305 = {
    "tenant_id": "Petra",
    "rule": {
        "id": 30305,
        "level": 5,
        "description": "Apache: Attempt to access forbidden file or directory.",
        "groups": ["apache", "web", "access_denied"]
    },
    "evidence": {
        "decoder": "apache-errorlog"
    },
    "network": {
        "src_ip": "34.76.33.44"
    },
    "observer": {
        "agent_name": "library_petra"
    }
}

pol_30305 = classify_alert(alert_30305)
fp_30305 = generate_fingerprint(alert_30305, pol_30305)
print(f"Rule 30305 -> Category: {pol_30305.code} | Domain: {pol_30305.domain} | Quality: {fp_30305.quality}")
assert pol_30305.code == "app_error_log", f"Expected app_error_log, got {pol_30305.code}"
assert fp_30305.quality == "exact", f"Expected exact, got {fp_30305.quality}"

# 2. Test Rule 5501 (PAM Session Opened)
alert_5501 = {
    "tenant_id": "TenantD",
    "rule": {
        "id": 5501,
        "level": 3,
        "description": "PAM: Login session opened.",
        "groups": ["pam", "syslog"]
    },
    "observer": {
        "agent_name": "isif-rproxy-155"
    }
}

pol_5501 = classify_alert(alert_5501)
fp_5501 = generate_fingerprint(alert_5501, pol_5501)
print(f"Rule 5501 -> Category: {pol_5501.code} | Domain: {pol_5501.domain} | Quality: {fp_5501.quality}")
assert pol_5501.code == "system_event", f"Expected system_event, got {pol_5501.code}"
assert fp_5501.quality == "exact", f"Expected exact, got {fp_5501.quality}"

print("VERIFICATION OF 2 MINOR FIXES ON VM: 100% PASSED!")
