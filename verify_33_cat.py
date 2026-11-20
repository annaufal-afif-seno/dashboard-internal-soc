
import sys
sys.path.insert(0, '/opt/dashboard-internal-soc-v3')
from pipeline.category_catalog import APEX_33_CATEGORIES, APEX_32_CATEGORIES, classify_alert
from pipeline.fingerprint_engine import generate_fingerprint, tf_status_cls, tf_msg_normalize

print("Categories count:", len(APEX_33_CATEGORIES))
assert len(APEX_33_CATEGORIES) == 33
assert len(set(c.code for c in APEX_33_CATEGORIES)) == 33
assert APEX_32_CATEGORIES is APEX_33_CATEGORIES

domains = {}
for c in APEX_33_CATEGORIES:
    domains[c.domain] = domains.get(c.domain, 0) + 1
print("Domains distribution:", domains)
assert len(domains) == 8

# Test specific rules with all required keys present
test_alerts = [
    # 31103 SQLi -> web_attack
    ({"tenant_id": "T1", "rule": {"id": 31103, "groups": ["web_attack", "sqli"]}, "network": {"src_ip": "1.2.3.4"}, "observer": {"agent_name": "web1"}}, "web_attack", "Web"),
    # 31151 400 error -> web_client_error
    ({"tenant_id": "T1", "rule": {"id": 31151, "groups": ["web", "accesslog"]}, "http": {"status_code": 404, "url_path": "/login"}, "network": {"src_ip": "1.2.3.4"}, "observer": {"agent_name": "web1"}}, "web_client_error", "Web"),
    # 31120 500 error -> web_server_error
    ({"tenant_id": "T1", "rule": {"id": 31120, "groups": ["web", "accesslog"]}, "data": {"id": "500", "url": "/api"}, "network": {"src_ip": "1.2.3.4"}, "observer": {"agent_name": "web1"}}, "web_server_error", "Web"),
    # 31533 High request rate -> web_post_burst
    ({"tenant_id": "T1", "rule": {"id": 31533, "groups": ["web_post_burst"]}, "observer": {"agent_name": "web1"}}, "web_post_burst", "Web"),
    # 30411 ModSecurity -> web_waf_block
    ({"tenant_id": "T1", "rule": {"id": 30411, "groups": ["modsecurity"]}, "network": {"src_ip": "1.2.3.4"}, "observer": {"agent_name": "web1"}}, "web_waf_block", "Web"),
    # 31301 Nginx error -> app_error_log
    ({"tenant_id": "T1", "rule": {"id": 31301, "description": "Nginx: worker died", "groups": ["nginx-errorlog"]}, "network": {"src_ip": "1.2.3.4"}, "observer": {"agent_name": "web1"}}, "app_error_log", "Endpoint"),
    # 5502 PAM login -> system_event
    ({"tenant_id": "T1", "rule": {"id": 5502, "description": "PAM: login opened", "groups": ["pam"]}, "observer": {"agent_name": "web1"}}, "system_event", "Endpoint"),
    # 5710 Auth failed -> auth_bruteforce
    ({"tenant_id": "T1", "rule": {"id": 5710, "groups": ["authentication_failed"]}, "network": {"src_ip": "1.2.3.4"}, "target": {"user_name": "admin"}, "observer": {"agent_name": "web1"}}, "auth_bruteforce", "Identity & access")
]

for a, expected_code, expected_domain in test_alerts:
    pol = classify_alert(a)
    fp = generate_fingerprint(a, pol)
    r_id = a["rule"]["id"]
    print(f"Rule {r_id} -> Cat: {pol.code} ({pol.domain}) Quality: {fp.quality} Hash: {fp.hash[:12]}...")
    assert pol.code == expected_code, f"Expected {expected_code}, got {pol.code}"
    assert pol.domain == expected_domain, f"Expected {expected_domain}, got {pol.domain}"
    assert fp.quality == "exact", f"Expected exact quality, got {fp.quality}"

print("ALL 33-CATEGORY VERIFICATION CHECKS PASSED!")
