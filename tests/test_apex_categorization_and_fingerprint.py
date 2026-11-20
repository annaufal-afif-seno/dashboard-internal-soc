"""
Unit Test Suite for Apex Categorization & Fingerprint Engine (Version 4.0 - 33 Categories in 8 Domains)
Ensures 100% adherence to Apex Gold Standard specification without touching the VM.
"""

import pytest
import json
from pipeline.category_catalog import (
    classify_alert,
    APEX_33_CATEGORIES,
    APEX_32_CATEGORIES,
    CategoryPolicy
)
from pipeline.fingerprint_engine import (
    generate_fingerprint,
    tf_clean_user,
    tf_file_dir,
    tf_url_template,
    tf_status_cls,
    tf_msg_normalize,
    CRITICAL_SECURITY_PATHS
)

def test_33_categories_catalog_integrity():
    """Verify all 33 categories are registered, unique, and spread across exactly 8 domains."""
    codes = [c.code for c in APEX_33_CATEGORIES]
    assert len(codes) == 33
    assert len(set(codes)) == 33
    assert APEX_32_CATEGORIES is APEX_33_CATEGORIES

    domains = {}
    for c in APEX_33_CATEGORIES:
        domains[c.domain] = domains.get(c.domain, 0) + 1

    assert len(domains) == 8
    assert domains["Identity & access"] == 3
    assert domains["Network"] == 6
    assert domains["Web"] == 5
    assert domains["Endpoint"] == 10
    assert domains["Posture"] == 3
    assert domains["Cloud & SaaS"] == 4
    assert domains["Containers"] == 1
    assert domains["Fallback"] == 1

def test_layered_specificity_sqli_with_compliance_tags():
    """
    Test that an active exploit (SQLi) with PCI DSS compliance tags is classified
    as web_attack (Weight 100) and NOT hijacked by policy_violation (Weight 30).
    """
    alert = {
        "tenant_id": "TenantA",
        "rule": {
            "id": 31103,
            "level": 12,
            "description": "SQL Injection attempt",
            "groups": ["web", "accesslog", "attack", "sqli", "pci_dss", "gdpr"]
        },
        "network": {
            "src_ip": "198.51.100.5",
            "dst_ip": "10.0.0.5"
        },
        "observer": {
            "agent_name": "web-srv-01"
        }
    }
    policy = classify_alert(alert)
    assert policy.code == "web_attack"
    assert policy.domain == "Web"
    assert policy.specificity_weight == 100

def test_web_client_error_classification_and_fingerprint():
    """
    Test classification of Rule 31151 (HTTP 400 error codes).
    Verifies URL template transform, status:cls transform, and exact quality.
    """
    alert = {
        "tenant_id": "TenantC",
        "rule": {
            "id": 31151,
            "level": 10,
            "description": "Multiple web server 400 error codes from same source ip.",
            "groups": ["web", "accesslog", "web_scan", "recon"]
        },
        "network": {
            "src_ip": "34.18.116.21",
            "dst_ip": "192.168.1.159"
        },
        "http": {
            "status_code": 404,
            "url_path": "/.env1"
        },
        "observer": {
            "agent_name": "hportal-prod-159"
        }
    }
    policy = classify_alert(alert)
    assert policy.code == "web_client_error"
    assert policy.domain == "Web"

    fp = generate_fingerprint(alert, policy)
    assert fp.quality == "exact"
    assert fp.body["tenant"] == "TenantC"
    assert fp.body["c"] == "web_client_error"
    assert fp.body["t"] == "leaf"
    assert fp.body["p"]["agent"] == "hportal-prod-159"
    assert fp.body["p"]["src_ip:true_client"] == "34.18.116.21"
    assert fp.body["p"]["status:cls"] == "4xx"
    assert "url_path:tmpl" in fp.tracked_samples
    assert fp.tracked_samples["url_path:tmpl"] == ["/.env1"]

def test_web_server_error_classification_and_fingerprint():
    """
    Test classification of Rule 31120 (HTTP 500 error code).
    Verifies status extraction and target focus behaviour.
    """
    alert = {
        "tenant_id": "TenantC",
        "rule": {
            "id": 31120,
            "level": 7,
            "description": "Web server 500 error code (Internal Server Error)",
            "groups": ["web", "accesslog"]
        },
        "network": {
            "src_ip": "10.0.0.45",
            "dst_ip": "192.168.1.159"
        },
        "data": {
            "id": "500",
            "url": "/api/checkout"
        },
        "observer": {
            "agent_name": "hportal-prod-159"
        }
    }
    policy = classify_alert(alert)
    assert policy.code == "web_server_error"
    assert policy.domain == "Web"
    assert policy.behaviour == "target focus"

    fp = generate_fingerprint(alert, policy)
    assert fp.quality == "exact"
    assert fp.body["p"]["status"] == "500"
    assert fp.body["p"]["agent"] == "hportal-prod-159"
    assert "src_ip" in fp.tracked_samples

def test_app_error_log_classification_and_fingerprint():
    """
    Test classification of Rule 31301 (Nginx error log).
    Verifies app_error_log categorization and msg:msg sanitization.
    """
    alert = {
        "tenant_id": "TenantC",
        "rule": {
            "id": 31301,
            "level": 5,
            "description": "Nginx: Worker process died",
            "groups": ["nginx-errorlog", "web"]
        },
        "network": {
            "src_ip": "192.168.1.1"
        },
        "observer": {
            "agent_name": "hportal-prod-159"
        }
    }
    policy = classify_alert(alert)
    assert policy.code == "app_error_log"
    assert policy.domain == "Endpoint"
    assert policy.behaviour == "target focus"

    fp = generate_fingerprint(alert, policy)
    assert fp.quality == "exact"
    assert fp.body["p"]["rule"] == "31301"
    assert fp.body["p"]["msg:msg"] == "nginx: worker process died"

def test_system_event_classification_and_fingerprint():
    """
    Test classification of Rule 5502 (PAM login session event).
    Verifies system_event category and agent + rule + msg:msg fingerprint.
    """
    alert = {
        "tenant_id": "TenantA",
        "rule": {
            "id": 5502,
            "level": 3,
            "description": "PAM: Login session opened",
            "groups": ["syslog", "pam"]
        },
        "observer": {
            "agent_name": "srv-prod"
        }
    }
    policy = classify_alert(alert)
    assert policy.code == "system_event"
    assert policy.domain == "Endpoint"
    assert policy.behaviour == "exact"

    fp = generate_fingerprint(alert, policy)
    assert fp.quality == "exact"
    assert fp.body["p"]["rule"] == "5502"
    assert fp.body["p"]["msg:msg"] == "pam: login session opened"

def test_apache_errorlog_30305_classification():
    """
    Test classification of Rule 30305 (Apache access forbidden / error log).
    Verifies that decoder evidence 'apache-errorlog' and rule 30305 classify into app_error_log.
    """
    alert = {
        "tenant_id": "TenantP",
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
    policy = classify_alert(alert)
    assert policy.code == "app_error_log"
    assert policy.domain == "Endpoint"

    fp = generate_fingerprint(alert, policy)
    assert fp.quality == "exact"
    assert fp.body["p"]["rule"] == "30305"

def test_pam_session_opened_5501_classification():
    """
    Test classification of Rule 5501 (PAM: Login session opened).
    Verifies companion rule 5501 classifies cleanly into system_event.
    """
    alert = {
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
    policy = classify_alert(alert)
    assert policy.code == "system_event"
    assert policy.domain == "Endpoint"

    fp = generate_fingerprint(alert, policy)
    assert fp.quality == "exact"
    assert fp.body["p"]["rule"] == "5501"

def test_multi_tenant_cryptographic_isolation():
    """
    CRITICAL: Verify that the exact same attack occurring on two different tenants
    produces two distinct cryptographic hashes (Zero cross-tenant collision).
    """
    alert_tenant_a = {
        "tenant_id": "TenantA",
        "rule": {"id": 5710, "groups": ["authentication_failed"]},
        "network": {"src_ip": "203.0.113.10"},
        "target": {"user_name": "root"},
        "observer": {"agent_name": "srv-prod"}
    }
    alert_tenant_b = {
        "tenant_id": "TenantB",
        "rule": {"id": 5710, "groups": ["authentication_failed"]},
        "network": {"src_ip": "203.0.113.10"},
        "target": {"user_name": "root"},
        "observer": {"agent_name": "srv-prod"}
    }

    policy = classify_alert(alert_tenant_a)
    assert policy.code == "auth_bruteforce"

    fp_a = generate_fingerprint(alert_tenant_a, policy)
    fp_b = generate_fingerprint(alert_tenant_b, policy)

    assert fp_a.hash != fp_b.hash
    assert fp_a.body["tenant"] == "TenantA"
    assert fp_b.body["tenant"] == "TenantB"

def test_user_clean_transform():
    """Verify user:clean strips domain prefixes, UPN suffixes, and normalizes casing."""
    assert tf_clean_user("CORP\\Administrator") == "administrator"
    assert tf_clean_user("admin@corp.local") == "admin"
    assert tf_clean_user("  jOhN_dOe  ") == "john_doe"
    assert tf_clean_user(None) == "__NULL__"

def test_status_cls_transform():
    """Verify status:cls transforms 404 -> 4xx, 502 -> 5xx, etc."""
    assert tf_status_cls(404) == "4xx"
    assert tf_status_cls("502") == "5xx"
    assert tf_status_cls("200 OK") == "2xx"
    assert tf_status_cls(None) == "__NULL__"

def test_msg_normalize_transform():
    """Verify msg:msg strips timestamps, PIDs, hex, IPs, and collapses whitespace."""
    raw = "2026/11/16 14:33:39 [error] 12345#12345: *6789 open() failed (2: No such file) [pid 999] at 0x7fff"
    normalized = tf_msg_normalize(raw)
    assert "14:33:39" not in normalized
    assert "[pid 999]" not in normalized
    assert "0x7fff" not in normalized
    assert "open() failed" in normalized

def test_file_path_dir_with_critical_path_exemption():
    """
    Verify normal paths are reduced to parent directory,
    while sensitive security paths (/etc/shadow) retain full path.
    """
    assert tf_file_dir("/var/log/apache2/access.log") == "/var/log/apache2"
    assert tf_file_dir("/home/user/test.txt") == "/home/user"

    assert tf_file_dir("/etc/shadow") == "/etc/shadow"
    assert tf_file_dir("/etc/passwd") == "/etc/passwd"
    assert tf_file_dir("/etc/sudoers") == "/etc/sudoers"

def test_url_template_transform():
    """Verify numeric IDs and UUIDs are collapsed into templates to prevent explosion."""
    assert tf_url_template("/api/v1/users/4921/view?token=xyz") == "/api/v1/users/{id}/view"
    assert tf_url_template("/order/c9a646d3-9c61-4cc9-bc55-e4d07b71329c") == "/order/{uuid}"
    assert tf_url_template("/index.php") == "/index.php"

def test_missing_required_field_triggers_degraded_tier():
    """
    If a required key field is missing (e.g. auth failure with NO username and NO src_ip),
    it must trigger the degraded tier with [rule_id, agent] fallback.
    """
    alert = {
        "tenant_id": "TenantA",
        "rule": {"id": 5710, "groups": ["authentication_failed"]},
        "observer": {"agent_name": "db-server"}
    }
    policy = classify_alert(alert)
    fp = generate_fingerprint(alert, policy)

    assert fp.quality == "degraded"
    assert fp.body["t"] == "degraded"
    assert fp.body["p"]["rule_id"] == "5710"
    assert fp.body["p"]["agent"] == "db-server"

def test_unmatched_alert_falls_to_generic_rule():
    """Alerts with unknown groups fall back to generic_rule with fallback quality."""
    alert = {
        "tenant_id": "TenantA",
        "rule": {"id": 99999, "groups": ["unknown_custom_hardware_event"]},
        "observer": {"agent_name": "custom-sensor"}
    }
    policy = classify_alert(alert)
    assert policy.code == "generic_rule"
    assert policy.domain == "Fallback"

    fp = generate_fingerprint(alert, policy)
    assert fp.quality == "fallback"
    assert fp.body["t"] == "leaf"
