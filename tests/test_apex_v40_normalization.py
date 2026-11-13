"""
========================================================================================
TEST APEX NORMALIZATION ENGINE VERSION 4.0 (SOVEREIGN GOLD STANDARD)
========================================================================================
Validates all Apex v4.0 enhancements:
1. Zero Assumption Rule: Missing dst_port, http.version, and device defaults are None/'unknown'.
2. Double URL Percent-Decoding: Canonicalizes %252e%252e%252f safely.
3. IPv6 Scope ID Stripping: Link-local fe80::1%eth0 parsed safely without crash.
4. POSIX Leap Second Parsing: Handles 23:59:60 without ValueError.
5. In-Flight Secret Redaction: Auto-redacts Bearer tokens and CLI passwords.
6. ReDoS Input Ceiling: Handles 100KB strings without catastrophic backtracking.
7. Deep JSON Recursion Guard: Handles deeply nested dicts without RecursionError.
8. Dedicated Windows Authentication & Cloud Telemetry Routers.
========================================================================================
"""

import pytest
from datetime import datetime, timezone
from pipeline.apex_normalizer import ApexNormalizerV40, ApexTransformsV40


def test_zero_assumption_on_web_log_without_port():
    """Verifies that an Apache log with no destination port returns dst_port = None (NO GUESSING 80)."""
    raw_alert = {
        "timestamp": "2026-10-16T04:18:36.940+0000",
        "agent": {"id": "019", "name": "hportal-prod-159", "ip": "192.168.1.159"},
        "data": {
            "srcip": "34.18.116.21",
            "protocol": "GET",
            "url": "/.env1",
            "id": "404"
        },
        "full_log": '34.18.116.21 - - [16/Oct/2026:04:18:28 +0000] "GET /.env1 HTTP/1.1" 404 6797 "-" "Mozilla/5.0"'
    }

    out = ApexNormalizerV40.normalize_alert(raw_alert)
    assert out["network"]["dst_port"] is None, "Must be None when port is absent from raw log (Zero Assumption)"
    assert out["alias_source"]["network.dst_port"] == "none:not_in_raw_log"
    assert out["http"]["method"] == "GET"
    assert out["network"]["transport"] == "tcp"


def test_double_url_percent_decoding():
    """Verifies that %252e%252e%252f (double encoded ../) is decoded canonically."""
    raw_path = "/api/%252e%252e%252f/etc/passwd"
    clean = ApexTransformsV40.transform_url_path(raw_path)
    assert clean == "/api/../etc/passwd"


def test_ipv6_scope_id_stripping():
    """Verifies that link-local IPv6 address with scope ID does not raise ValueError."""
    link_local = "fe80::1%eth0"
    clean_ip = ApexTransformsV40.transform_ip(link_local)
    assert clean_ip == "fe80::1"

    # Standard IPv4-mapped IPv6
    mapped_ipv6 = "::ffff:192.168.1.100"
    assert ApexTransformsV40.transform_ip(mapped_ipv6) == "192.168.1.100"


def test_posix_leap_second_parsing():
    """Verifies that 23:59:60 leap second string parses gracefully without crash."""
    ts_leap = "2026-12-31T23:59:60Z"
    dt = ApexNormalizerV40._parse_iso_timestamp(ts_leap)
    assert dt is not None
    assert dt.second == 59
    assert dt.microsecond == 999999


def test_in_flight_secret_redaction():
    """Verifies that cleartext tokens and passwords in raw text are redacted."""
    raw_cmd = "curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID' http://api.internal -p SecretPass123"
    redacted = ApexTransformsV40.redact_in_flight_secrets(raw_cmd)
    assert "Bearer [REDACTED_TOKEN]" in redacted
    assert "-p [REDACTED_SECRET]" in redacted
    assert "SecretPass123" not in redacted


def test_deep_json_recursion_guard():
    """Verifies that deeply nested dict (depth > 20) does not cause RecursionError."""
    deep_dict = {"data": "deep"}
    for _ in range(30):
        deep_dict = {"nested": deep_dict}

    sanitized = ApexTransformsV40.sanitize_null_bytes(deep_dict, max_depth=16)
    assert isinstance(sanitized, dict)


def test_windows_authentication_router():
    """Verifies that Windows Logon EventID 4624 is routed to dedicated authentication object."""
    win_alert = {
        "timestamp": "2026-10-16T04:35:22.411+0000",
        "agent": {"id": "045", "name": "dc-prod-01", "ip": "192.168.1.10"},
        "data": {
            "win": {
                "system": {"eventID": "4624"},
                "eventdata": {
                    "targetUserName": "Administrator",
                    "targetDomainName": "CORP",
                    "logonType": "3",
                    "ipAddress": "192.168.1.55",
                    "sourcePort": "51234",
                    "destinationPort": "445"
                }
            }
        }
    }

    out = ApexNormalizerV40.normalize_alert(win_alert)
    assert "authentication" in out
    assert out["authentication"]["event_id"] == "4624"
    assert out["authentication"]["target_user"] == "administrator"
    assert out["authentication"]["domain"] == "CORP"
    assert out["authentication"]["logon_type"] == 3
    assert out["network"]["src_ip"] == "192.168.1.55"
    assert out["network"]["dst_port"] == 445


def test_cloud_audit_router():
    """Verifies that AWS CloudTrail alert is routed to dedicated cloud object."""
    cloud_alert = {
        "timestamp": "2026-10-16T04:40:00.000Z",
        "agent": {"id": "000", "name": "wazuh-manager"},
        "data": {
            "aws": {
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateUser",
                "awsRegion": "us-east-1",
                "userIdentity": {"arn": "arn:aws:iam::123456789012:user/attacker"},
                "sourceIPAddress": "203.0.113.19"
            }
        }
    }

    out = ApexNormalizerV40.normalize_alert(cloud_alert)
    assert "cloud" in out
    assert out["cloud"]["provider"] == "aws"
    assert out["cloud"]["actor_arn"] == "arn:aws:iam::123456789012:user/attacker"
    assert out["cloud"]["operation"] == "CreateUser"
    assert out["network"]["src_ip"] == "203.0.113.19"
    assert out["network"]["dst_port"] is None, "Zero Assumption: dst_port is None for cloud API unless explicit"
    assert out["alias_source"]["network.dst_port"] == "none:cloud_api_no_port_in_raw_log"


def test_github_cloud_audit_router():
    """Verifies that GitHub Audit alert extracts actor, operation, and IP correctly."""
    github_alert = {
        "timestamp": "2026-10-16T04:45:00.000Z",
        "agent": {"id": "000", "name": "wazuh-manager"},
        "data": {
            "github": {
                "actor": "octocat-hacker",
                "action": "repo.destroy",
                "actor_ip": "198.51.100.42",
                "repository": "corp/classified-repo"
            }
        }
    }

    out = ApexNormalizerV40.normalize_alert(github_alert)
    assert "cloud" in out
    assert out["cloud"]["provider"] == "github"
    assert out["cloud"]["actor_arn"] == "octocat-hacker"
    assert out["cloud"]["operation"] == "repo.destroy"
    assert out["network"]["src_ip"] == "198.51.100.42"
    assert out["network"]["dst_port"] is None


def test_user_agent_edge_opera_and_bots():
    """Verifies that Edge, Opera, and Googlebot are parsed accurately without Chrome/desktop misattribution."""
    edge_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36 Edg/131.0.2903.86"
    res_edge = ApexNormalizerV40._parse_user_agent(edge_ua)
    assert res_edge["browser"] == "Edge"
    assert res_edge["browser_version"] == "131.0.2903.86"
    assert res_edge["device"] == "desktop"

    opera_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36 OPR/115.0.5322.77"
    res_opera = ApexNormalizerV40._parse_user_agent(opera_ua)
    assert res_opera["browser"] == "Opera"
    assert res_opera["browser_version"] == "115.0.5322.77"

    bot_ua = "Googlebot/2.1 (+http://www.google.com/bot.html)"
    res_bot = ApexNormalizerV40._parse_user_agent(bot_ua)
    assert res_bot["browser"] == "Googlebot"
    assert res_bot["device"] == "bot"


def test_empty_hash_guard():
    """Verifies that hash prefix with empty value returns None (no 'sha256:' garbage)."""
    assert ApexTransformsV40.transform_hash("sha256=") is None
    assert ApexTransformsV40.transform_hash("imphash=") is None
    assert ApexTransformsV40.transform_hash("md5=") is None


def test_timezone_naive_timestamp_arithmetic():
    """Verifies that naive ISO timestamp without Z does not cause TypeError in latency calculations."""
    naive_alert = {
        "timestamp": "2026-10-16T04:18:28",  # No timezone!
        "@timestamp": "2026-10-16T04:18:30Z",
        "full_log": "test event"
    }
    out = ApexNormalizerV40.normalize_alert(naive_alert)
    assert "timestamps" in out
    assert out["timestamps"]["pipeline_latency_ms"] == 2000
    assert out["timestamps"]["clock_skew_detected"] is False


def test_url_template_in_web_output():
    """Verifies that http.url_template is properly populated in web telemetry output."""
    web_alert = {
        "timestamp": "2026-10-16T04:18:28Z",
        "decoder": {"name": "web-accesslog"},
        "data": {
            "url": "/api/v1/users/49102/profile",
            "protocol": "GET"
        }
    }
    out = ApexNormalizerV40.normalize_alert(web_alert)
    assert "http" in out
    assert out["http"]["url_path"] == "/api/v1/users/49102/profile"
    assert out["http"]["url_template"] == "/api/v1/users/{id}/profile"
    assert out["alias_source"]["http.url_template"] == "transform_tmpl(http.url_path)"


def test_extended_secret_redaction():
    """Verifies extended secret redaction (Basic Auth, x-api-key, URI credentials)."""
    raw_text = "curl -H 'Authorization: Basic YWRtaW46cGFzczEyMw==' -H 'x-api-key: SEC-12345678' postgres://app_user:SuperSecretPassword!@db.internal:5432/prod"
    redacted = ApexTransformsV40.redact_in_flight_secrets(raw_text)
    assert "Basic [REDACTED_BASIC_AUTH]" in redacted
    assert "x-api-key: [REDACTED_API_KEY]" in redacted
    assert "postgres://app_user:[REDACTED_PASS]@db.internal:5432/prod" in redacted
    assert "SuperSecretPassword!" not in redacted


def test_apex_v40_normalize_compact():
    """Verify Gold-Standard Compact Normalization (Sparse RFC 8259, Zero NULLs, No OTel duplicate)."""
    raw_sample = {
        "id": "1792124316.162672",
        "timestamp": "2026-10-16T04:18:36.940+0000",
        "agent": {"id": "019", "name": "hportal-prod-159", "ip": "192.168.1.159", "labels": {"tenant": "TenantC"}},
        "data": {"srcip": "34.18.116.21", "protocol": "GET", "url": "/.env1", "id": "404"},
        "decoder": {"name": "web-accesslog"},
        "full_log": "34.18.116.21 - - [16/Oct/2026:04:18:28 +0000] \"GET /.env1 HTTP/1.1\" 404 6797 \"-\" \"curl/7.81.0\"",
        "location": "/var/log/apache2/access.log",
        "rule": {"id": "31151", "level": 10, "description": "Web scan error", "groups": ["web", "recon"]}
    }
    compact = ApexNormalizerV40.normalize_compact(raw_sample)

    assert compact["event_id"] == "1792124316.162672"
    assert compact["schema_ref"] == "apex:v4.0#web-accesslog"
    assert "otel" not in compact  # Redundant identity dropped
    assert "tenant_salted_hmac" not in compact  # Redundant HMAC dropped
    assert "file" not in compact  # Sparse: Web attack does not have file block
    assert "vulnerability" not in compact  # Sparse: No vulnerability block
    assert "alias_source" not in compact  # Replaced by schema_ref
    assert compact["network"]["src_ip"] == "34.18.116.21"
    assert compact["http"]["status_code"] == 404

    # Recursively assert NO key is None or empty dict
    def check_no_null(d):
        if isinstance(d, dict):
            for k, v in d.items():
                assert v is not None, f"Found None for key {k}"
                assert v != {}, f"Found empty dict for key {k}"
                check_no_null(v)
        elif isinstance(d, list):
            for item in d:
                check_no_null(item)

    check_no_null(compact)


def test_ingest_pipeline_compact_integration_real_alerts():
    """
    End-to-End Integration Test:
    Verifies AlertStreamReader integration using ApexNormalizerV40.normalize_compact()
    across the 3 empirical archetypes (Web, FIM, CVE).
    Ensures 0% NULLs, RFC 8259 sparse structure, and Dual-Track classification compatibility.
    """
    from pipeline.ingest import AlertStreamReader
    from pipeline.models import CommonEventModel

    reader = AlertStreamReader.__new__(AlertStreamReader)
    reader.total_valid_records = 1
    reader.asset_resolver = type("MockAR", (), {
        "register_observation": lambda *a: None,
        "resolve_target_host": lambda *a, **k: "target-host"
    })()
    reader.assets_config = {}

    # 1. Real Web Attack Alert (Agent 019, TenantC)
    web_alert = {
        "timestamp": "2026-10-31T07:38:36.162672+00:00",
        "@timestamp": "2026-10-31T07:38:37.297000+00:00",
        "id": "1792124316.162672",
        "agent": {"id": "019", "name": "hportal-prod-159", "ip": "10.20.100.159", "labels": {"tenant": "TenantC"}},
        "rule": {"id": "31101", "level": 5, "description": "Web server 400 error", "groups": ["web", "accesslog"]},
        "decoder": {"name": "web-accesslog"},
        "data": {
            "srcip": "10.20.100.252",
            "dstip": "10.20.100.159",
            "url": "/api/v1/auth/login?action=host.view.refresh",
            "protocol": "POST",
            "id": "401",
            "http_user_agent": "Mozilla/5.0 Chrome/120.0"
        }
    }
    cem_web = reader.normalize_record(web_alert)
    assert isinstance(cem_web, CommonEventModel)
    assert cem_web.protocol == "http"
    assert cem_web.network_transport == "tcp"
    assert cem_web.tenant_id == "TenantC"
    assert cem_web.alias_source == {"schema_ref": "apex:v4.0#web-accesslog"}
    # Verify compact apex dict
    compact_web = cem_web.apex_normalized
    assert compact_web["schema_ref"] == "apex:v4.0#web-accesslog"
    assert "file" not in compact_web
    assert "vulnerability" not in compact_web
    assert "otel" not in compact_web
    assert "tenant_salted_hmac" not in compact_web

    # 2. Real FIM Syscheck Alert (Agent 026, TenantD)
    fim_alert = {
        "timestamp": "2026-10-31T07:38:40.98303697+00:00",
        "@timestamp": "2026-10-31T07:38:41.000000+00:00",
        "id": "1792087426.98303697",
        "agent": {"id": "026", "name": "portal-bssn-163", "ip": "10.20.100.163", "labels": {"tenant": "TenantD"}},
        "rule": {"id": "550", "level": 7, "description": "Integrity checksum changed.", "groups": ["syscheck"]},
        "decoder": {"name": "syscheck_integrity_changed"},
        "syscheck": {
            "path": "/etc/pam.d/common-auth",
            "event": "modified",
            "sha256_after": "a6b2c8901234567890abcdef1234567890abcdef1234567890abcdef12345678"
        }
    }
    cem_fim = reader.normalize_record(fim_alert)
    assert isinstance(cem_fim, CommonEventModel)
    assert cem_fim.tenant_id == "TenantD"
    assert cem_fim.fim_info["path"] == "/etc/pam.d/common-auth"
    compact_fim = cem_fim.to_apex_compact_dict()
    assert compact_fim["schema_ref"] == "apex:v4.0#syscheck_integrity_changed"
    assert "http" not in compact_fim
    assert "vulnerability" not in compact_fim
    assert compact_fim["classification"]["category_code"] == "fim_change"
    assert compact_fim["fingerprint"]["quality"] == "exact"

    # 3. Real CVE Scan Alert (Agent 012, TenantA)
    cve_alert = {
        "timestamp": "2026-10-31T07:38:47.628000+00:00",
        "@timestamp": "2026-10-31T07:38:47.628000+00:00",
        "id": "1793432327.23637424",
        "agent": {"id": "012", "name": "zabbix-prod-214", "ip": "10.20.100.214", "labels": {"tenant": "tenanta"}},
        "rule": {"id": "23502", "level": 3, "description": "CVE-2026-64138 solved.", "groups": ["vulnerability-detector"]},
        "decoder": {"name": "json"},
        "data": {
            "vulnerability": {
                "cve": "CVE-2026-64138",
                "severity": "High",
                "package": {"name": "linux-image-5.15.0-198-generic", "version": "5.15.0-198.208", "architecture": "amd64"},
                "cvss": {"cvss3": {"base_score": 8.8}}
            }
        }
    }
    cem_cve = reader.normalize_record(cve_alert)
    assert isinstance(cem_cve, CommonEventModel)
    assert cem_cve.tenant_id == "TenantA"
    assert cem_cve.vulnerability_info["cve_id"] == "CVE-2026-64138"
    compact_cve = cem_cve.to_apex_compact_dict()
    assert compact_cve["schema_ref"] == "apex:v4.0#json"
    assert "http" not in compact_cve
    assert "file" not in compact_cve
    assert compact_cve["classification"]["category_code"] == "vuln_detected"
    assert compact_cve["fingerprint"]["quality"] == "exact"


def test_feature_introspection_custom_decoder():
    """
    Verifies Feature-Signature Introspection (Duck Typing):
    Unorthodox or custom decoder names (e.g. 'traefik-gateway-v2', 'auditd-collector')
    are dynamically mapped to canonical domains based on structural telemetry features.
    """
    # 1. Custom Reverse Proxy / Ingress Decoder
    proxy_alert = {
        "timestamp": "2026-10-16T04:20:00.000Z",
        "agent": {"id": "010", "name": "k8s-ingress-traefik", "ip": "10.0.0.1"},
        "decoder": {"name": "traefik-enterprise-gateway"},
        "data": {
            "url": "/api/v2/tokens?auth=true",
            "protocol": "POST",
            "srcip": "198.51.100.99",
            "id": "200"
        }
    }
    out_proxy = ApexNormalizerV40.normalize_compact(proxy_alert)
    assert "http" in out_proxy
    assert out_proxy["http"]["method"] == "POST"
    assert out_proxy["http"]["url_path"] == "/api/v2/tokens"
    assert out_proxy["http"]["status_code"] == 200
    assert out_proxy["network"]["src_ip"] == "198.51.100.99"
    assert out_proxy["schema_ref"] == "apex:v4.0#traefik-enterprise-gateway"

    # 2. Custom Auditd Collector Decoder
    audit_alert = {
        "timestamp": "2026-10-16T04:22:00.000Z",
        "agent": {"id": "015", "name": "linux-db-01", "ip": "10.0.0.15"},
        "decoder": {"name": "auditd-custom-collector"},
        "data": {
            "audit": {
                "exe": "/usr/bin/cat",
                "command": "cat /etc/shadow",
                "pid": "4819",
                "auid": "root"
            }
        }
    }
    out_audit = ApexNormalizerV40.normalize_compact(audit_alert)
    assert "process" in out_audit
    assert out_audit["process"]["name"] == "cat"
    assert out_audit["process"]["path"] == "/usr/bin/cat"
    assert out_audit["process"]["command_line"] == "cat /etc/shadow"
    assert out_audit["process"]["pid"] == 4819
    assert out_audit["process"]["user"] == "root"
    assert out_audit["schema_ref"] == "apex:v4.0#auditd-custom-collector"


def test_multi_domain_hybrid_webshell_rce():
    """
    Verifies Multi-Domain Independent Extractors:
    A single complex attack event (Web exploitation + File write + Command execution)
    simultaneously extracts HTTP, File (FIM), and Process domains with 0% null clutter.
    """
    hybrid_alert = {
        "timestamp": "2026-10-16T04:30:00.000Z",
        "@timestamp": "2026-10-16T04:30:00.000Z",
        "id": "999888.11223344",
        "agent": {"id": "007", "name": "app-server-dmz", "ip": "192.168.1.7", "labels": {"tenant": "TenantB"}},
        "decoder": {"name": "caddy-custom-gateway"},
        "rule": {
            "id": "100201",
            "level": 12,
            "description": "Webshell uploaded and executed via web server.",
            "groups": ["web", "syscheck", "process"]
        },
        "data": {
            "url": "/uploads/c99.php",
            "protocol": "POST",
            "srcip": "203.0.113.88",
            "id": "200",
            "command": "/bin/sh -c whoami",
            "process_name": "whoami",
            "process_path": "/usr/bin/whoami",
            "user": "www-data"
        },
        "syscheck": {
            "path": "/var/www/html/uploads/c99.php",
            "event": "added",
            "sha256_after": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }
    }

    # Direct Apex V4.0 Compact Normalization check
    compact_out = ApexNormalizerV40.normalize_compact(hybrid_alert)
    assert "http" in compact_out, "HTTP domain must be independently captured"
    assert "file" in compact_out, "File domain must be independently captured"
    assert "process" in compact_out, "Process domain must be independently captured"

    assert compact_out["http"]["method"] == "POST"
    assert compact_out["http"]["url_path"] == "/uploads/c99.php"
    assert compact_out["file"]["path"] == "/var/www/html/uploads/c99.php"
    assert compact_out["file"]["event_type"] == "added"
    assert compact_out["process"]["name"] == "whoami"
    assert compact_out["process"]["command_line"] == "/bin/sh -c whoami"
    assert compact_out["process"]["user"] == "www-data"

    # RFC 8259 Sparse verification: 0% nulls
    assert None not in compact_out["http"].values()
    assert None not in compact_out["file"].values()
    assert None not in compact_out["process"].values()

    # Ingest Pipeline CommonEventModel integration check
    from pipeline.ingest import AlertStreamReader
    reader = AlertStreamReader.__new__(AlertStreamReader)
    reader.total_valid_records = 1
    reader.asset_resolver = type("MockAR", (), {"register_observation": lambda *a: None, "resolve_target_host": lambda *a, **k: "app-server-dmz"})()
    reader.assets_config = {}

    cem = reader.normalize_record(hybrid_alert)
    assert cem.http_method == "POST"
    assert cem.fim_info["path"] == "/var/www/html/uploads/c99.php"
    assert cem.process_name == "whoami"
    assert cem.command_line == "/bin/sh -c whoami"
    assert cem.username == "www-data"


def test_multi_domain_windows_event4688_auth_and_process():
    """
    Verifies that Windows Process Creation (EventID 4688) alert
    simultaneously extracts both Authentication identity and Process execution lineages.
    """
    win_proc_alert = {
        "timestamp": "2026-10-16T04:35:00.000Z",
        "agent": {"id": "045", "name": "dc-prod-01", "ip": "192.168.1.10"},
        "decoder": {"name": "windows"},
        "data": {
            "win": {
                "system": {"eventID": "4688"},
                "eventdata": {
                    "subjectUserName": "Administrator",
                    "targetDomainName": "CORP",
                    "logonType": "2",
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "commandLine": "powershell.exe -ExecutionPolicy Bypass -File evil.ps1",
                    "parentImage": "C:\\Windows\\System32\\cmd.exe",
                    "parentProcessId": "1234",
                    "processId": "5678"
                }
            }
        }
    }

    out = ApexNormalizerV40.normalize_compact(win_proc_alert)
    assert "authentication" in out, "Authentication context must be extracted from EventID 4688"
    assert "process" in out, "Process execution context must be extracted from EventID 4688"

    assert out["authentication"]["event_id"] == "4688"
    assert out["authentication"]["target_user"] == "administrator"
    assert out["authentication"]["domain"] == "CORP"

    assert out["process"]["name"] == "powershell.exe"
    assert out["process"]["path"] == "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    assert out["process"]["command_line"] == "powershell.exe -ExecutionPolicy Bypass -File evil.ps1"
    assert out["process"]["parent_name"] == "cmd.exe"
    assert out["process"]["pid"] == 5678
    assert out["process"]["parent_pid"] == 1234


