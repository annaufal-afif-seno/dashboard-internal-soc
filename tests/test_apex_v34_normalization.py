"""
Unit Tests for Apex Normalization Version 3.4 (The Definitive Apex Standard)
Verifies: Pure Normalization, RFC 3986 URL parsing, L4/L7 separation,
Triangulation of 3 timestamps, SLA Latency arithmetic, FIM Syscheck extraction,
CVE Vulnerability resolution, and NIST SP 800-86 1-to-1 alias_source contract.
"""
import pytest
from pipeline.apex_normalizer import ApexNormalizerV34, ApexTransformsV34
from pipeline.ingest import AlertStreamReader
from pipeline.models import CommonEventModel


@pytest.fixture
def web_bot_alert():
    return {
        "timestamp": "2026-08-13T05:39:46.270+0000",
        "@timestamp": "2026-08-13T05:39:47.405Z",
        "id": "1786599586.663007",
        "source": "wazuh-alert",
        "location": "/var/log/apache2/access.log",
        "manager": {"name": "multitenant-soc-131"},
        "agent": {
            "id": "012",
            "name": "zabbix-prod-214",
            "ip": "10.20.100.214",
            "type": "filebeat",
            "version": "8.17.5",
            "ephemeral_id": "208ca614-598d-4774-9543-866c5309a848",
            "labels": {"tenant": "tenanta"}
        },
        "rule": {
            "id": "31533",
            "level": 10,
            "description": "High amount of POST requests in a small period of time (likely bot).",
            "groups": ["web", "appsec", "attack"],
            "frequency": 8,
            "firedtimes": 7,
            "mitre": {
                "id": ["T1498"],
                "tactic": ["Impact"],
                "technique": ["Network Denial of Service"]
            },
            "pci_dss": ["6.5", "11.4"],
            "nist_800_53": ["SA.11", "SI.4"]
        },
        "decoder": {"name": "web-accesslog"},
        "data": {
            "id": "200",
            "srcip": "10.20.100.252",
            "protocol": "POST",
            "url": "/zabbix/zabbix.php?action=host.view.refresh"
        },
        "full_log": '10.20.100.252 - - [13/Aug/2026:05:39:45 +0000] "POST /zabbix/zabbix.php?action=host.view.refresh HTTP/1.1" 200 5292 "http://10.20.100.214/zabbix/zabbix.php?ref=1" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"'
    }


@pytest.fixture
def fim_syscheck_alert():
    return {
        "syscheck": {
            "event": "modified",
            "path": "/usr/bin/systemd-hwdb",
            "mode": "scheduled",
            "size_after": "121504",
            "uname_after": "root",
            "gname_after": "root",
            "perm_after": "rwxr-xr-x",
            "md5_after": "ed5ae272650e9b0ecbde01141ae1b908",
            "sha256_after": "7aee84532d872d2946764a501787af22b74020aa32137c812b6943e9e280ba65"
        },
        "location": "syscheck",
        "manager": {"name": "multitenant-soc-131"},
        "rule": {
            "id": "550",
            "level": 7,
            "description": "Integrity checksum changed.",
            "groups": ["ossec", "syscheck", "syscheck_entry_modified"]
        },
        "timestamp": "2026-08-12T15:01:52.573+0000",
        "@timestamp": "2026-08-12T15:01:55.933Z",
        "id": "1786546912.2196333",
        "agent": {
            "id": "012",
            "name": "zabbix-prod-214",
            "ip": "10.20.100.214",
            "labels": {"tenant": "tenanta"}
        },
        "decoder": {"name": "syscheck_integrity_changed"},
        "full_log": "File '/usr/bin/systemd-hwdb' modified"
    }


@pytest.fixture
def cve_vulnerability_alert():
    return {
        "location": "vulnerability-detector",
        "manager": {"name": "multitenant-soc-131"},
        "rule": {
            "id": "23504",
            "level": 7,
            "description": "CVE-2025-54292 affects lxd",
            "groups": ["vulnerability-detector"]
        },
        "timestamp": "2026-08-12T04:11:46.542+0000",
        "@timestamp": "2026-08-12T04:11:56.258Z",
        "id": "1786507906.482987",
        "agent": {
            "id": "005",
            "name": "hp-fluentd-tenant-172",
            "ip": "192.168.1.172",
            "labels": {"tenant": "tenanta"}
        },
        "decoder": {"name": "json"},
        "data": {
            "vulnerability": {
                "cve": "CVE-2025-54292",
                "severity": "Medium",
                "package": {
                    "name": "lxd",
                    "version": "5.0.8-46bcfa0"
                },
                "cvss": {
                    "cvss3": {
                        "base_score": "4.6"
                    }
                }
            }
        }
    }


def test_apex_normalizer_direct_web(web_bot_alert):
    """Test direct ApexNormalizerV34 output on Web Access Log alert."""
    out = ApexNormalizerV34.normalize_alert(web_bot_alert)
    assert out["schema_version"] == "1.0.0"
    assert len(out["raw_sha256"]) == 64
    assert out["timestamps"]["pipeline_latency_ms"] == 1135
    assert out["timestamps"]["detection_delay_sec"] == 1.27
    assert out["network"]["transport"] is None, "Must be None when proto is absent from raw log (Strictly Explicit)"
    assert out["network"]["protocol"] is None, "Must be None when protocol in raw log is POST (HTTP method, not protocol)"
    assert out["network"]["direction"] is None, "Must be None when direction is absent from raw log (Strictly Explicit)"
    assert out["network"]["bytes_out"] == 5292
    assert out["http"]["method"] == "POST"
    assert out["http"]["url_path"] == "/zabbix/zabbix.php"
    assert out["http"]["query_string"] == "action=host.view.refresh"
    assert out["http"]["parsed_query"] == {"action": "host.view.refresh"}
    assert out["http"]["referrer"]["is_same_origin"] is True
    assert out["http"]["user_agent"]["browser"] == "Chrome"
    assert out["alias_source"]["schema_version"] == "static:1.0.0"
    assert out["alias_source"]["http.method"] == "data.protocol"


def test_apex_normalizer_direct_fim(fim_syscheck_alert):
    """Test direct ApexNormalizerV34 output on FIM alert."""
    out = ApexNormalizerV34.normalize_alert(fim_syscheck_alert)
    assert out["schema_version"] == "1.0.0"
    assert "file" in out
    assert out["file"]["path"] == "/usr/bin/systemd-hwdb"
    assert out["file"]["event_type"] == "modified"
    assert out["file"]["sha256_after"] == "sha256:7aee84532d872d2946764a501787af22b74020aa32137c812b6943e9e280ba65"
    assert out["file"]["md5_after"] == "md5:ed5ae272650e9b0ecbde01141ae1b908"
    assert out["file"]["size_after"] == 121504


def test_apex_normalizer_direct_cve(cve_vulnerability_alert):
    """Test direct ApexNormalizerV34 output on CVE alert."""
    out = ApexNormalizerV34.normalize_alert(cve_vulnerability_alert)
    assert out["schema_version"] == "1.0.0"
    assert "vulnerability" in out
    assert out["vulnerability"]["cve_id"] == "CVE-2025-54292"
    assert out["vulnerability"]["package_name"] == "lxd"
    assert out["vulnerability"]["installed_version"] == "5.0.8-46bcfa0"
    assert out["vulnerability"]["cvss_score"] == 4.6


def test_ingest_pipeline_integration_web(web_bot_alert):
    """Test AlertStreamReader integration on Web Access Log alert."""
    reader = AlertStreamReader.__new__(AlertStreamReader)
    reader.total_valid_records = 1
    reader.asset_resolver = type("MockAR", (), {"register_observation": lambda *a: None, "resolve_target_host": lambda *a, **k: "zabbix-prod-214"})()
    reader.assets_config = {}

    cem = reader.normalize_record(web_bot_alert)
    assert isinstance(cem, CommonEventModel)
    assert cem.schema_version == "1.0.0"
    assert cem.protocol == "http"
    assert cem.network_transport is None, "Must be None when proto is absent from raw log (Strictly Explicit)"
    assert cem.http_method == "POST"
    assert cem.pipeline_latency_ms == 1135
    assert cem.detection_delay_sec == 1.27
    assert cem.query_string == "action=host.view.refresh"
    assert cem.parsed_query == {"action": "host.view.refresh"}
    assert cem.bytes_out == 5292

    # Verify to_apex_v34_dict() contract
    apex_dict = cem.to_apex_v34_dict()
    assert apex_dict["schema_version"] == "1.0.0"
    assert apex_dict["timestamps"]["pipeline_latency_ms"] == 1135


def test_ingest_pipeline_integration_cve(cve_vulnerability_alert):
    """Test AlertStreamReader integration on CVE alert (package extraction)."""
    reader = AlertStreamReader.__new__(AlertStreamReader)
    reader.total_valid_records = 1
    reader.asset_resolver = type("MockAR", (), {"register_observation": lambda *a: None, "resolve_target_host": lambda *a, **k: "hp-fluentd-tenant-172"})()
    reader.assets_config = {}

    cem = reader.normalize_record(cve_vulnerability_alert)
    assert cem.package_name == "lxd"
    assert cem.vulnerability_info is not None
    assert cem.vulnerability_info["cve_id"] == "CVE-2025-54292"


def test_apex_transforms_volatile_values():
    """Verify all 12 volatile transforms in ApexTransformsV34."""
    # 1. IP
    assert ApexTransformsV34.transform_ip("::ffff:10.0.0.5") == "10.0.0.5"
    assert ApexTransformsV34.transform_ip("10.20.100.252:8080") == "10.20.100.252"
    assert ApexTransformsV34.transform_ip("-") is None

    # 2. Hash
    assert ApexTransformsV34.transform_hash("SHA256=48F886F3") == "sha256:48f886f3"
    assert ApexTransformsV34.transform_hash("MD5=C1542F69") == "md5:c1542f69"
    assert ApexTransformsV34.transform_hash("e410ad11acaa875812c5cd9121624407f4a36aef4dbdd4c8e386508dd7765833") == "sha256:e410ad11acaa875812c5cd9121624407f4a36aef4dbdd4c8e386508dd7765833"

    # 3. Host
    assert ApexTransformsV34.transform_host("Zabbix-Prod-214.Corp.") == "zabbix-prod-214.corp"
    assert ApexTransformsV34.transform_host("http://WebServer-01:8080") == "webserver-01"

    # 4. URL Path
    assert ApexTransformsV34.transform_url_path("/zabbix/zabbix.php?action=view#frag") == "/zabbix/zabbix.php"
    assert ApexTransformsV34.transform_url_path("/api//v1//users/") == "/api/v1/users"

    # 5. URL Template
    assert ApexTransformsV34.transform_tmpl("/orders/8841/items") == "/orders/{id}/items"

    # 6. Query Dict
    q_dict = ApexTransformsV34.transform_query_dict("b=2&a=1&_t=1691905186")
    assert q_dict == {"a": "1", "b": "2", "_t": "{volatile}"}

    # 7. Command line
    cmd_clean = ApexTransformsV34.transform_cmd("powershell.exe  -enc  AAB=  -pid 4412")
    assert cmd_clean == "powershell.exe -enc aab= -pid {n}"

    # 8. User (Identity-aware)
    assert ApexTransformsV34.transform_user("CORP\\Administrator", os_type="windows") == "corp\\administrator"
    assert ApexTransformsV34.transform_user("OracleAdmin", os_type="linux") == "OracleAdmin"

    # 9. Bytes
    assert ApexTransformsV34.transform_bytes("5292") == 5292
    assert ApexTransformsV34.transform_bytes("-") is None
