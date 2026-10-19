"""
Unit Tests for GenericIOCExtractorPlugin — Regex-based IOC Extraction Fallback
Tests IPv4, MD5/SHA256/SHA1, domain, CVE, and URL extraction from raw alert payloads.
"""
import pytest
from pipeline.normalization_plugins import GenericIOCExtractorPlugin


class MockCEM:
    """Minimal mock of CommonEventModel for plugin testing."""
    def __init__(self, raw_payload=None, rule_description=None, ioa_summary=None, extracted_iocs=None):
        self.raw_payload = raw_payload
        self.rule_description = rule_description
        self.ioa_summary = ioa_summary
        self.extracted_iocs = extracted_iocs
        self.event_id = "test-001"


class MockRaw:
    """Minimal mock of WazuhRawAlert."""
    def __init__(self, full_log=None):
        self.full_log = full_log


class TestGenericIOCExtractor:

    def test_extracts_external_ipv4(self):
        """External IPv4 addresses should be extracted from raw payload."""
        plugin = GenericIOCExtractorPlugin()
        cem = MockCEM(raw_payload="Connection from 203.0.113.45 to port 443")
        result = plugin.enrich(cem, MockRaw())
        assert result.extracted_iocs is not None
        assert "203.0.113.45" in result.extracted_iocs["ipv4"]

    def test_excludes_internal_ipv4(self):
        """Internal/private IPv4 addresses should not appear in extracted IOCs."""
        plugin = GenericIOCExtractorPlugin()
        cem = MockCEM(raw_payload="Traffic from 192.168.1.100 to 10.0.0.1")
        result = plugin.enrich(cem, MockRaw())
        ipv4s = (result.extracted_iocs or {}).get("ipv4", [])
        assert "192.168.1.100" not in ipv4s
        assert "10.0.0.1" not in ipv4s

    def test_extracts_md5_hash(self):
        """MD5 hashes (32 hex chars) should be extracted."""
        plugin = GenericIOCExtractorPlugin()
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        cem = MockCEM(raw_payload=f"File hash: {md5}")
        result = plugin.enrich(cem, MockRaw())
        assert result.extracted_iocs is not None
        assert md5 in result.extracted_iocs.get("md5", [])

    def test_extracts_sha256_hash(self):
        """SHA256 hashes (64 hex chars) should be extracted."""
        plugin = GenericIOCExtractorPlugin()
        sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        cem = MockCEM(raw_payload=f"SHA256: {sha}")
        result = plugin.enrich(cem, MockRaw())
        assert result.extracted_iocs is not None
        assert sha in result.extracted_iocs.get("sha256", [])

    def test_extracts_cve_ids(self):
        """CVE identifiers should be extracted and set ioa_summary."""
        plugin = GenericIOCExtractorPlugin()
        cem = MockCEM(raw_payload="CVE-2026-23307 affects linux-image-5.15.0-186-generic")
        result = plugin.enrich(cem, MockRaw())
        assert result.extracted_iocs is not None
        assert "CVE-2026-23307" in result.extracted_iocs.get("cves", [])
        assert "CVE-2026-23307" in result.ioa_summary

    def test_extracts_domains(self):
        """Domain names should be extracted from payloads."""
        plugin = GenericIOCExtractorPlugin()
        cem = MockCEM(raw_payload="DNS query to malware-c2.evil.com detected")
        result = plugin.enrich(cem, MockRaw())
        assert result.extracted_iocs is not None
        domains = result.extracted_iocs.get("domains", [])
        assert any("evil.com" in d for d in domains)

    def test_extracts_urls(self):
        """HTTP/HTTPS URLs should be extracted."""
        plugin = GenericIOCExtractorPlugin()
        cem = MockCEM(raw_payload="Request to https://attacker.example.com/payload.exe blocked")
        result = plugin.enrich(cem, MockRaw())
        assert result.extracted_iocs is not None
        urls = result.extracted_iocs.get("urls", [])
        assert any("attacker.example.com" in u for u in urls)

    def test_skips_when_extracted_iocs_already_set(self):
        """Plugin should not overwrite pre-existing extracted_iocs."""
        plugin = GenericIOCExtractorPlugin()
        existing = {"ipv4": ["1.2.3.4"]}
        cem = MockCEM(raw_payload="203.0.113.45", extracted_iocs=existing)
        result = plugin.enrich(cem, MockRaw())
        assert result.extracted_iocs == existing

    def test_uses_full_log_from_raw(self):
        """Should extract IOCs from WazuhRawAlert.full_log."""
        plugin = GenericIOCExtractorPlugin()
        cem = MockCEM()
        raw = MockRaw(full_log="Attack from 198.51.100.1 using CVE-2024-1234")
        result = plugin.enrich(cem, raw)
        assert result.extracted_iocs is not None
        assert "198.51.100.1" in result.extracted_iocs.get("ipv4", [])
        assert "CVE-2024-1234" in result.extracted_iocs.get("cves", [])

    def test_empty_payload_produces_no_iocs(self):
        """Empty payloads should not produce any IOCs."""
        plugin = GenericIOCExtractorPlugin()
        cem = MockCEM()
        result = plugin.enrich(cem, MockRaw())
        assert result.extracted_iocs is None

    def test_multiple_cves_extracted(self):
        """Multiple CVE IDs in a single payload should all be captured."""
        plugin = GenericIOCExtractorPlugin()
        cem = MockCEM(raw_payload="Affected by CVE-2026-11111 and CVE-2026-22222")
        result = plugin.enrich(cem, MockRaw())
        cves = result.extracted_iocs.get("cves", [])
        assert "CVE-2026-11111" in cves
        assert "CVE-2026-22222" in cves
