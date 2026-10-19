"""
Unit Tests for 14 Wazuh Custom XML Rule Files, CDB Lists & OSSEC Config (Phase 2)
"""
import os, glob
import xml.etree.ElementTree as ET
import pytest
from config.settings import RULES_DIR, LISTS_DIR, BASE_DIR


def test_all_14_xml_files_exist_and_parse():
    xml_files = sorted(glob.glob(str(RULES_DIR / "*.xml")))
    assert len(xml_files) == 14, f"Expected 14 XML rule files, found {len(xml_files)}"

    for fpath in xml_files:
        fname = os.path.basename(fpath)
        with open(fpath, "r", encoding="utf-8") as f:
            content = f.read()
        
        # Parse XML root
        root = ET.fromstring(content)
        assert root.tag == "group", f"File {fname} root tag must be <group>"
        rules = root.findall("rule")
        assert len(rules) > 0, f"File {fname} must contain at least one <rule>"


def test_rule_id_uniqueness_and_level_bounds():
    xml_files = sorted(glob.glob(str(RULES_DIR / "*.xml")))
    seen_ids = set()
    rule_count = 0

    for fpath in xml_files:
        fname = os.path.basename(fpath)
        tree = ET.parse(fpath)
        root = tree.getroot()

        for rule in root.findall("rule"):
            rule_count += 1
            rule_id = rule.get("id")
            rule_level = rule.get("level")

            assert rule_id is not None, f"Rule in {fname} missing id attribute"
            assert rule_level is not None, f"Rule {rule_id} in {fname} missing level attribute"

            rule_id_int = int(rule_id)
            rule_level_int = int(rule_level)

            assert 0 <= rule_level_int <= 16, f"Rule {rule_id} level {rule_level_int} out of bounds (0-16)"
            assert rule_id_int not in seen_ids, f"Duplicate Rule ID {rule_id_int} found in {fname}"
            seen_ids.add(rule_id_int)

    assert rule_count >= 30, f"Expected at least 30 active custom rules in manifest, found {rule_count}"


def test_mitre_attack_tag_formatting():
    xml_files = sorted(glob.glob(str(RULES_DIR / "*.xml")))
    mitre_count = 0

    for fpath in xml_files:
        tree = ET.parse(fpath)
        root = tree.getroot()

        for rule in root.findall("rule"):
            mitre = rule.find("mitre")
            if mitre is not None:
                for mitre_id in mitre.findall("id"):
                    val = mitre_id.text.strip()
                    assert val.startswith("T"), f"Invalid MITRE ATT&CK ID {val} (must start with T)"
                    mitre_count += 1

    assert mitre_count > 0, "Expected MITRE ATT&CK IDs across ruleset"


def test_cdb_lists_exist_and_valid():
    expected_lists = [
        "approved-admin-hosts",
        "approved-maintenance-windows",
        "approved-vulnerability-scanners",
        "backup-systems",
        "critical-assets-list",
        "monitoring-systems",
        "service-accounts"
    ]
    for list_name in expected_lists:
        list_path = LISTS_DIR / list_name
        assert list_path.exists(), f"Missing CDB list file: {list_name}"
        with open(list_path, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f.readlines() if l.strip() and not l.startswith("#")]
            assert len(lines) > 0, f"CDB list {list_name} is empty"
            for line in lines:
                assert ":" in line, f"CDB list entry '{line}' must be key:value format"


def test_rule_list_references_exist():
    xml_files = sorted(glob.glob(str(RULES_DIR / "*.xml")))
    for fpath in xml_files:
        tree = ET.parse(fpath)
        root = tree.getroot()
        for rule in root.findall("rule"):
            for list_elem in rule.findall("list"):
                list_ref = list_elem.text.strip()
                list_name = os.path.basename(list_ref)
                assert (LISTS_DIR / list_name).exists(), f"Rule {rule.get('id')} references non-existent list: {list_ref}"


def test_ossec_snippet_configuration():
    ossec_conf = BASE_DIR / "ruleset" / "ossec_snippet.conf"
    assert ossec_conf.exists(), "Missing ruleset/ossec_snippet.conf"
    with open(ossec_conf, "r", encoding="utf-8") as f:
        content = f.read()
    assert "<ossec_config>" in content
    assert "<include>ruleset/rules/001-base-normalization.xml</include>" in content
    assert "<include>ruleset/rules/095-governance-log.xml</include>" in content
    assert "<list>etc/lists/approved-admin-hosts</list>" in content
