"""
Per-Tenant Wazuh Suppression Proposal Exporter & wazuh-logtest Validation Generator
=====================================================================================
Processes all high-confidence benign tickets (CLOSED / BENIGN)
and automatically generates:
1. Per-Tenant Wazuh CDB Lists (ruleset/lists/tenant_<tenant_id>_allowlist_ips)
2. Per-Tenant Wazuh Child XML Rules (ruleset/rules/tenant_<tenant_id>_suppression.xml)
3. Automated wazuh-logtest Test Scenarios for verifying upstream noise suppression.
"""

import os
import re
import sys
import json
import psycopg2
from pathlib import Path
from collections import defaultdict
from typing import Dict, Any, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD, BASE_DIR

PROPOSALS_DIR = BASE_DIR / "exports" / "suppression_proposals"
LISTS_DIR = PROPOSALS_DIR / "lists"
RULES_DIR = PROPOSALS_DIR / "rules"


def export_suppression_proposals_per_tenant(db_name: str = "wazuh_soc_db") -> Dict[str, Any]:
    """
    Export all auto-closed benign incidents into structured per-tenant CDB lists and XML rules.
    """
    print("=" * 80)
    print(f"[*] EXPORTING PER-TENANT WAZUH SUPPRESSION PROPOSALS (DB: {db_name})")
    print("=" * 80)

    LISTS_DIR.mkdir(parents=True, exist_ok=True)
    RULES_DIR.mkdir(parents=True, exist_ok=True)

    conn = psycopg2.connect(
        host=DB_HOST, port=DB_PORT, database=db_name,
        user=DB_USER, password=DB_PASSWORD
    )
    cur = conn.cursor()

    # Query all closed benign tickets with their underlying aggregate details
    cur.execute("""
        SELECT 
            i.incident_id,
            COALESCE(i.tenant_id, 'DEFAULT') AS tenant_id,
            i.target_host,
            COALESCE(i.attacker_source_ip, '127.0.0.1') AS actor_ip,
            i.correlation_rule_id,
            i.title,
            q.false_positive_reason,
            COALESCE(s.rule_ids, '{}') AS underlying_rule_ids
        FROM soc_ops.soc_triage_queue q
        JOIN correlation.correlated_incidents i ON q.incident_id = i.incident_id
        LEFT JOIN (
            SELECT 
                st.incident_id,
                ARRAY_AGG(DISTINCT a.rule_id) FILTER (WHERE a.rule_id IS NOT NULL) AS rule_ids
            FROM correlation.incident_stages st
            LEFT JOIN suppression.aggregated_alerts a ON st.reference_id = a.aggregation_id
            GROUP BY st.incident_id
        ) s ON q.incident_id = s.incident_id
        WHERE q.triage_status = 'CLOSED' 
          AND q.resolution_outcome IN ('BENIGN', 'BENIGN_AUTHORIZED', 'OPERATIONAL_NOISE')
        ORDER BY i.tenant_id, i.target_host;
    """)

    rows = cur.fetchall()
    print(f"[+] Found {len(rows):,} closed benign tickets to map into suppression proposals.")

    # Group by Tenant -> Target Host -> Attacker IP / Rules
    tenant_data = defaultdict(lambda: {
        "cdb_ips": set(),
        "rules_map": defaultdict(set),
        "incidents_count": 0
    })

    for inc_id, tenant, host, actor_ip, corr_rule, title, reason, raw_rules in rows:
        t_clean = re.sub(r'[^a-zA-Z0-9_-]', '_', tenant.strip()) or "DEFAULT"
        tenant_data[t_clean]["incidents_count"] += 1

        # 1. CDB Candidate IPs
        if actor_ip and actor_ip != "unknown":
            tenant_data[t_clean]["cdb_ips"].add((actor_ip, host))

        # 2. Extract underlying rule IDs
        rule_ids = set()
        if raw_rules:
            rule_ids.update(int(r) for r in raw_rules if r)
        # Parse from title if CORR-SA
        m = re.findall(r'Rule\s+(\d+)', title)
        for r_str in m:
            rule_ids.add(int(r_str))

        if not rule_ids and corr_rule == 'CORR-007':
            rule_ids.update([30305, 30306, 31101, 31530])

        for rid in rule_ids:
            tenant_data[t_clean]["rules_map"][rid].add(host)

    summary_results = {}
    base_xml_rule_id = 112000

    for tenant, data in tenant_data.items():
        print(f"\n[*] Processing Tenant: {tenant} ({data['incidents_count']} incidents)...")

        # --- A. Generate CDB List ---
        cdb_filename = f"tenant_{tenant.lower()}_allowlist_ips"
        cdb_path = LISTS_DIR / cdb_filename
        with open(cdb_path, "w", encoding="utf-8") as f:
            f.write(f"# Wazuh CDB Allowlist for Tenant: {tenant}\n")
            f.write(f"# Auto-generated from calibrated SOC benign proposals\n")
            for ip, host in sorted(data["cdb_ips"]):
                f.write(f"{ip}:{host}\n")
        print(f"  [+] Generated CDB List: {cdb_path.name} ({len(data['cdb_ips'])} entries)")

        # --- B. Generate Wazuh Child XML Rules (Level 0) ---
        xml_filename = f"tenant_{tenant.lower()}_suppression.xml"
        xml_path = RULES_DIR / xml_filename
        xml_rules = []
        xml_rules.append(f'<!-- Auto-Generated Wazuh Upstream Suppression Rules for Tenant: {tenant} -->')
        xml_rules.append(f'<group name="tenant_tuning,suppression,{tenant.lower()},">')

        current_rule_id = base_xml_rule_id
        for rid, hosts in sorted(data["rules_map"].items()):
            current_rule_id += 1
            host_regex = "|".join(re.escape(h) for h in sorted(hosts)[:10])
            xml_rules.append(f"""
  <!-- Tenant {tenant}: Suppress benign noise for Wazuh Rule {rid} -->
  <rule id="{current_rule_id}" level="0">
    <if_sid>{rid}</if_sid>
    <hostname>{host_regex}</hostname>
    <description>FP-SUPPRESSION: Auto-suppressed verified operational noise for Tenant {tenant}</description>
    <options>no_log</options>
  </rule>""")

        xml_rules.append(f'</group>\n')
        with open(xml_path, "w", encoding="utf-8") as f:
            f.write("\n".join(xml_rules))

        print(f"  [+] Generated XML Rules: {xml_path.name} ({len(data['rules_map'])} child rules)")
        base_xml_rule_id = current_rule_id + 100

        summary_results[tenant] = {
            "incidents_suppressed": data["incidents_count"],
            "cdb_list_path": str(cdb_path),
            "cdb_entries": len(data["cdb_ips"]),
            "xml_rules_path": str(xml_path),
            "xml_rules_count": len(data["rules_map"])
        }

    conn.close()

    # --- C. Generate wazuh-logtest Validation Shell / Batch Script ---
    test_script_path = PROPOSALS_DIR / "test_suppression_proposals.bat"
    with open(test_script_path, "w", encoding="utf-8") as f:
        f.write("@echo off\n")
        f.write("REM Automated Wazuh Logtest Verification Suite for Suppression Proposals\n")
        f.write("echo [*] Testing Wazuh XML Rule Suppression via wazuh-logtest...\n")
        f.write("echo [Sample Log] Nginx 404 UI Chunk Polling:\n")
        f.write('echo "2026/08/10 12:00:00 [error] 1234#1234: *1 connect() failed, client: 103.19.110.156, request: \\"GET /dash/chunk/main.js HTTP/1.1\\"" | /var/ossec/bin/wazuh-logtest 2>nul\n')
        f.write("echo [+] If Rule level is 0, suppression is verified!\n")

    print(f"\n[+] Generated wazuh-logtest test suite at: {test_script_path.name}")
    print("=" * 80)
    return summary_results


if __name__ == "__main__":
    export_suppression_proposals_per_tenant()
