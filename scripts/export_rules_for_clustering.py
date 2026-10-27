import io
import csv
import json
import os
import sys

sys.path.insert(0, os.getcwd())
sys.stdout.reconfigure(encoding='utf-8')

from pipeline.ingest import classify_event_archetype, classify_event_taxonomy
from pipeline.deduplicate import CLUSTER_CONFIG

def parse_line_clean(line):
    line = line.strip()
    if not line:
        return None
    while line.endswith(';'):
        line = line[:-1]
    if line.startswith('"') and line.endswith('"'):
        line = line[1:-1].replace('""', '"')
    try:
        reader = csv.reader(io.StringIO(line))
        return next(reader)
    except:
        return None

def clean_json_list(val):
    if not val or val.strip() in ('[]', ''):
        return []
    val = val.strip()
    try:
        return json.loads(val)
    except:
        if val.startswith('[') and val.endswith(']'):
            items = val[1:-1].split(',')
            return [it.strip().strip('"').strip("'") for it in items if it.strip()]
        return [val]

os.makedirs('data/processed', exist_ok=True)
json_out_path = 'data/processed/wazuh_rules_level3_plus_for_clustering.json'
csv_out_path = 'data/processed/wazuh_rules_level3_plus_for_clustering.csv'

# Centralized Cluster v1 Parameters
WINDOW_SIZE = CLUSTER_CONFIG.get("window_size_seconds", 900)
GRACE_PERIOD = CLUSTER_CONFIG.get("grace_period_seconds", 120)
LATE_CUTOFF = CLUSTER_CONFIG.get("late_arriving_cutoff_hours", 24)

processed_rules = []
csv_rows = []

with open('rules.csv', 'r', encoding='utf-8', errors='ignore') as f:
    header = f.readline().strip().rstrip(';').split(',')
    for line in f:
        row = parse_line_clean(line)
        if not row or len(row) < 15:
            if 'ruleset/rules' in line:
                parts = line.strip().rstrip(';').split(',')
                for i, p in enumerate(parts):
                    if p.endswith('ruleset/rules'):
                        try:
                            rule_file = parts[i-1].lstrip('"')
                            rel_dir = parts[i]
                            r_id = parts[i+1]
                            r_lvl = int(parts[i+2])
                            status = parts[i+3]
                            if r_lvl >= 3:
                                row = [rule_file, rel_dir, r_id, r_lvl, status, "{}", "[]", "[]", "[]", "[]", "[]", "[]", "[]", "[]", "Ruleset rule"]
                        except:
                            pass
        if not row or len(row) < 15:
            continue
            
        try:
            level = int(row[3])
            rule_id = str(row[2])
        except ValueError:
            continue
            
        if level < 3:
            continue
            
        file_name = row[0]
        rel_dir = row[1]
        status = row[4]
        details_raw = row[5]
        pci_dss = clean_json_list(row[6])
        gpg13 = clean_json_list(row[7])
        gdpr = clean_json_list(row[8])
        hipaa = clean_json_list(row[9])
        nist_800_53 = clean_json_list(row[10])
        tsc = clean_json_list(row[11])
        mitre = clean_json_list(row[12])
        groups = clean_json_list(row[13])
        desc = row[14].rstrip(';')
        
        try:
            details = json.loads(details_raw) if details_raw.startswith('{') else {}
        except:
            details = {}

        # 1. Archetype classification (Sweet-spot category)
        archetype, actor, target, win_class, win_dur = classify_event_archetype(
            groups=groups,
            rule_id=rule_id,
            rule_level=level,
            source_ip=None,
            destination_host=None,
            destination_ip=None,
            username=None,
            process_name=None,
            agent_name="wazuh_agent",
            rule_description=desc,
            mitre_tactics=None
        )
        
        # 2. 3-Layer Category Taxonomy
        domain, target_category, action_ttp, lifecycle_role, disposition, conf_score = classify_event_taxonomy(
            rule_id=rule_id,
            rule_level=level,
            groups=groups,
            rule_description=desc,
            full_log=None,
            data=details,
            source_ip=None,
            http_status=None,
            is_scanner_ua=False,
            mitre_tactics=None
        )

        rule_obj = {
            "rule_id": rule_id,
            "rule_level": level,
            "rule_description": desc,
            "file": file_name,
            "status": status,
            "groups": groups,
            "mitre": mitre,
            "compliance": {
                "pci_dss": pci_dss,
                "gdpr": gdpr,
                "hipaa": hipaa,
                "nist_800_53": nist_800_53,
                "tsc": tsc,
                "gpg13": gpg13
            },
            "clustering_profile": {
                "cluster_architecture_version": "v1",
                "sweet_spot_archetype": archetype,
                "window_type": "UNIFORM_15_MIN",
                "window_size_seconds": WINDOW_SIZE,
                "grace_period_seconds": GRACE_PERIOD,
                "late_arriving_cutoff_hours": LATE_CUTOFF,
                "high_value_bypass_capability": True,
                "clustering_domain": domain,
                "clustering_target_category": target_category,
                "clustering_action_ttp": action_ttp,
                "lifecycle_role": lifecycle_role,
                "disposition": disposition,
                "confidence_score": conf_score
            }
        }
        processed_rules.append(rule_obj)

        csv_rows.append({
            "rule_id": rule_id,
            "rule_level": level,
            "rule_description": desc,
            "file": file_name,
            "status": status,
            "sweet_spot_archetype": archetype,
            "window_type": "UNIFORM_15_MIN",
            "window_size_seconds": WINDOW_SIZE,
            "grace_period_seconds": GRACE_PERIOD,
            "clustering_domain": domain,
            "clustering_target_category": target_category,
            "clustering_action_ttp": action_ttp,
            "lifecycle_role": lifecycle_role,
            "disposition": disposition,
            "confidence_score": conf_score,
            "groups": "|".join(groups),
            "mitre": "|".join(mitre),
            "pci_dss": "|".join(pci_dss),
            "gdpr": "|".join(gdpr),
            "hipaa": "|".join(hipaa),
            "nist_800_53": "|".join(nist_800_53)
        })

# Write JSON
with open(json_out_path, 'w', encoding='utf-8') as f:
    json.dump(processed_rules, f, indent=2, ensure_ascii=False)

# Write CSV
csv_fields = [
    "rule_id", "rule_level", "rule_description", "file", "status",
    "sweet_spot_archetype", "window_type", "window_size_seconds", "grace_period_seconds",
    "clustering_domain", "clustering_target_category", "clustering_action_ttp",
    "lifecycle_role", "disposition", "confidence_score",
    "groups", "mitre", "pci_dss", "gdpr", "hipaa", "nist_800_53"
]

with open(csv_out_path, 'w', encoding='utf-8', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=csv_fields)
    writer.writeheader()
    writer.writerows(csv_rows)

print(f"Export complete (Cluster v1 Architecture Uniform 15-Minute Window):")
print(f"  JSON: {json_out_path} ({len(processed_rules)} rules)")
print(f"  CSV:  {csv_out_path} ({len(csv_rows)} rows)")
