"""
Export SOC Ground Truth Dataset to Unsloth / Alpaca / ShareGPT Training Format
=============================================================================
Prepares instruction-tuning dataset from PostgreSQL soc_ops.ground_truth_dataset
for fine-tuning Qwen models with Unsloth.
"""

import os
import sys
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import psycopg2
from config.settings import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD

def export_unsloth_dataset(output_file: str = "exports/unsloth_training_dataset.jsonl"):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    cur = conn.cursor()

    cur.execute("""
        SELECT 
            g.incident_id,
            g.priority,
            g.rule_code,
            g.target_host,
            g.host_criticality,
            g.total_risk_score,
            g.event_count,
            g.ground_truth_label,
            g.analyst_notes,
            c.title,
            c.narrative,
            c.attacker_source_ip
        FROM soc_ops.ground_truth_dataset g
        JOIN correlation.correlated_incidents c ON g.incident_id = c.incident_id
        WHERE g.ground_truth_label IS NOT NULL
        ORDER BY g.id ASC;
    """)
    rows = cur.fetchall()
    
    dataset = []
    for r in rows:
        inc_id = r[0]
        priority = r[1] or "P2"
        rule_code = r[2] or "ANOMALOUS_ACTIVITY"
        target_host = r[3] or "srv-internal"
        host_crit = r[4] or "STANDARD"
        total_risk = r[5] or 50
        event_count = r[6] or 1
        gt_label = r[7]
        analyst_notes = r[8] or ""
        title = r[9] or "Security Incident"
        narrative = r[10] or "Observed anomalous activity"
        attacker_ip = r[11] or "192.168.1.50"

        verdict_str = "THREAT" if gt_label == 1 else "BENIGN"
        action_str = "FORWARD_TO_TRIAGE" if gt_label == 1 else "AUTO_CLOSE"

        # Format input instruction
        instruction = "You are a Senior Cyber SOC Analyst L2. Analyze the following security incident telemetry and provide your authoritative forensic verdict in JSON format."
        user_input = f"""INCIDENT DETAILS:
- Incident ID: {inc_id}
- Title: {title}
- Target Asset: {target_host} (Criticality Tier: {host_crit})
- Attacker Source IP: {attacker_ip}
- Correlation Rule: {rule_code}
- Priority & Risk Score: Priority {priority} (Total Risk Score: {total_risk}/100)
- Event Volume: {event_count} raw alert events
- Narrative: {narrative}"""

        clean_notes = analyst_notes.split(" | ")[-1] if analyst_notes else f"Forensic analysis confirms {verdict_str} based on telemetry and criticality."
        
        target_output = {
            "verdict": verdict_str,
            "confidence": 95.0,
            "mitre_technique": "T1078" if verdict_str == "THREAT" else "NONE",
            "reasoning": clean_notes,
            "recommended_action": action_str
        }

        # ShareGPT / Unsloth format
        entry = {
            "conversations": [
                {"from": "human", "value": f"{instruction}\n\n{user_input}"},
                {"from": "gpt", "value": json.dumps(target_output, indent=2)}
            ]
        }
        dataset.append(entry)

    with open(output_file, "w", encoding="utf-8") as f:
        for item in dataset:
            f.write(json.dumps(item) + "\n")

    cur.close()
    conn.close()

    print(f"[+] Successfully exported {len(dataset)} training samples to {output_file}")
    return len(dataset)

if __name__ == "__main__":
    export_unsloth_dataset()
