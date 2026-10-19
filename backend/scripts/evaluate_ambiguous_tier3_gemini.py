"""
Batch Evaluation of ML Ambiguous Incidents (< 85% Confidence) via Tier-3 Cloud LLM (Google Gemini)
===================================================================================================
Compares:
  - Tier-1 ML (LightGBM)
  - Tier-2 Local LLM (Qwen)
  - Tier-3 Cloud LLM (Google Gemini)
  - Ground Truth (SOC Analyst)
"""

import os
import sys
import time
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import psycopg2
from config.settings import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
from pipeline.cloud_llm import CloudLLMTriageClient

def run_gemini_batch_evaluation():
    print("=" * 80)
    print("TIER-3 CLOUD LLM (GOOGLE GEMINI) BATCH EVALUATION FOR 12 AMBIGUOUS TICKETS")
    print("=" * 80)

    client = CloudLLMTriageClient()
    print(f"[*] Cloud Provider : Google Gemini REST API")
    print(f"[*] Target Model   : {client.model}")
    print(f"[*] API Key Status : {'Configured' if client.api_key else 'Missing'}")
    print(f"[*] Service Check  : {client.is_available()}\n")

    if not client.api_key:
        print("[!] Error: GEMINI_API_KEY is not set.")
        return

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
            g.ground_truth_label,
            g.ml_tier1_prediction,
            g.ml_tier1_confidence,
            g.local_llm_verdict,
            g.local_llm_confidence,
            g.priority,
            g.rule_code,
            g.category,
            g.target_host,
            g.host_criticality,
            g.total_risk_score,
            g.event_count,
            g.ioa_summary,
            c.title,
            c.narrative,
            c.attacker_source_ip
        FROM soc_ops.ground_truth_dataset g
        JOIN correlation.correlated_incidents c ON g.incident_id = c.incident_id
        WHERE g.ml_tier1_confidence < 85.0
        ORDER BY g.ml_tier1_confidence ASC;
    """)
    rows = cur.fetchall()
    total_tickets = len(rows)
    print(f"[+] Total ambiguous incidents to evaluate: {total_tickets} tickets\n")

    results = []

    for idx, r in enumerate(rows, start=1):
        inc_id = r[0]
        gt_label = r[1]
        ml_pred = r[2]
        ml_conf = float(r[3])
        local_llm_v = r[4]
        local_llm_c = float(r[5]) if r[5] is not None else None
        priority = r[6] or "P2"
        rule_code = r[7] or "CORR_GENERIC"
        target_host = r[9] or "Unknown Host"
        host_crit = r[10] or "STANDARD"
        risk_score = r[11] or 50
        event_count = r[12] or 1
        ioa_summary = r[13] or ""
        title = r[14] or "Incident"
        narrative = r[15] or ""
        attacker_ip = r[16] or "Unknown"

        incident_payload = {
            "incident_id": inc_id,
            "title": title,
            "narrative": narrative or ioa_summary,
            "target_host": target_host,
            "host_criticality": host_crit,
            "total_risk_score": risk_score,
            "priority": priority,
            "rule_code": rule_code,
            "attacker_source_ip": attacker_ip,
            "event_count": event_count,
        }

        print(f"[{idx}/{total_tickets}] Evaluating {inc_id} ({priority}, ML: {ml_conf:.1f}%)...")
        eval_res = client.evaluate_incident(incident_payload)

        gt_str = "THREAT" if gt_label == 1 else "BENIGN"
        local_str = "THREAT" if local_llm_v == "TRUE_POSITIVE" else ("BENIGN" if local_llm_v == "FALSE_POSITIVE" else "N/A")

        eval_res["ground_truth"] = gt_str
        eval_res["ml_confidence"] = ml_conf
        eval_res["ml_verdict"] = "THREAT" if ml_pred == 1 else "BENIGN"
        eval_res["local_llm_verdict"] = local_str
        eval_res["local_llm_confidence"] = local_llm_c
        eval_res["is_gemini_match"] = (eval_res["verdict"] == gt_str)

        results.append(eval_res)
        print(f"    -> Gemini: {eval_res['verdict']} ({eval_res['confidence']:.1f}%) | Action: {eval_res['decision']}")
        print(f"    -> Local Qwen: {local_str} ({local_llm_c}%) | ML: {eval_res['ml_verdict']} ({ml_conf:.1f}%) | GT: {gt_str}")
        print(f"    -> Time: {eval_res['execution_time_seconds']}s\n")
        
        # Small delay to respect rate limits
        time.sleep(1)

    cur.close()
    conn.close()

    # Save to JSON
    export_file = "exports/tier3_gemini_evaluation_results.json"
    with open(export_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("=" * 80)
    print("EVALUATION COMPLETED!")
    print(f"[+] Results exported to: {export_file}")
    print("=" * 80)

if __name__ == "__main__":
    run_gemini_batch_evaluation()
