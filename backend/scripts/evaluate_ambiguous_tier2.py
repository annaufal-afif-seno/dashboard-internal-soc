"""
Batch Evaluation of ML Ambiguous Incidents (< 85% Confidence) via Tier-2 Local LLM (Ollama)
"""

import os
import sys
import time
import json
import argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import psycopg2
from config.settings import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD, LOCAL_LLM_MODEL
from pipeline.local_llm import LocalLLMTriageClient

def run_tier2_evaluation(model_name=None):
    chosen_model = model_name or LOCAL_LLM_MODEL
    print("=" * 80)
    print(f"TIER-2 LOCAL LLM ({chosen_model}) EVALUATION FOR ML CONFIDENCE < 85%")
    print("=" * 80)

    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    cur = conn.cursor()

    # 1. Fetch ambiguous incidents (< 85% ML confidence)
    cur.execute("""
        SELECT 
            g.incident_id,
            g.ground_truth_label,
            g.ml_tier1_prediction,
            g.ml_tier1_confidence,
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
    total_ambiguous = len(rows)
    print(f"\n[+] Total incidents found with ML Tier-1 Confidence < 85%: {total_ambiguous} tickets\n")

    client = LocalLLMTriageClient(model=chosen_model, timeout=120)
    print(f"[*] Target LLM Service: {client.base_url}")
    print(f"[*] Target LLM Model  : {client.model}")
    print(f"[*] Service Available : {client.is_available()}\n")

    results = []

    for idx, r in enumerate(rows, start=1):
        inc_id = r[0]
        gt_label = r[1]
        ml_pred = r[2]
        ml_conf = float(r[3])
        priority = r[4] or "P2"
        rule_code = r[5] or "CORR_GENERIC"
        category = r[6] or "Threat"
        target_host = r[7] or "Unknown Host"
        host_crit = r[8] or "STANDARD"
        risk_score = r[9] or 50
        event_count = r[10] or 1
        ioa_summary = r[11] or ""
        title = r[12] or "Incident"
        narrative = r[13] or ""
        attacker_ip = r[14] or "Unknown"

        # Fetch stages
        cur.execute("""
            SELECT stage_name, stage_description 
            FROM correlation.incident_stages 
            WHERE incident_id = %s 
            ORDER BY sequence_order ASC;
        """, (inc_id,))
        stage_rows = cur.fetchall()
        stages = [{"stage_name": s[0], "stage_description": s[1]} for s in stage_rows]

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
            "stages": stages
        }

        print(f"[{idx}/{total_ambiguous}] Evaluating {inc_id} ({priority}, ML Conf: {ml_conf:.2f}%)...")
        eval_res = client.evaluate_incident(incident_payload)
        
        gt_str = "THREAT" if gt_label == 1 else "BENIGN"
        is_match = (eval_res["verdict"] == gt_str)

        eval_res["ground_truth"] = gt_str
        eval_res["ml_confidence"] = ml_conf
        eval_res["priority"] = priority
        eval_res["is_match"] = is_match
        results.append(eval_res)

        print(f"    -> LLM Verdict: {eval_res['verdict']} | Conf: {eval_res['confidence']:.2f}% | Action: {eval_res['decision']}")
        print(f"    -> Ground Truth: {gt_str} | Match: {'YES' if is_match else 'NO'} | Time: {eval_res['execution_time_seconds']}s\n")

    # Update decision_path in DB safely
    for res in results:
        cur.execute("""
            UPDATE soc_ops.ground_truth_dataset
            SET decision_path = %s
            WHERE incident_id = %s;
        """, (f"TIER2_{res['decision']}", res["incident_id"]))
    conn.commit()
    cur.close()
    conn.close()

    print("=" * 80)
    print("EVALUATION SUMMARY REPORT")
    print("=" * 80)

    auto_threat = [r for r in results if r["decision"] == "FORWARD_TO_TRIAGE"]
    auto_benign = [r for r in results if r["decision"] == "AUTO_CLOSE"]
    req_human = [r for r in results if r["decision"] == "REQUIRE_GROUND_TRUTH"]
    matches = [r for r in results if r["is_match"]]

    print(f"Total Ambiguous Tickets Evaluated : {len(results)}")
    print(f"Auto-Escalated as THREAT (>= 85%) : {len(auto_threat)} tickets")
    print(f"Auto-Suppressed as BENIGN (>= 85%): {len(auto_benign)} tickets")
    print(f"Ambiguous / Require Human GT (<85%): {len(req_human)} tickets")
    print(f"Local LLM Alignment vs Ground Truth: {len(matches)}/{len(results)} ({len(matches)/len(results)*100:.1f}%)")
    print("=" * 80)

    # Save to JSON
    safe_name = chosen_model.replace(':', '_').replace('.', '_')
    export_file = f"exports/tier2_{safe_name}_evaluation_results.json"
    os.makedirs("exports", exist_ok=True)
    with open(export_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"[+] Detailed results exported to {export_file}")

    # Also keep a copy as latest
    with open("exports/tier2_local_llm_latest.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=str, default=None, help="Ollama model name")
    args = parser.parse_args()
    run_tier2_evaluation(args.model)
