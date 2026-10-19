"""
Production Cascading AI Triage Pipeline (Vectorized High-Throughput)
===================================================================
Runs:
1. Tier-1 ML (LightGBM Calibrated) vectorized inference for high throughput.
2. For tickets where confidence >= 85%:
   - Benign -> Auto-Close (status='CLOSE', outcome='FALSE_POSITIVE_TUNING_REQ')
   - Threat -> Escalated to IRIS (status='INVESTIGATE', outcome='TRUE_POSITIVE_ACTIONABLE')
3. For borderline tickets (< 85% confidence):
   - Cascades to Tier-2 Local LLM (Qwen) -> Tier-3 Cloud LLM (Gemini Soft Voting)
   - If still inconclusive -> Human SOC Audit (status='OPEN', outcome=NULL)
   - Records Ground Truth in soc_ops.ground_truth_dataset for ML retraining.
"""

import sys
import os
import time
import json
import logging
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone

PROJECT_ROOT = Path(r"c:\Users\Pongo\Downloads\wazuh alert grouping -")
sys.path.insert(0, str(PROJECT_ROOT))

import psycopg2
from psycopg2.extras import execute_batch
import numpy as np
import pandas as pd

import config.settings as s
from pipeline.ml_classifier import get_classifier, evaluate_cascading_pipeline

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("CascadingTriagePipeline")

def run_triage():
    conn = psycopg2.connect(
        host=s.DB_HOST, port=s.DB_PORT, dbname=s.DB_NAME, user=s.DB_USER, password=s.DB_PASSWORD
    )
    cur = conn.cursor()

    logger.info("[*] Fetching pending tickets from soc_ops.soc_triage_queue...")
    cur.execute("""
        SELECT 
            q.incident_id, q.triage_id, q.priority,
            i.title, i.narrative, i.attacker_source_ip, i.target_host, i.tenant_id,
            i.first_seen_at, i.last_seen_at, i.correlation_rule_id
        FROM soc_ops.soc_triage_queue q
        JOIN correlation.correlated_incidents i ON q.incident_id = i.incident_id
        WHERE q.resolution_outcome IS NULL
        ORDER BY 
            CASE q.priority WHEN 'P0' THEN 1 WHEN 'P1' THEN 2 WHEN 'P2' THEN 3 WHEN 'P3' THEN 4 ELSE 5 END,
            q.created_at ASC;
    """)
    cols = [desc[0] for desc in cur.description]
    all_rows = cur.fetchall()
    total = len(all_rows)
    logger.info(f"[*] Total pending tickets to triage: {total:,} tickets")

    if total == 0:
        logger.info("[OK] No pending tickets. All tickets are already triaged!")
        conn.close()
        return

    clf = get_classifier()

    stats = {
        "tier1_autoclose": 0,
        "tier1_threat": 0,
        "tier2_autoclose": 0,
        "tier2_threat": 0,
        "tier3_autoclose": 0,
        "tier3_threat": 0,
        "analyst_audit": 0,
        "ground_truth_added": 0
    }

    t0 = time.time()
    batch_size = 10000
    llm_pattern_cache = {}

    for batch_start in range(0, total, batch_size):
        batch_slice = all_rows[batch_start:batch_start + batch_size]
        batch_dicts = [dict(zip(cols, r)) for r in batch_slice]

        # Extract features for batch
        for d in batch_dicts:
            prio = d.get("priority", "P4")
            d["rule_code"] = d.get("correlation_rule_id") or "CORR-ENTITY"
            d["stages_count"] = 1
            d["rule_level"] = 13 if prio == "P0" else (10 if prio == "P1" else (7 if prio == "P2" else (5 if prio == "P3" else 2)))
            d["total_risk_score"] = 90.0 if prio == "P0" else (75.0 if prio == "P1" else (50.0 if prio == "P2" else (30.0 if prio == "P3" else 10.0)))

        batch_features = [clf.extract_features(d) for d in batch_dicts]
        df_feats = pd.DataFrame(batch_features)

        for col in clf.FEATURE_CATEGORICAL:
            df_feats[col] = df_feats[col].fillna("UNKNOWN").astype(str)
        for col in clf.FEATURE_NUMERIC:
            df_feats[col] = pd.to_numeric(df_feats[col], errors="coerce").fillna(0)

        X_cat = clf.encoder.transform(df_feats[clf.FEATURE_CATEGORICAL])
        X_num = df_feats[clf.FEATURE_NUMERIC].values
        X_matrix = np.hstack([X_num, X_cat])

        # Fast Vectorized LightGBM Inference
        probs = clf.calibrated_model.predict_proba(X_matrix)

        triage_updates = []
        closed_inc_ids = []
        escalated_inc_ids = []
        gt_inserts = []

        for idx_in_batch, d in enumerate(batch_dicts):
            p_benign = float(probs[idx_in_batch, 0])
            p_threat = float(probs[idx_in_batch, 1])

            if p_threat >= p_benign:
                verdict = "THREAT"
                conf = round(p_threat * 100.0, 2)
            else:
                verdict = "BENIGN"
                conf = round(p_benign * 100.0, 2)

            inc_id = d["incident_id"]
            trg_id = d["triage_id"]
            prio = d.get("priority", "P4")
            rule_id = d.get("correlation_rule_id", "CORR-ENTITY")
            target = d.get("target_host", "unknown")
            tenant = d.get("tenant_id", "DEFAULT")

            if conf >= 85.0:
                # High Confidence Tier-1
                if verdict == "BENIGN":
                    status = "CLOSE"
                    outcome = "FALSE_POSITIVE_TUNING_REQ"
                    analyst = "ai_cascade_Tier-1 ML"
                    reason = f"Auto-closed by Tier-1 ML ({conf:.1f}% confidence Benign): Calibrated Operational Noise."
                    stats["tier1_autoclose"] += 1
                    closed_inc_ids.append(inc_id)
                else:
                    status = "INVESTIGATE"
                    outcome = "TRUE_POSITIVE_ACTIONABLE"
                    analyst = "iris_orchestrator"
                    reason = f"Threat confirmed by Tier-1 ML ({conf:.1f}% confidence): Escalated to DFIR-IRIS."
                    stats["tier1_threat"] += 1
                    escalated_inc_ids.append(inc_id)

                triage_updates.append((status, outcome, analyst, reason, inc_id))

            else:
                # Borderline / Ambiguous (<85%): Cascade to Tier-2 / Tier-3
                is_internal = 1 if any(k in str(d.get("attacker_source_ip", "")).lower() for k in ("user:", "10.", "192.168.", "172.", "localhost", "127.0.0.1")) else 0
                title_sig = str(d.get("title", ""))[:30]
                cache_key = (prio, rule_id, title_sig, is_internal)
                if cache_key in llm_pattern_cache:
                    res = dict(llm_pattern_cache[cache_key])
                else:
                    res = evaluate_cascading_pipeline(d)
                    llm_pattern_cache[cache_key] = res

                cascade_decision = res.get("decision")
                cascade_verdict = res.get("final_verdict")
                cascade_conf = float(res.get("final_confidence", 0.0))
                tier = res.get("active_tier", "Cascading AI")
                needs_gt = res.get("needs_ground_truth", False)

                if cascade_decision == "AUTO_CLOSE":
                    status = "CLOSE"
                    outcome = "FALSE_POSITIVE_TUNING_REQ"
                    analyst = f"ai_{tier[:6].lower().replace(' ', '_').replace('-', '_')}"
                    reason = f"Auto-closed by {tier} ({cascade_conf:.1f}% confidence): {res.get('reasoning', '')[:160]}"
                    if "Tier-2" in tier:
                        stats["tier2_autoclose"] += 1
                    else:
                        stats["tier3_autoclose"] += 1
                    closed_inc_ids.append(inc_id)

                elif cascade_decision == "CREATE_IRIS_CASE":
                    status = "INVESTIGATE"
                    outcome = "TRUE_POSITIVE_ACTIONABLE"
                    analyst = "iris_orchestrator"
                    reason = f"Threat confirmed by {tier} ({cascade_conf:.1f}% confidence): {res.get('reasoning', '')[:160]}"
                    if "Tier-2" in tier:
                        stats["tier2_threat"] += 1
                    else:
                        stats["tier3_threat"] += 1
                    escalated_inc_ids.append(inc_id)

                else:
                    status = "OPEN"
                    outcome = None
                    analyst = "tier1_soc_analyst"
                    reason = f"Inconclusive / Ambiguous ({cascade_conf:.1f}%): Dispatched to SOC Analyst Audit and Gold Standard GT."
                    stats["analyst_audit"] += 1

                triage_updates.append((status, outcome, analyst, reason, inc_id))

                if needs_gt:
                    stats["ground_truth_added"] += 1
                    gt_label = 1 if cascade_verdict == "THREAT" else 0
                    is_train = True if (cascade_verdict in ("THREAT", "BENIGN") and cascade_conf >= 90.0) else False
                    src = "AI_LOCAL_LLM" if "Local LLM" in tier else "AI_SOFT_VOTING"
                    gt_outcome = "TRUE_POSITIVE_ACTIONABLE" if gt_label == 1 else "FALSE_POSITIVE_TUNING_REQ"
                    gt_inserts.append((
                        inc_id, trg_id, tenant or "DEFAULT", rule_id, prio, target or "unknown",
                        1 if cascade_verdict == "THREAT" else 0, cascade_conf, res.get("decision_path", "CASCADING"),
                        gt_label, gt_outcome, analyst, reason, src, is_train
                    ))

        # Batch Execute DB Updates
        update_queue_sql = """
            UPDATE soc_ops.soc_triage_queue
            SET triage_status = %s,
                resolution_outcome = %s,
                assigned_analyst = %s,
                false_positive_reason = %s,
                resolved_at = CASE WHEN %s = 'CLOSE' THEN CURRENT_TIMESTAMP ELSE resolved_at END,
                updated_at = CURRENT_TIMESTAMP
            WHERE incident_id = %s;
        """
        execute_batch(cur, update_queue_sql, [(u[0], u[1], u[2], u[3], u[0], u[4]) for u in triage_updates], page_size=1000)

        if closed_inc_ids:
            cur.execute("""
                UPDATE correlation.correlated_incidents
                SET incident_status = 'CLOSED_FP'
                WHERE incident_id = ANY(%s);
            """, (closed_inc_ids,))

        if escalated_inc_ids:
            cur.execute("""
                UPDATE correlation.correlated_incidents
                SET incident_status = 'ESCALATED'
                WHERE incident_id = ANY(%s);
            """, (escalated_inc_ids,))

        if gt_inserts:
            gt_sql = """
                INSERT INTO soc_ops.ground_truth_dataset (
                    incident_id, triage_id, tenant_id, rule_code, priority, target_host,
                    ml_tier1_prediction, ml_tier1_confidence, decision_path, ground_truth_label,
                    resolution_outcome, analyst_id, analyst_notes, label_source, is_used_in_training, created_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, CURRENT_TIMESTAMP
                )
                ON CONFLICT (incident_id) DO UPDATE SET
                    decision_path = EXCLUDED.decision_path,
                    resolution_outcome = EXCLUDED.resolution_outcome,
                    analyst_notes = EXCLUDED.analyst_notes;
            """
            execute_batch(cur, gt_sql, gt_inserts, page_size=1000)

        conn.commit()
        done_count = min(batch_start + batch_size, total)
        elapsed = time.time() - t0
        rate = done_count / max(elapsed, 0.001)
        logger.info(f"Progress: [{done_count:,}/{total:,}] ({done_count/total*100:.1f}%) in {elapsed:.1f}s ({rate:.1f} tickets/sec) | "
                    f"Tier-1 Close: {stats['tier1_autoclose']:,}, Tier-1 Threat: {stats['tier1_threat']:,}, "
                    f"Cascade Close: {stats['tier2_autoclose'] + stats['tier3_autoclose']:,}, "
                    f"Cascade Threat: {stats['tier2_threat'] + stats['tier3_threat']:,}, "
                    f"Audit: {stats['analyst_audit']:,}")

    # Refresh Rollup Table
    logger.info("[*] Refreshing metrics.hourly_overview_rollup for live dashboard display...")
    cur.execute("SELECT db.refresh_hourly_overview_rollup();")
    conn.commit()

    cur.close()
    conn.close()

    total_time = time.time() - t0
    logger.info("=" * 80)
    logger.info(f"[SUCCESS] CASCADING AI TRIAGE FINISHED FOR ALL {total:,} TICKETS in {total_time:.2f}s!")
    logger.info(f"  • Tier-1 ML Auto-Closed (Benign):   {stats['tier1_autoclose']:,}")
    logger.info(f"  • Tier-1 ML Escalated (Threat):      {stats['tier1_threat']:,}")
    logger.info(f"  • Tier-2/3 LLM Auto-Closed:          {stats['tier2_autoclose'] + stats['tier3_autoclose']:,}")
    logger.info(f"  • Tier-2/3 LLM Escalated:            {stats['tier2_threat'] + stats['tier3_threat']:,}")
    logger.info(f"  • Dispatched for Human SOC Audit:    {stats['analyst_audit']:,}")
    logger.info(f"  • Ground Truths Recorded:            {stats['ground_truth_added']:,}")
    logger.info("=" * 80)

if __name__ == "__main__":
    run_triage()
