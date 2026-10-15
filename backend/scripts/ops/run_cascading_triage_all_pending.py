"""
Production Cascading AI Triage Pipeline (All Pending Tickets)
=============================================================
Runs Tier-1 ML (LightGBM) -> Tier-2 Local LLM (Qwen) -> Tier-3 Cloud LLM (Gemini Soft Voting)
for all tickets currently unfinalized (resolution_outcome IS NULL) in soc_ops.soc_triage_queue.
"""

import sys
import os
import time
import json
import logging
import re
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone

PROJECT_ROOT = Path(r"c:\Users\Pongo\Downloads\wazuh alert grouping -")
sys.path.insert(0, str(PROJECT_ROOT))

import psycopg2
import config.settings as s
from pipeline.ml_classifier import evaluate_cascading_pipeline

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("CascadingTriagePipeline")

def run_triage():
    conn = psycopg2.connect(
        host=s.DB_HOST, port=s.DB_PORT, dbname=s.DB_NAME, user=s.DB_USER, password=s.DB_PASSWORD
    )
    cur = conn.cursor()

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
    rows = cur.fetchall()
    total = len(rows)
    logger.info(f"[*] Total pending tickets to triage: {total:,} tickets")

    if total == 0:
        logger.info("[OK] No pending tickets. All tickets are already triaged!")
        conn.close()
        return

    # Memory cache for ambiguous LLM evaluations by forensic pattern
    llm_pattern_cache = {}

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
    batch_updates = []

    for idx, r in enumerate(rows, start=1):
        inc_id, trg_id, prio, title, narr, src_ip, target, tenant, f_seen, l_seen, rule_id = r

        inc_payload = {
            "incident_id": inc_id,
            "triage_id": trg_id,
            "priority": prio,
            "title": title or "Security Event",
            "narrative": narr or "Activity sequence",
            "attacker_source_ip": src_ip,
            "target_host": target,
            "tenant_id": tenant,
            "first_seen_at": f_seen,
            "last_seen_at": l_seen,
            "rule_code": rule_id or "CORR-SA",
            "stages": [],
            "stages_count": 1,
            "rule_level": 13 if prio == "P0" else (10 if prio == "P1" else 3),
            "total_risk_score": 85.0 if prio == "P0" else (70.0 if prio == "P1" else 15.0),
            "threat_intel_match": 1 if prio in ("P0", "P1") else 0
        }

        # Semantic cache key for borderline cases to avoid redundant LLM calls for identical burst patterns
        w_match = re.search(r'Rule\s+(\d+)', (narr or '') + ' ' + (title or ''))
        w_num = w_match.group(1) if w_match else '0'
        is_priv_host = 1 if any(k in (target or '').lower() for k in ('prod', 'proxy', 'terminal', 'sgu', 'instiki')) else 0
        cache_key = (prio, rule_id, w_num, is_priv_host, src_ip if prio in ('P0', 'P1') else '')

        if cache_key in llm_pattern_cache:
            res = dict(llm_pattern_cache[cache_key])
            res["cached"] = True
        else:
            res = evaluate_cascading_pipeline(inc_payload)
            if "Local LLM" in res.get("active_tier", "") or "Cloud LLM" in res.get("active_tier", ""):
                llm_pattern_cache[cache_key] = res

        decision = res.get("decision")
        verdict = res.get("final_verdict")
        conf = float(res.get("final_confidence", 0.0))
        tier = res.get("active_tier", "Tier-1 ML")
        needs_gt = res.get("needs_ground_truth", False)

        if decision == "AUTO_CLOSE":
            status = "CLOSE"
            outcome = "FALSE_POSITIVE_TUNING_REQ"
            analyst = f"ai_{tier[:6].lower().replace(' ', '_').replace('-', '_')}"
            reason = f"Auto-closed by {tier} ({conf:.1f}% confidence {verdict}): {res.get('reasoning', '')[:180]}"
            if "Tier-1" in tier:
                stats["tier1_autoclose"] += 1
            elif "Tier-2" in tier:
                stats["tier2_autoclose"] += 1
            else:
                stats["tier3_autoclose"] += 1

        elif decision == "CREATE_IRIS_CASE":
            status = "OPEN"
            outcome = "TRUE_POSITIVE_ACTIONABLE"
            analyst = "iris_orchestrator"
            reason = f"Threat confirmed by {tier} ({conf:.1f}% confidence): {res.get('reasoning', '')[:180]}"
            if "Tier-1" in tier:
                stats["tier1_threat"] += 1
            elif "Tier-2" in tier:
                stats["tier2_threat"] += 1
            else:
                stats["tier3_threat"] += 1

        else: # AUDIT_SOC_ANALYST
            status = "OPEN"
            outcome = None
            analyst = "tier1_soc_analyst"
            reason = f"Inconclusive / Ambiguous ({conf:.1f}%): Dispatched to SOC Analyst Audit and Gold Standard GT."
            stats["analyst_audit"] += 1

        # Queue DB updates
        batch_updates.append((status, outcome, analyst, reason, inc_id))

        # Handle ground truth recording if required
        if needs_gt:
            stats["ground_truth_added"] += 1
            gt_label = 1 if verdict == "THREAT" else 0
            is_train = True if (verdict in ("THREAT", "BENIGN") and conf >= 92.0) else False
            src = "AI_LOCAL_LLM" if "Local LLM" in tier else ("AI_CLOUD_LLM" if "Cloud LLM" in tier else "PENDING_HUMAN")
            gt_outcome = "TRUE_POSITIVE_ACTIONABLE" if gt_label == 1 else "FALSE_POSITIVE_TUNING_REQ"
            cur.execute("""
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
            """, (
                inc_id, trg_id, tenant or "DEFAULT", rule_id or "CORR-SA", prio, target or "unknown",
                1 if verdict == "THREAT" else 0, conf, res.get("decision_path", "CASCADING"), gt_label,
                gt_outcome, analyst, reason, src, is_train
            ))

        # Commit batch every 500 tickets
        if len(batch_updates) >= 500 or idx == total:
            cur.executemany("""
                UPDATE soc_ops.soc_triage_queue
                SET triage_status = %s,
                    resolution_outcome = %s,
                    assigned_analyst = %s,
                    false_positive_reason = %s,
                    resolved_at = CASE WHEN %s = 'CLOSE' THEN CURRENT_TIMESTAMP ELSE resolved_at END,
                    updated_at = CURRENT_TIMESTAMP
                WHERE incident_id = %s;
            """, [(b[0], b[1], b[2], b[3], b[0], b[4]) for b in batch_updates])

            # Update correlated_incidents status
            closed_inc_ids = [b[4] for b in batch_updates if b[0] == "CLOSE"]
            if closed_inc_ids:
                cur.execute("""
                    UPDATE correlation.correlated_incidents
                    SET incident_status = 'CLOSED_FP'
                    WHERE incident_id = ANY(%s);
                """, (closed_inc_ids,))

            escalated_inc_ids = [b[4] for b in batch_updates if b[1] == "TRUE_POSITIVE_ACTIONABLE"]
            if escalated_inc_ids:
                cur.execute("""
                    UPDATE correlation.correlated_incidents
                    SET incident_status = 'ESCALATED'
                    WHERE incident_id = ANY(%s);
                """, (escalated_inc_ids,))

            conn.commit()
            batch_updates = []
            elapsed_sec = time.time() - t0
            rate = idx / max(elapsed_sec, 0.001)
            logger.info(f"Progress: [{idx:,}/{total:,}] ({idx/total*100:.1f}%) in {elapsed_sec:.1f}s ({rate:.1f} tickets/sec) | "
                        f"Tier1 Close: {stats['tier1_autoclose']:,}, Tier1 Threat: {stats['tier1_threat']:,}, "
                        f"Tier2 Close: {stats['tier2_autoclose']:,}, Tier2 Threat: {stats['tier2_threat']:,}, "
                        f"Tier3 Close: {stats['tier3_autoclose']:,}, Tier3 Threat: {stats['tier3_threat']:,}, "
                        f"Audit: {stats['analyst_audit']}")

    conn.commit()
    cur.close()
    conn.close()

    total_time = time.time() - t0
    logger.info("=" * 80)
    logger.info(f"[SUCCESS] CASCADING AI TRIAGE FINISHED FOR ALL {total:,} TICKETS in {total_time:.2f}s!")
    logger.info(f"  • Tier-1 ML Auto-Closed (Benign):   {stats['tier1_autoclose']:,}")
    logger.info(f"  • Tier-1 ML Escalated (Threat):      {stats['tier1_threat']:,}")
    logger.info(f"  • Tier-2 Local LLM Auto-Closed:      {stats['tier2_autoclose']:,}")
    logger.info(f"  • Tier-2 Local LLM Escalated:        {stats['tier2_threat']:,}")
    logger.info(f"  • Tier-3 Cloud LLM Auto-Closed:      {stats['tier3_autoclose']:,}")
    logger.info(f"  • Tier-3 Cloud LLM Escalated:        {stats['tier3_threat']:,}")
    logger.info(f"  • Dispatched for Human SOC Audit:    {stats['analyst_audit']:,}")
    logger.info(f"  • Ground Truths Recorded:            {stats['ground_truth_added']:,}")
    logger.info("=" * 80)

if __name__ == "__main__":
    run_triage()
