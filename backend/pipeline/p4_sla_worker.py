"""
SLA Expiry AI Dispatch Worker (All Priorities)
===============================================
PRD Section 6: Semua tiket harus lewat ML / LLM local / LLM cloud setelah
SLA habis dan tidak ada aggregate yang menggantung.

Alur:
1. Enrich (MISP + AbuseIPDB) setelah SLA tiket menutup (PRD Section 6.1)
2. ML -> LLM local -> LLM cloud (PRD Section 6.2)
3. Soft voting jika sampai cloud (PRD Section 6.3)
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
import psycopg2

from config.settings import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
from pipeline.ml_classifier import evaluate_cascading_pipeline
from pipeline.score import SLA_MATRIX_MINUTES

logger = logging.getLogger("SLAWorker")


def get_expired_tickets(
    db_name: str = DB_NAME,
    reference_time: Optional[datetime] = None
) -> List[Dict[str, Any]]:
    """
    Fetch ALL tickets whose SLA has expired and have no hanging aggregates.
    PRD Section 5.4: Tiket tidak langsung diproses saat SLA habis jika
    masih ada aggregate yang menggantung.
    PRD Section 6: Semua tiket lewat AI setelah SLA habis.
    """
    ref_ts = reference_time or datetime.now(timezone.utc)
    ref_naive = ref_ts.replace(tzinfo=None) if getattr(ref_ts, "tzinfo", None) else ref_ts

    conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, database=db_name,
                            user=DB_USER, password=DB_PASSWORD)
    cur = conn.cursor()

    # Fetch tickets where SLA has expired based on priority
    query = """
        SELECT
            q.incident_id, q.triage_id, q.priority, q.triage_status,
            COALESCE(q.priority_established_at, q.created_at) AS priority_established_at,
            i.title, i.attacker_source_ip, i.target_host, i.tenant_id,
            i.narrative, i.correlation_rule_id, i.first_seen_at, i.last_seen_at
        FROM soc_ops.soc_triage_queue q
        JOIN correlation.correlated_incidents i ON q.incident_id = i.incident_id
        WHERE q.triage_status IN ('NEW', 'HOLDING_P4', 'OPEN')
          AND (
            (q.priority = 'P0' AND (COALESCE(q.priority_established_at, q.created_at) + INTERVAL '15 minutes') <= %s) OR
            (q.priority = 'P1' AND (COALESCE(q.priority_established_at, q.created_at) + INTERVAL '60 minutes') <= %s) OR
            (q.priority = 'P2' AND (COALESCE(q.priority_established_at, q.created_at) + INTERVAL '4 hours') <= %s) OR
            (q.priority = 'P3' AND (COALESCE(q.priority_established_at, q.created_at) + INTERVAL '1 day') <= %s) OR
            (q.priority = 'P4' AND (COALESCE(q.priority_established_at, q.created_at) + INTERVAL '7 days') <= %s)
          )
          -- Pastikan tidak ada aggregate in-flight yang masih menggantung (window_end > current reference time)
          AND NOT EXISTS (
              SELECT 1 
              FROM suppression.aggregated_alerts a
              WHERE (a.source_ip = i.attacker_source_ip OR a.actor = i.attacker_source_ip)
                AND (a.target = i.target_host OR a.agent_id = i.target_host)
                AND a.window_end > %s
          )
        ORDER BY q.priority ASC, q.created_at ASC;
    """
    cur.execute(query, (ref_naive, ref_naive, ref_naive, ref_naive, ref_naive, ref_naive))
    rows = cur.fetchall()

    expired_tickets = []
    for r in rows:
        inc_id = r[0]
        cur.execute("""
            SELECT sequence_order, stage_name, reference_id, stage_description
            FROM correlation.incident_stages
            WHERE incident_id = %s ORDER BY sequence_order ASC;
        """, (inc_id,))
        stages = [
            {"sequence_order": s[0], "stage_name": s[1], "category": s[1],
             "reference_id": s[2], "stage_description": s[3]}
            for s in cur.fetchall()
        ]

        # Threat Intel Context Enrichment (AbuseIPDB & MISP feed lookup)
        src_ip = r[6]
        ti_match = 0
        ti_feed = None
        ti_conf = 0
        if src_ip:
            cur.execute("""
                SELECT threat_actor, malware_family, confidence_score, source_feed, description
                FROM enrichment.threat_intelligence_iocs
                WHERE indicator_value = %s AND is_active = TRUE
                ORDER BY confidence_score DESC LIMIT 1;
            """, (src_ip,))
            ti_row = cur.fetchone()
            if ti_row:
                ti_match = 1
                ti_conf = ti_row[2] or 80
                ti_feed = ti_row[3] or "AbuseIPDB/MISP"

        expired_tickets.append({
            "incident_id": inc_id, "triage_id": r[1], "priority": r[2],
            "triage_status": r[3], "priority_established_at": r[4],
            "title": r[5], "attacker_source_ip": src_ip, "target_host": r[7],
            "tenant_id": r[8], "narrative": r[9],
            "rule_code": r[10] or "STANDALONE_AGGREGATE",
            "correlation_rule_id": r[10] or "CORR-SA",
            "first_seen_at": r[11], "last_seen_at": r[12],
            "threat_intel_match": ti_match,
            "threat_intel_confidence": ti_conf,
            "threat_intel_feed": ti_feed,
            "stages": stages, "stages_count": len(stages)
        })

    cur.close()
    conn.close()
    return expired_tickets


# Backward-compatible alias
get_expired_p4_tickets = get_expired_tickets


def process_expired_tickets(
    db_name: str = DB_NAME,
    reference_time: Optional[datetime] = None
) -> Dict[str, Any]:
    """
    PRD Section 6: Proses AI triage untuk semua tiket yang SLA-nya habis.
    1. Enrich (MISP/AbuseIPDB) - PRD Section 6.1
    2. ML -> LLM local -> LLM cloud - PRD Section 6.2
    3. Soft voting (0.4 local + 0.6 cloud) - PRD Section 6.3
    """
    expired_tickets = get_expired_tickets(db_name, reference_time)
    if not expired_tickets:
        logger.info("[SLAWorker] No expired tickets pending AI processing.")
        return {"total_expired": 0, "auto_closed": 0, "escalated": 0, "details": []}

    logger.info(f"[SLAWorker] Found {len(expired_tickets)} expired tickets. Dispatching to AI pipeline...")

    conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, database=db_name,
                            user=DB_USER, password=DB_PASSWORD)
    cur = conn.cursor()
    auto_closed = 0
    escalated = 0
    details = []

    for inc in expired_tickets:
        inc_id = inc["incident_id"]
        triage_id = inc["triage_id"]
        try:
            cascade_res = evaluate_cascading_pipeline(inc)
            decision = cascade_res.get("decision")
            tier = cascade_res.get("active_tier", "Unknown")
            conf = float(cascade_res.get("final_confidence", 0.0))
            reasoning = cascade_res.get("reasoning", "")
            verdict = cascade_res.get("final_verdict", "BENIGN")

            if decision in ("AUTO_CLOSE", "AUTO_SUPPRESS"):
                # PRD Section 6.2: Confidence >= 85 dan benign -> tiket closed
                auto_closed += 1
                reason = f"SLA expired. Auto-resolved by {tier} ({conf:.1f}%): {reasoning}"
                cur.execute("""
                    UPDATE soc_ops.soc_triage_queue
                    SET triage_status = 'CLOSE', resolution_outcome = 'FALSE_POSITIVE_TUNING_REQ',
                        assigned_analyst = %s, false_positive_reason = %s,
                        resolved_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                    WHERE incident_id = %s;
                """, (f"ai_cascade_{tier}", reason, inc_id))
                cur.execute("""
                    UPDATE correlation.correlated_incidents
                    SET incident_status = 'CLOSED_FP'
                    WHERE incident_id = %s;
                """, (inc_id,))
                details.append({"incident_id": inc_id, "action": "AUTO_CLOSE",
                                "tier": tier, "confidence": conf, "verdict": verdict})

            elif decision == "CREATE_IRIS_CASE":
                # PRD Section 6.2: Confidence >= 85 dan threat -> case di IRIS + import MISP
                escalated += 1
                reason = f"SLA expired. Threat detected by {tier} ({conf:.1f}%): {reasoning}"
                cur.execute("""
                    UPDATE soc_ops.soc_triage_queue
                    SET triage_status = 'INVESTIGATE', resolution_outcome = 'TRUE_POSITIVE_ACTIONABLE',
                        assigned_analyst = 'iris_orchestrator', false_positive_reason = %s,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE incident_id = %s;
                """, (reason, inc_id))
                cur.execute("""
                    UPDATE correlation.correlated_incidents
                    SET incident_status = 'ESCALATED'
                    WHERE incident_id = %s;
                """, (inc_id,))
                details.append({"incident_id": inc_id, "action": "CREATE_IRIS_CASE",
                                "tier": tier, "confidence": conf, "verdict": verdict})
            else:
                # PRD Section 6.2: Confidence < 85 -> audit SOC analyst + groundtruth
                escalated += 1
                reason = f"SLA expired. Inconclusive ({conf:.1f}%): {reasoning}"
                cur.execute("""
                    UPDATE soc_ops.soc_triage_queue
                    SET triage_status = 'OPEN', assigned_analyst = 'tier1_soc_analyst',
                        false_positive_reason = %s, updated_at = CURRENT_TIMESTAMP
                    WHERE incident_id = %s;
                """, (reason, inc_id))
                details.append({"incident_id": inc_id, "action": "AUDIT_SOC_ANALYST",
                                "tier": tier, "confidence": conf, "verdict": verdict})
        except Exception as e:
            logger.error(f"[SLAWorker] Failed to process {inc_id}: {e}")
            details.append({"incident_id": inc_id, "action": "ERROR", "error": str(e)})

    conn.commit()
    cur.close()
    conn.close()
    logger.info(f"[SLAWorker] Done: {auto_closed} Auto-Closed, {escalated} Escalated.")
    return {"total_expired": len(expired_tickets), "auto_closed": auto_closed,
            "escalated": escalated, "details": details}


# Backward-compatible alias
process_expired_p4_tickets = process_expired_tickets


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SLA Expiry AI Dispatch Worker")
    parser.add_argument("--db", default=DB_NAME, help="Target database name")
    parser.add_argument("--days-offset", type=float, default=0.0)
    args = parser.parse_args()
    ref = datetime.now(timezone.utc) + timedelta(days=args.days_offset)
    res = process_expired_tickets(db_name=args.db, reference_time=ref)
    print(res)

