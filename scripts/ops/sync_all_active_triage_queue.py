import psycopg2
import psycopg2.extras
from pipeline.ml_classifier import evaluate_cascading_pipeline

def sync_active_tickets():
    conn = psycopg2.connect(host='localhost', port=5432, dbname='wazuh_soc_db', user='postgres', password='postgres')
    conn.autocommit = False
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    try:
        # Get all tickets that are currently GROUNDTRUTH or OPEN or INVESTIGATE
        cur.execute("""
            SELECT q.triage_id, q.priority, q.triage_status, q.ground_truth_status, i.*
            FROM soc_ops.soc_triage_queue q
            JOIN correlation.correlated_incidents i ON q.incident_id = i.incident_id
            WHERE q.triage_status IN ('GROUNDTRUTH', 'OPEN', 'INVESTIGATING', 'INVESTIGATE')
            ORDER BY 
                CASE q.triage_status WHEN 'GROUNDTRUTH' THEN 1 ELSE 2 END,
                CASE q.priority WHEN 'P0' THEN 1 WHEN 'P1' THEN 2 WHEN 'P2' THEN 3 WHEN 'P3' THEN 4 ELSE 5 END,
                q.created_at ASC;
        """)
        candidates = cur.fetchall()
        print(f"Total candidate active tickets to sync: {len(candidates)}")

        # Fetch stages
        cur.execute("SELECT incident_id, sequence_order, stage_name, stage_description FROM correlation.incident_stages ORDER BY incident_id, sequence_order;")
        stages_by_inc = {}
        for r in cur.fetchall():
            stages_by_inc.setdefault(r["incident_id"], []).append(dict(r))

        threat_updates = []
        benign_updates = []
        gt_updates = []

        for idx, row in enumerate(candidates, 1):
            inc = dict(row)
            inc_id = inc["incident_id"]
            triage_id = inc["triage_id"]
            inc["stages"] = stages_by_inc.get(inc_id, [])

            cascade_res = evaluate_cascading_pipeline(inc)
            tier = cascade_res.get("active_tier", "Tier-1 ML")
            conf = float(cascade_res.get("final_confidence", 0.0))
            reasoning = cascade_res.get("reasoning", "")
            verdict = cascade_res.get("final_verdict", "BENIGN")
            decision = cascade_res.get("decision")

            if decision == "CREATE_IRIS_CASE" or (verdict == "THREAT" and conf >= 85.0):
                reason = f"Threat confirmed by {tier} ({conf:.1f}%): {reasoning}"
                threat_updates.append((reason, triage_id, inc_id))
                print(f"[{idx}/{len(candidates)}] {triage_id} -> THREAT ({conf:.1f}%)")
            elif decision in ("AUTO_CLOSE", "AUTO_SUPPRESS") or (verdict == "BENIGN" and conf >= 85.0):
                reason = f"Auto-closed by {tier} ({conf:.1f}%): {reasoning}"
                benign_updates.append((f"ai_cascade_{tier}", reason, triage_id, inc_id))
                print(f"[{idx}/{len(candidates)}] {triage_id} -> BENIGN ({conf:.1f}%)")
            else:
                reason = f"Inconclusive ({conf:.1f}%): {reasoning}"
                gt_updates.append((reason, triage_id, inc_id))
                print(f"[{idx}/{len(candidates)}] {triage_id} -> GROUNDTRUTH ({conf:.1f}%)")

        # Execute updates
        if threat_updates:
            psycopg2.extras.execute_batch(cur, """
                UPDATE soc_ops.soc_triage_queue
                SET triage_status = 'CLOSE',
                    resolution_outcome = 'TRUE_POSITIVE_ACTIONABLE',
                    is_verified_true_positive = TRUE,
                    assigned_analyst = 'iris_orchestrator',
                    false_positive_reason = %s,
                    ground_truth_status = NULL,
                    resolved_at = COALESCE(resolved_at, CURRENT_TIMESTAMP),
                    updated_at = CURRENT_TIMESTAMP
                WHERE triage_id = %s OR incident_id = %s;
            """, threat_updates, page_size=200)

        if benign_updates:
            psycopg2.extras.execute_batch(cur, """
                UPDATE soc_ops.soc_triage_queue
                SET triage_status = 'CLOSE',
                    resolution_outcome = 'BENIGN',
                    is_verified_true_positive = FALSE,
                    assigned_analyst = %s,
                    false_positive_reason = %s,
                    ground_truth_status = NULL,
                    resolved_at = COALESCE(resolved_at, CURRENT_TIMESTAMP),
                    updated_at = CURRENT_TIMESTAMP
                WHERE triage_id = %s OR incident_id = %s;
            """, benign_updates, page_size=200)

        if gt_updates:
            psycopg2.extras.execute_batch(cur, """
                UPDATE soc_ops.soc_triage_queue
                SET triage_status = 'GROUNDTRUTH',
                    ground_truth_status = 'ACT NEED',
                    resolution_outcome = NULL,
                    assigned_analyst = 'tier1_soc_analyst',
                    false_positive_reason = %s,
                    updated_at = CURRENT_TIMESTAMP
                WHERE triage_id = %s OR incident_id = %s;
            """, gt_updates, page_size=200)

        conn.commit()
        print(f"\n[SELESAI] Sinkronisasi Sukses! Threat: {len(threat_updates)}, Benign: {len(benign_updates)}, Inconclusive Groundtruth: {len(gt_updates)}")

    except Exception as e:
        conn.rollback()
        print(f"Error during sync: {e}")
        raise
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    sync_active_tickets()
