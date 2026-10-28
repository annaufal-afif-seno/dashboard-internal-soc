#!/usr/bin/env python3
"""
Sync Threat Tickets and Campaigns
=================================
1. Evaluates all P0, P1, P2 tickets via Cascading AI Triage (Tier-1 ML, Tier-2 Foundation LLM, Tier-3 Cloud).
2. Updates soc_triage_queue and correlated_incidents with true verdicts:
   - Confident THREAT (>= 85%) -> resolution_outcome = 'TRUE_POSITIVE_ACTIONABLE', incident_status = 'ESCALATED'
   - Confident BENIGN (>= 85%) -> resolution_outcome = 'BENIGN', incident_status = 'CLOSED_FP'
   - Ambiguous (< 85%)         -> triage_status = 'GROUNDTRUTH', ground_truth_status = 'ACT NEED'
3. Reconstructs Threat Campaigns STRICTLY FROM CONFIRMED THREAT TICKETS ONLY.
4. Generates Executive Forensic Summaries with Local Foundation LLM.
"""

import sys
import os
import time
import psycopg2
import psycopg2.extras
from datetime import datetime, timezone
from collections import defaultdict

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, PROJECT_ROOT)

import config.settings as s
from pipeline.ml_classifier import evaluate_cascading_pipeline
from pipeline.campaign_clustering import ThreatCampaignClusterer
from scripts.ops.generate_campaign_executive_summaries import generate_summaries

def sync_pipeline():
    print("=" * 80)
    print("   PENYELARASAN STATUS THREAT TIKET & THREAT CAMPAIGNS")
    print(f"   Target DB: {s.DB_HOST}:{s.DB_PORT}/{s.DB_NAME}")
    print("=" * 80)

    t0 = time.time()
    conn = psycopg2.connect(
        host=s.DB_HOST, port=s.DB_PORT, dbname=s.DB_NAME, user=s.DB_USER, password=s.DB_PASSWORD
    )
    conn.autocommit = False
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    try:
        # 1. Fetch all P0, P1, P2 tickets
        print("\n[LANGKAH 1/4] Mengambil seluruh tiket P0, P1, dan P2 untuk evaluasi AI Triase...")
        cur.execute("""
            SELECT q.triage_id, q.priority, q.triage_status, i.*
            FROM soc_ops.soc_triage_queue q
            JOIN correlation.correlated_incidents i ON q.incident_id = i.incident_id
            WHERE q.priority IN ('P0', 'P1', 'P2')
            ORDER BY 
                CASE q.priority WHEN 'P0' THEN 1 WHEN 'P1' THEN 2 WHEN 'P2' THEN 3 ELSE 4 END,
                q.created_at ASC;
        """)
        threat_candidate_tickets = cur.fetchall()
        total_candidates = len(threat_candidate_tickets)
        print(f"   -> Ditemukan {total_candidates} tiket berprioritas P0/P1/P2.")

        # Pre-fetch all stages
        print("\n[LANGKAH 2/4] Mengeksekusi Cascading AI Triase (Tier-1 ML / Tier-2 Foundation LLM)...")
        cur.execute("""
            SELECT incident_id, sequence_order, stage_name, stage_description, reference_id
            FROM correlation.incident_stages
            ORDER BY incident_id, sequence_order;
        """)
        stages_by_inc = defaultdict(list)
        for s_row in cur.fetchall():
            stages_by_inc[s_row["incident_id"]].append(dict(s_row))

        threat_count = 0
        benign_count = 0
        groundtruth_count = 0

        threat_updates_queue = []
        threat_updates_inc = []
        benign_updates_queue = []
        benign_updates_inc = []
        gt_updates_queue = []

        for idx, row in enumerate(threat_candidate_tickets, 1):
            inc = dict(row)
            inc_id = inc["incident_id"]
            inc["stages"] = stages_by_inc.get(inc_id, [])

            # Run Tier-1 / Tier-2 evaluation
            cascade_res = evaluate_cascading_pipeline(inc)
            decision = cascade_res.get("decision")
            tier = cascade_res.get("active_tier", "Tier-1 ML")
            conf = float(cascade_res.get("final_confidence", 0.0))
            reasoning = cascade_res.get("reasoning", "")
            verdict = cascade_res.get("final_verdict", "BENIGN")

            if decision == "CREATE_IRIS_CASE" or verdict == "THREAT":
                threat_count += 1
                reason = f"Threat detected by {tier} ({conf:.1f}%): {reasoning}"
                threat_updates_queue.append((reason, inc_id))
                threat_updates_inc.append((inc_id,))
            elif decision in ("AUTO_CLOSE", "AUTO_SUPPRESS"):
                benign_count += 1
                reason = f"Auto-closed by {tier} ({conf:.1f}% confidence Benign): {reasoning}"
                benign_updates_queue.append((f"ai_cascade_{tier}", reason, inc_id))
                benign_updates_inc.append((inc_id,))
            else:
                groundtruth_count += 1
                reason = f"Inconclusive ({conf:.1f}%): {reasoning}"
                gt_updates_queue.append((reason, inc_id))

            if idx % 200 == 0 or idx == total_candidates:
                print(f"   [{idx}/{total_candidates}] Diproses -> Threat: {threat_count}, Benign: {benign_count}, Review: {groundtruth_count}")

        # Batch execute updates
        if threat_updates_queue:
            psycopg2.extras.execute_batch(cur, """
                UPDATE soc_ops.soc_triage_queue
                SET triage_status = 'CLOSE',
                    resolution_outcome = 'TRUE_POSITIVE_ACTIONABLE',
                    is_verified_true_positive = TRUE,
                    assigned_analyst = 'iris_orchestrator',
                    false_positive_reason = %s,
                    ground_truth_status = NULL,
                    resolved_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE incident_id = %s;
            """, threat_updates_queue, page_size=500)

            psycopg2.extras.execute_batch(cur, """
                UPDATE correlation.correlated_incidents
                SET incident_status = 'ESCALATED'
                WHERE incident_id = %s;
            """, threat_updates_inc, page_size=500)

        if benign_updates_queue:
            psycopg2.extras.execute_batch(cur, """
                UPDATE soc_ops.soc_triage_queue
                SET triage_status = 'CLOSE',
                    resolution_outcome = 'BENIGN',
                    is_verified_true_positive = FALSE,
                    assigned_analyst = %s,
                    false_positive_reason = %s,
                    ground_truth_status = NULL,
                    resolved_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE incident_id = %s;
            """, benign_updates_queue, page_size=500)

            psycopg2.extras.execute_batch(cur, """
                UPDATE correlation.correlated_incidents
                SET incident_status = 'CLOSED_FP'
                WHERE incident_id = %s;
            """, benign_updates_inc, page_size=500)

        if gt_updates_queue:
            psycopg2.extras.execute_batch(cur, """
                UPDATE soc_ops.soc_triage_queue
                SET triage_status = 'GROUNDTRUTH',
                    ground_truth_status = 'ACT NEED',
                    resolution_outcome = NULL,
                    assigned_analyst = 'tier1_soc_analyst',
                    false_positive_reason = %s,
                    updated_at = CURRENT_TIMESTAMP
                WHERE incident_id = %s;
            """, gt_updates_queue, page_size=500)

        conn.commit()
        print(f"   [OK] Database Updated: {threat_count} Tiket THREAT, {benign_count} BENIGN, {groundtruth_count} GROUNDTRUTH.")

        # 3. Clean and Rebuild Threat Campaigns STRICTLY FROM THREAT TICKETS
        print("\n[LANGKAH 3/4] Membersihkan Campaign lama & membangun Campaign HANYA dari Tiket THREAT...")
        cur.execute("DELETE FROM correlation.cluster_causality_edges;")
        cur.execute("DELETE FROM correlation.cluster_members;")
        cur.execute("DELETE FROM correlation.threat_campaign_clusters;")
        conn.commit()

        # Query confirmed THREAT pivot incidents
        cur.execute("""
            WITH ranked AS (
                SELECT 
                    i.*, q.triage_id, q.priority as triage_priority,
                    ROW_NUMBER() OVER (
                        PARTITION BY i.target_host 
                        ORDER BY 
                            CASE q.priority WHEN 'P0' THEN 1 WHEN 'P1' THEN 2 WHEN 'P2' THEN 3 ELSE 4 END,
                            i.first_seen_at ASC
                    ) as rn
                FROM correlation.correlated_incidents i
                JOIN soc_ops.soc_triage_queue q ON i.incident_id = q.incident_id
                WHERE q.resolution_outcome = 'TRUE_POSITIVE_ACTIONABLE'
            )
            SELECT * FROM ranked WHERE rn = 1;
        """)
        cols = [desc[0] for desc in cur.description]
        confirmed_threat_pivots = [dict(zip(cols, r)) for r in cur.fetchall()]
        print(f"   -> Ditemukan {len(confirmed_threat_pivots)} host dengan tiket THREAT terkonfirmasi.")

        clusterer = ThreatCampaignClusterer()
        campaigns_created = 0
        for idx, inc in enumerate(confirmed_threat_pivots, 1):
            target = inc.get("target_host")
            prio = inc.get("triage_priority") or inc.get("priority")
            inc["priority"] = prio
            try:
                res = clusterer.cluster_threat_campaign(inc, lookback_hours=72)
                cid = res.get("cluster_id")
                ics = res.get("causality_dag", {}).get("incident_confidence_score", 0)
                iss = res.get("causality_dag", {}).get("incident_severity_score", 0)
                campaigns_created += 1
                print(f"      [{idx}/{len(confirmed_threat_pivots)}] Campaign {cid} pada {target}: Prioritas {prio}, ICS={ics}%, ISS={iss}")
            except Exception as e_c:
                print(f"      [-] Warning campaign {target}: {e_c}")

        conn.commit()
        print(f"   [OK] Berhasil merekonstruksi {campaigns_created} Campaign murni dari Tiket THREAT.")

        # 4. Generate Executive Summaries for Campaigns
        if campaigns_created > 0:
            print("\n[LANGKAH 4/4] Menghasilkan Executive Forensic Summary...")
            generate_summaries()
            print("   [OK] Executive Summaries berhasil digenerate.")
        else:
            print("\n[LANGKAH 4/4] Tidak ada campaign yang perlu disintesis summary.")

        elapsed = round(time.time() - t0, 2)
        print("\n" + "=" * 80)
        print(f"[+] PENYELARASAN SELESAI & SINKRON 100% DALAM {elapsed} DETIK!")
        print("=" * 80)

    except Exception as e:
        conn.rollback()
        print(f"\n[-] ERROR fatal pada sinkronisasi: {e}")
        import traceback
        traceback.print_exc()
        raise
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    sync_pipeline()
