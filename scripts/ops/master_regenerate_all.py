#!/usr/bin/env python3
"""
Master Regeneration Pipeline: Alert -> Cluster -> Kategori -> Korelasi/Tiket -> Insiden -> Campaign
==================================================================================================
Eksekusi regenerasi menyeluruh dengan logic, taxonomy, scoring deterministik,
deduplikasi entitas, ICS/ISS, dan Executive Summary terbaru.
"""

import sys
import os
import time
import psycopg2
import psycopg2.extras
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List
from collections import defaultdict

# Setup python path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, PROJECT_ROOT)

import config.settings as s
from pipeline.score import PriorityEngine, SLA_MATRIX_MINUTES, _normalize_category
from pipeline.campaign_clustering import ThreatCampaignClusterer

def run_master_pipeline():
    print("=" * 90)
    print("   MEMULAI REGENERASI MENYELURUH PIPELINE SOC (VERSI 3)")
    print("   Alert -> Cluster -> Kategori -> Korelasi/Tiket -> Insiden -> Campaign")
    print(f"   Target DB: {s.DB_HOST}:{s.DB_PORT}/{s.DB_NAME} (User: {s.DB_USER})")
    print("=" * 90)

    t_start = time.time()
    conn = psycopg2.connect(
        host=s.DB_HOST, port=s.DB_PORT, dbname=s.DB_NAME, user=s.DB_USER, password=s.DB_PASSWORD
    )
    conn.autocommit = False
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    engine = PriorityEngine()

    try:
        # ---------------------------------------------------------------------
        # TAHAP 1: KATEGORI & AGREGAT ALERTS (suppression.aggregated_alerts)
        # ---------------------------------------------------------------------
        print("\n[TAHAP 1/5] Memperbarui Kategori & Agregat Alerts...")
        cur.execute("""
            UPDATE suppression.aggregated_alerts
            SET category = 'SYSTEM_HEALTH'
            WHERE rule_id IN (40704, 40701, 12109, 50120, 50520, 50521, 60746, 60969);
        """)
        c_health = cur.rowcount

        cur.execute("""
            UPDATE suppression.aggregated_alerts
            SET category = 'COMPLIANCE'
            WHERE rule_id IN (40700, 2904, 2932, 63105, 83202);
        """)
        c_comp = cur.rowcount
        print(f"  [OK] {c_health} alert diarahkan ke SYSTEM_HEALTH, {c_comp} ke COMPLIANCE.")

        # ---------------------------------------------------------------------
        # TAHAP 2: FORENSIC STAGES (correlation.incident_stages)
        # ---------------------------------------------------------------------
        print("\n[TAHAP 2/5] Memperbarui Tahapan Forensik (incident_stages)...")
        cur.execute("""
            UPDATE correlation.incident_stages
            SET stage_name = 'SYSTEM_HEALTH'
            WHERE stage_name = 'PERSISTENCE'
              AND (
                stage_description ILIKE '%40704%'
                OR stage_description ILIKE '%systemd%'
                OR reference_id IN (
                    SELECT aggregation_id FROM suppression.aggregated_alerts 
                    WHERE rule_id IN (40704, 40701, 12109, 50120, 50520, 50521, 60746, 60969)
                )
              );
        """)
        c_stg_health = cur.rowcount

        cur.execute("""
            UPDATE correlation.incident_stages
            SET stage_name = 'COMPLIANCE'
            WHERE stage_name = 'PERSISTENCE'
              AND (
                stage_description ILIKE '%dpkg%'
                OR stage_description ILIKE '%package%'
                OR reference_id IN (
                    SELECT aggregation_id FROM suppression.aggregated_alerts 
                    WHERE rule_id IN (40700, 2904, 2932, 63105, 83202)
                )
              );
        """)
        c_stg_comp = cur.rowcount
        print(f"  [OK] {c_stg_health} stages diperbarui ke SYSTEM_HEALTH, {c_stg_comp} ke COMPLIANCE.")

        # ---------------------------------------------------------------------
        # TAHAP 3: KORELASI TIKET & PENENTUAN PRIORITAS (P0 - P4)
        # ---------------------------------------------------------------------
        print("\n[TAHAP 3/5] Menghitung Ulang Prioritas & SLA Seluruh Tiket Insiden...")
        cur.execute("""
            SELECT incident_id, correlation_rule_id, tenant_id, title, narrative, 
                   attacker_source_ip, target_host, detected_at, first_seen_at, last_seen_at
            FROM correlation.correlated_incidents;
        """)
        all_incidents = cur.fetchall()

        cur.execute("""
            SELECT incident_id, sequence_order, stage_name, stage_description, reference_id
            FROM correlation.incident_stages
            ORDER BY incident_id, sequence_order;
        """)
        stages_by_inc = defaultdict(list)
        for s_row in cur.fetchall():
            stages_by_inc[s_row["incident_id"]].append(dict(s_row))

        priority_counter = {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "P4": 0}
        title_updates = []
        p4_queue_updates = []
        other_queue_updates = []

        for inc in all_incidents:
            inc_id = inc["incident_id"]
            inc_dict = dict(inc)
            inc_dict["stages"] = stages_by_inc.get(inc_id, [])

            new_prio, reason, sla_mins = engine.determine_priority(inc_dict)
            priority_counter[new_prio] += 1

            old_title = inc["title"] or ""
            new_title = old_title
            for p_tag in ("P0", "P1", "P2", "P3", "P4"):
                if old_title.startswith(f"[{p_tag}]"):
                    new_title = f"[{new_prio}]" + old_title[4:]
                    break

            title_updates.append((new_title, inc_id))

            if new_prio == "P4":
                p4_queue_updates.append((sla_mins, inc_id))
            else:
                other_queue_updates.append((new_prio, sla_mins, inc_id))

        # Batch update correlated_incidents titles
        psycopg2.extras.execute_batch(cur, """
            UPDATE correlation.correlated_incidents
            SET title = %s
            WHERE incident_id = %s;
        """, title_updates, page_size=500)

        # Batch update P4 queue records
        if p4_queue_updates:
            psycopg2.extras.execute_batch(cur, """
                UPDATE soc_ops.soc_triage_queue
                SET priority = 'P4',
                    sla_deadline = COALESCE(priority_established_at, created_at) + (%s * INTERVAL '1 minute'),
                    ground_truth_status = NULL,
                    resolution_outcome = CASE 
                        WHEN resolution_outcome = 'TRUE_POSITIVE_ACTIONABLE' THEN 'BENIGN'
                        ELSE resolution_outcome
                    END,
                    is_verified_true_positive = FALSE,
                    assigned_analyst = CASE
                        WHEN assigned_analyst = 'iris_orchestrator' THEN 'system_health_filter'
                        ELSE assigned_analyst
                    END,
                    false_positive_reason = 'Operational noise / systemd service failure (P4)',
                    triage_status = CASE
                        WHEN triage_status = 'GROUNDTRUTH' THEN 'OPEN'
                        ELSE triage_status
                    END
                WHERE incident_id = %s;
            """, p4_queue_updates, page_size=500)

        # Batch update other queue records
        if other_queue_updates:
            psycopg2.extras.execute_batch(cur, """
                UPDATE soc_ops.soc_triage_queue
                SET priority = %s,
                    sla_deadline = COALESCE(priority_established_at, created_at) + (%s * INTERVAL '1 minute')
                WHERE incident_id = %s;
            """, other_queue_updates, page_size=500)

        print(f"  [OK] Hasil Sebaran Prioritas Tiket:")
        for p, count in sorted(priority_counter.items()):
            print(f"       * {p}: {count} tiket")

        # ---------------------------------------------------------------------
        # TAHAP 4: DEDUPLIKASI TIKET ENTITAS (Penyerang + Korban + Tenant)
        # ---------------------------------------------------------------------
        print("\n[TAHAP 4/5] Melakukan Deduplikasi Tiket Aktif (Triple Entitas)...")
        cur.execute("""
            SELECT q.incident_id, COALESCE(i.attacker_source_ip, 'none'), i.target_host, i.tenant_id, q.created_at
            FROM soc_ops.soc_triage_queue q
            JOIN correlation.correlated_incidents i ON q.incident_id = i.incident_id
            WHERE q.triage_status = 'OPEN'
            ORDER BY q.created_at ASC;
        """)
        open_rows = cur.fetchall()
        groups = defaultdict(list)
        for inc_id, actor, target, tenant, created_at in open_rows:
            groups[(actor, target, tenant)].append(inc_id)

        merged_tickets = 0
        canonical_tickets = 0
        for (actor, target, tenant), inc_ids in groups.items():
            canonical_id = inc_ids[0]
            canonical_tickets += 1
            duplicate_ids = inc_ids[1:]
            if not duplicate_ids:
                continue

            cur.execute("""
                SELECT COALESCE(MAX(sequence_order), 0)
                FROM correlation.incident_stages
                WHERE incident_id = %s;
            """, (canonical_id,))
            max_seq = cur.fetchone()[0]

            for dup_id in duplicate_ids:
                cur.execute("""
                    SELECT stage_name, reference_id, evidence_type, stage_description
                    FROM correlation.incident_stages
                    WHERE incident_id = %s
                    ORDER BY sequence_order ASC;
                """, (dup_id,))
                dup_stages = cur.fetchall()
                for stg_name, ref_id, ev_type, desc in dup_stages:
                    max_seq += 1
                    cur.execute("""
                        INSERT INTO correlation.incident_stages
                            (incident_id, sequence_order, stage_name, reference_id, evidence_type, stage_description)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (incident_id, sequence_order) DO NOTHING;
                    """, (canonical_id, max_seq, stg_name, ref_id, ev_type, desc))

                cur.execute("""
                    DELETE FROM soc_ops.ticket_aggregates
                    WHERE ticket_id = (SELECT triage_id FROM soc_ops.soc_triage_queue WHERE incident_id = %s)
                      AND aggregation_id IN (
                          SELECT aggregation_id FROM soc_ops.ticket_aggregates
                          WHERE ticket_id = (SELECT triage_id FROM soc_ops.soc_triage_queue WHERE incident_id = %s)
                      );
                """, (dup_id, canonical_id))
                cur.execute("""
                    UPDATE soc_ops.ticket_aggregates
                    SET ticket_id = (SELECT triage_id FROM soc_ops.soc_triage_queue WHERE incident_id = %s)
                    WHERE ticket_id = (SELECT triage_id FROM soc_ops.soc_triage_queue WHERE incident_id = %s);
                """, (canonical_id, dup_id))

                cur.execute("""
                    UPDATE soc_ops.soc_triage_queue
                    SET triage_status = 'CLOSE',
                        resolution_outcome = 'OPERATIONAL_NOISE',
                        false_positive_reason = 'Deduplicated: absorbed into active 7-day P4 primary ticket ' || %s
                    WHERE incident_id = %s;
                """, (canonical_id, dup_id))

                cur.execute("""
                    UPDATE correlation.correlated_incidents
                    SET incident_status = 'RESOLVED'
                    WHERE incident_id = %s;
                """, (dup_id,))
                merged_tickets += 1

            cur.execute("""
                SELECT MAX(last_seen_at)
                FROM correlation.correlated_incidents
                WHERE incident_id = ANY(%s);
            """, (inc_ids,))
            max_last = cur.fetchone()[0]
            cur.execute("""
                UPDATE correlation.correlated_incidents
                SET last_seen_at = %s
                WHERE incident_id = %s;
            """, (max_last, canonical_id))

        print(f"  [OK] {merged_tickets} tiket duplikat digabungkan ke {canonical_tickets} tiket aktif utama.")

        # Clean fake samples from ground truth
        cur.execute("""
            DELETE FROM soc_ops.ground_truth_dataset
            WHERE incident_id IN (
                SELECT c.incident_id 
                FROM correlation.correlated_incidents c
                JOIN correlation.incident_stages s ON c.incident_id = s.incident_id
                WHERE s.stage_name = 'SYSTEM_HEALTH' OR s.stage_description ILIKE '%40704%'
            );
        """)
        c_gt = cur.rowcount
        print(f"  [OK] {c_gt} data training noise dibersihkan dari ground_truth_dataset.")

        conn.commit()

        # ---------------------------------------------------------------------
        # TAHAP 5: THREAT CAMPAIGN CLUSTERING & ICS / ISS / SUMMARY
        # ---------------------------------------------------------------------
        print("\n[TAHAP 5/5] Merekonstruksi Seluruh Threat Campaign Clusters...")
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
                WHERE q.priority IN ('P0', 'P1', 'P2')
                  AND i.incident_status != 'RESOLVED'
            )
            SELECT * FROM ranked WHERE rn = 1;
        """)
        cols = [desc[0] for desc in cur.description]
        threat_pivots = [dict(zip(cols, r)) for r in cur.fetchall()]
        print(f"  [i] Ditemukan {len(threat_pivots)} target host ancaman untuk direkonstruksi ke dalam Campaign.")

        clusterer = ThreatCampaignClusterer()
        campaigns_created = 0
        for idx, inc in enumerate(threat_pivots, 1):
            target = inc.get("target_host")
            prio = inc.get("triage_priority") or inc.get("priority")
            inc["priority"] = prio
            try:
                res = clusterer.cluster_threat_campaign(inc, lookback_hours=72)
                cid = res.get("cluster_id")
                ics = res.get("causality_dag", {}).get("incident_confidence_score", 0)
                iss = res.get("causality_dag", {}).get("incident_severity_score", 0)
                campaigns_created += 1
                if idx <= 5 or idx == len(threat_pivots):
                    print(f"      [{idx}/{len(threat_pivots)}] {cid} pada {target}: Prioritas {prio}, ICS={ics}%, ISS={iss}")
            except Exception as e_c:
                print(f"      [-] Warning campaign {target}: {e_c}")

        print(f"  [OK] Berhasil merekonstruksi {campaigns_created} Threat Campaign Clusters.")

        # Populate narrative summaries
        print("\n[*] Menghasilkan Executive Forensic Summary untuk semua Threat Campaign...")
        from scripts.ops.generate_campaign_executive_summaries import generate_summaries
        generate_summaries()
        print("  [OK] Executive Summaries berhasil digenerate & diperbarui.")

        elapsed = round(time.time() - t_start, 2)
        print("\n" + "=" * 90)
        print(f"[+] REGENERASI MENYELURUH SELESAI DALAM {elapsed} DETIK!")
        print("=" * 90)

    except Exception as e:
        conn.rollback()
        print(f"\n[-] ERROR fatal pada regenerasi pipeline: {e}")
        import traceback
        traceback.print_exc()
        raise
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    run_master_pipeline()
