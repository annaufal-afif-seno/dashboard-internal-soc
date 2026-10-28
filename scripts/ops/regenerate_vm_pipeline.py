#!/usr/bin/env python3
"""
Regenerate VM Pipeline Database Records
========================================
Reclassifies all incidents, aggregates, stages, and triage records based on:
1. Updated category & subcategory mappings (Rule 40704 and system rules -> SYSTEM_HEALTH / P4)
2. PriorityEngine.determine_priority() deterministic scoring (PRD Section 8)
3. Fast batch execution via psycopg2.extras.execute_batch
"""

import sys
import os
import time
import psycopg2
import psycopg2.extras
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from pipeline.score import PriorityEngine, SLA_MATRIX_MINUTES

def run_regeneration(db_url: str):
    print("=" * 80)
    print("[*] MEMULAI REGENERASI DATABASE VM SESUAI TAXONOMY & ATURAN SISTEM BARU")
    print(f"[*] Target DB: {db_url}")
    print("=" * 80)

    t0 = time.time()
    conn = psycopg2.connect(db_url)
    conn.autocommit = False
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    engine = PriorityEngine()

    try:
        # Step 1: Update suppression.aggregated_alerts
        print("\n[*] Langkah 1: Memperbarui kategori di suppression.aggregated_alerts...")
        cur.execute("""
            UPDATE suppression.aggregated_alerts
            SET category = 'SYSTEM_HEALTH'
            WHERE rule_id IN (40704, 40701, 12109, 50120, 50520, 50521, 60746, 60969);
        """)
        c1 = cur.rowcount
        cur.execute("""
            UPDATE suppression.aggregated_alerts
            SET category = 'COMPLIANCE'
            WHERE rule_id IN (40700, 2904, 2932, 63105, 83202);
        """)
        c2 = cur.rowcount
        print(f"    -> {c1} baris diupdate ke SYSTEM_HEALTH, {c2} baris ke COMPLIANCE.")

        # Step 2: Update correlation.incident_stages
        print("\n[*] Langkah 2: Memperbarui correlation.incident_stages untuk systemd & rule non-attack...")
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
        c_stages = cur.rowcount

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
        c_stages2 = cur.rowcount
        print(f"    -> {c_stages} stages ke SYSTEM_HEALTH, {c_stages2} stages ke COMPLIANCE.")

        # Step 3: Fetch all correlated incidents and re-score with PriorityEngine
        print("\n[*] Langkah 3: Menghitung ulang prioritas seluruh incident...")
        cur.execute("""
            SELECT incident_id, correlation_rule_id, tenant_id, title, narrative, 
                   attacker_source_ip, target_host, detected_at, first_seen_at, last_seen_at
            FROM correlation.correlated_incidents;
        """)
        all_incidents = cur.fetchall()
        print(f"    -> Ditemukan {len(all_incidents)} incident untuk dievaluasi ulang.")

        # Pre-fetch all stages grouped by incident_id
        cur.execute("""
            SELECT incident_id, sequence_order, stage_name, stage_description, reference_id
            FROM correlation.incident_stages
            ORDER BY incident_id, sequence_order;
        """)
        all_stages = cur.fetchall()
        stages_by_inc = {}
        for s in all_stages:
            inc_id = s["incident_id"]
            if inc_id not in stages_by_inc:
                stages_by_inc[inc_id] = []
            stages_by_inc[inc_id].append(dict(s))

        priority_counter = {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "P4": 0}
        downgraded_p0_to_p4 = 0

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
            if old_title.startswith("[P0]") and new_prio != "P0":
                new_title = f"[{new_prio}]" + old_title[4:]
                downgraded_p0_to_p4 += 1
            elif old_title.startswith("[P1]") and new_prio != "P1":
                new_title = f"[{new_prio}]" + old_title[4:]
            elif old_title.startswith("[P2]") and new_prio != "P2":
                new_title = f"[{new_prio}]" + old_title[4:]
            elif old_title.startswith("[P3]") and new_prio != "P3":
                new_title = f"[{new_prio}]" + old_title[4:]
            elif old_title.startswith("[P4]") and new_prio != "P4":
                new_title = f"[{new_prio}]" + old_title[4:]

            title_updates.append((new_title, inc_id))

            if new_prio == "P4":
                p4_queue_updates.append((sla_mins, inc_id))
            else:
                other_queue_updates.append((new_prio, sla_mins, inc_id))

        # Batch update titles
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

        print(f"    -> Hasil re-kalkulasi prioritas:")
        for p, count in priority_counter.items():
            print(f"       * {p}: {count} tiket")
        print(f"    -> Tiket palsu P0 yang berhasil diturunkan ke P4: {downgraded_p0_to_p4}")

        # Step 4: Clean up ground_truth_dataset
        print("\n[*] Langkah 4: Membersihkan data training palsu dari soc_ops.ground_truth_dataset...")
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
        print(f"    -> Dihapus {c_gt} baris systemd/noise dari ground_truth_dataset.")

        conn.commit()
        elapsed = round(time.time() - t0, 2)
        print(f"\n[+] REGENERASI DATABASE VM SELESAI & BERHASIL DI-COMMIT DALAM {elapsed} DETIK!")

    except Exception as e:
        conn.rollback()
        print(f"\n[-] ERROR saat regenerasi database: {e}")
        raise
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    db_conn_str = os.getenv("DB_CONNECTION_STRING", "postgresql://postgres:postgres@localhost:5432/wazuh_soc_db")
    run_regeneration(db_conn_str)
