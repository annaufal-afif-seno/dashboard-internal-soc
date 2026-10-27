"""
Optimized Fast Bulk Correlation & Ticket Ingestion Engine (Version 6 Pure Categories & Subcategories)
===================================================================================================
Executes the exact specification:
1. 6 Pure Categories with Functional Subcategories:
   - Identity / Access (Auth Success, Auth Failure, Auth Anomaly, Privilege Escalation)
   - Attack (Web Attack, Exploitation / RCE, Recon / Scan, Command & Control, Lateral Movement)
   - Vulnerability (CVE Detected, Missing Patch / Outdated)
   - Configuration / Compliance (SCA / CIS Benchmark, File Integrity (FIM), Policy Violation)
   - Malware (Ransomware, Rootkit / Backdoor, Virus / Trojan (YARA))
   - System / Availability (Web Operational, Service Health / Error, Cloud / Container Event)
2. Stateful Priority & Dynamic SLA Stopwatch:
   - P0 (15m): Auth Success followed by subsequent action / post-exploit
   - P1 (60m): Auth Success (perimeter breached)
   - P2 (4h): Attack / Malware / Auth Anomaly OR Vulnerable target hit by any subsequent action
   - P3 (1d): Target verified with vulnerability / compliance issue
   - P4 (7d): Reconnaissance, probe, web error, failed logins, scanning noise
3. Populates:
   - correlation.correlated_incidents
   - soc_ops.soc_triage_queue
   - soc_ops.ticket_aggregates
   - correlation.incident_stages
   - risk_engine.calculated_risk_scores
"""

import sys
import os
sys.path.insert(0, os.path.abspath("."))
import time
import hashlib
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import psycopg2
from psycopg2.extras import execute_values

from config.settings import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
from pipeline.score import SLA_MATRIX_MINUTES, PRIORITY_RANK

VULN_SUBCATS = frozenset({
    "CVE Detected", "Missing Patch / Outdated", "SCA / CIS Benchmark", "File Integrity (FIM)", "Policy Violation"
})
ATTACK_SUBCATS = frozenset({
    "Web Attack", "Exploitation / RCE", "Lateral Movement", "Auth Anomaly", "Rootkit / Backdoor", "Ransomware", "Virus / Trojan (YARA)"
})
BREACH_SUBCATS = frozenset({
    "Auth Success", "Command & Control", "Privilege Escalation"
})

def eval_new_cat(state, primary_cat, subcat, rule_id=None, rdesc=""):
    cve_seen = state["cve_seen"]
    cve_idx = state["cve_idx"]
    breach_seen = state["breach_seen"]
    breach_idx = state["breach_idx"]
    attack = state["attack"]
    post_exploit = state["post_exploit"]
    n = state["n"] + 1

    cat = (primary_cat or "").strip()
    sub = (subcat or "").strip()
    desc_l = (rdesc or "").lower()

    is_vuln = (sub in VULN_SUBCATS) or (cat in ("Vulnerability", "Configuration / Compliance"))
    is_attack = (sub in ATTACK_SUBCATS) or (cat in ("Attack", "Malware"))
    is_breach = (sub in BREACH_SUBCATS) or (sub == "Auth Success")

    if is_vuln and not cve_seen:
        cve_seen = True
        cve_idx = n - 1

    if is_attack:
        attack = True

    if is_breach and not breach_seen:
        breach_seen = True
        breach_idx = n - 1

    if sub in ("Privilege Escalation", "Lateral Movement", "Command & Control") or "privilege" in desc_l or "persistence" in desc_l:
        post_exploit = True

    # P0 (15 Menit): Terjadi Breach (AUTH_SUCCESS) diikuti aksi lanjutan apapun, atau Post-Exploit
    if (breach_seen and (n - 1) > breach_idx) or post_exploit:
        new_p, reason = "P0", f"Breach ({sub}) Diikuti Aksi Lanjutan / Post-Exploit"
    # P1 (60 Menit): Terdeteksi Keberhasilan Masuk Perimeter
    elif breach_seen:
        new_p, reason = "P1", f"Keberhasilan Masuk Perimeter ({sub})"
    # P2 (4 Jam): Percobaan Serangan Nyata ATAU Target Vulnerability Diserang Lanjutan
    elif attack or (cve_seen and (n - 1) > cve_idx):
        new_p, reason = "P2", f"Percobaan Serangan Nyata ({cat} / {sub})" if attack else "Target Berstatus Vulnerability Ditembak Lanjutan"
    # P3 (1 Hari): Target Terverifikasi Memiliki Celah
    elif cve_seen:
        new_p, reason = "P3", f"Target Terverifikasi Memiliki Celah ({cat} / {sub})"
    # P4 (7 Hari): Reconnaissance / Probe Coba-coba / Scanning Noise
    else:
        new_p, reason = "P4", f"Reconnaissance / Probe Coba-coba / Noise ({sub})"

    new_state = {
        "cve_seen": cve_seen, "cve_idx": cve_idx,
        "breach_seen": breach_seen, "breach_idx": breach_idx,
        "attack": attack, "post_exploit": post_exploit,
        "n": n
    }
    return new_p, reason, new_state


def main():
    print("=" * 80)
    print("[*] MEMULAI GENERASI TIKET KORELASI (6 KATEGORI & SUBKATEGORI LENGKAP)")
    print("=" * 80)

    t0 = time.time()
    conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD)
    cur = conn.cursor()

    print("[*] 1. Mengambil seluruh 715,183 clusters dari suppression.aggregated_alerts...")
    cur.execute("""
        SELECT aggregation_id, rule_id, primary_category, subcategory, actor, target, tenant_id, window_start, window_end, event_count, rule_description
        FROM suppression.aggregated_alerts
        ORDER BY window_start ASC;
    """)
    rows = cur.fetchall()
    print(f"[+] Loaded {len(rows):,} clusters in {time.time()-t0:.2f}s")

    t1 = time.time()
    print("[*] 2. Menjalankan korelasi linear stateful ticket & dynamic SLA reset...")
    active_tickets = {}
    completed_tickets = []

    for agg in rows:
        agg_id, rid, cat, subcat, actor, target, tenant, w_start, w_end, ev_count, rdesc = agg
        actor_clean = actor or "unknown_actor"
        target_clean = target or "unknown_target"
        tenant_clean = tenant or "DEFAULT"
        key = (actor_clean, target_clean, tenant_clean)

        ticket = active_tickets.get(key)
        if ticket:
            if w_start > ticket["sla_deadline"]:
                completed_tickets.append(ticket)
                ticket = None
                active_tickets.pop(key, None)

        if ticket is None:
            init_state = {
                "cve_seen": False, "cve_idx": -1,
                "breach_seen": False, "breach_idx": -1,
                "attack": False, "post_exploit": False,
                "n": 0
            }
            prio, reason, new_state = eval_new_cat(init_state, cat, subcat, rid, rdesc)
            sla_mins = SLA_MATRIX_MINUTES[prio]
            sla_deadline = w_start + timedelta(minutes=sla_mins)

            inc_hash = hashlib.md5(f"{agg_id}_{actor_clean}_{target_clean}".encode()).hexdigest()[:12]
            incident_id = f"INC-{prio}-{inc_hash.upper()}"
            triage_id = f"TRG-{prio}-{inc_hash.upper()}"

            ticket = {
                "incident_id": incident_id,
                "triage_id": triage_id,
                "key": key,
                "actor": actor_clean,
                "target": target_clean,
                "tenant_id": tenant_clean,
                "induk_agg_id": agg_id,
                "priority": prio,
                "priority_reason": reason,
                "priority_established_at": w_start,
                "sla_deadline": sla_deadline,
                "first_seen_at": w_start,
                "last_seen_at": w_end,
                "window_buffer_until": w_end,
                "event_count": ev_count,
                "state": new_state,
                "rule_desc": rdesc or cat,
                "stages": [
                    {
                        "sequence_order": 1,
                        "stage_name": cat,
                        "reference_id": agg_id,
                        "evidence_type": "AGGREGATED_ALERT",
                        "stage_description": f"Induk ({prio}): {cat} -> {subcat} | {rdesc or cat}",
                        "recorded_at": w_start
                    }
                ],
                "ticket_aggregates": [
                    {
                        "aggregation_id": agg_id,
                        "is_induk": True,
                        "is_escalation_trigger": False,
                        "added_at": w_start
                    }
                ]
            }
            active_tickets[key] = ticket
        else:
            new_p, reason, new_state = eval_new_cat(ticket["state"], cat, subcat, rid, rdesc)
            curr_p = ticket["priority"]
            ticket["state"] = new_state
            ticket["last_seen_at"] = max(ticket["last_seen_at"], w_end)
            ticket["window_buffer_until"] = max(ticket["window_buffer_until"], w_end)
            ticket["event_count"] += ev_count

            is_escalation = PRIORITY_RANK[new_p] > PRIORITY_RANK[curr_p]
            if is_escalation:
                ticket["priority"] = new_p
                ticket["priority_reason"] = reason
                ticket["priority_established_at"] = w_start  # DYNAMIC STOPWATCH RESET!
                ticket["sla_deadline"] = w_start + timedelta(minutes=SLA_MATRIX_MINUTES[new_p])
                
                inc_hash = ticket["incident_id"].split("-", 2)[-1]
                ticket["incident_id"] = f"INC-{new_p}-{inc_hash}"
                ticket["triage_id"] = f"TRG-{new_p}-{inc_hash}"

                ticket["stages"].append({
                    "sequence_order": len(ticket["stages"]) + 1,
                    "stage_name": cat,
                    "reference_id": agg_id,
                    "evidence_type": "AGGREGATED_ALERT",
                    "stage_description": f"Eskalasi {curr_p} -> {new_p}: {cat} -> {subcat} | {reason}",
                    "recorded_at": w_start
                })

            ticket["ticket_aggregates"].append({
                "aggregation_id": agg_id,
                "is_induk": False,
                "is_escalation_trigger": is_escalation,
                "added_at": w_start
            })

    for t in active_tickets.values():
        completed_tickets.append(t)

    print(f"[+] Selesai korelasi dalam {time.time()-t1:.2f}s!")
    print(f"[+] Total Tiket Terbentuk: {len(completed_tickets):,} (dari 715,183 clusters)")

    dist = defaultdict(int)
    for t in completed_tickets:
        dist[t["priority"]] += 1
    for p in ["P0", "P1", "P2", "P3", "P4"]:
        cnt = dist[p]
        pct = (cnt / len(completed_tickets) * 100) if completed_tickets else 0
        sla_str = f"{SLA_MATRIX_MINUTES[p]}m"
        print(f"    Priority {p:<3} (SLA: {sla_str:<6}) : {cnt:>8,} tiket ({pct:>5.2f}%)")

    # 3. Truncate target tables
    print("\n[*] 3. Mengosongkan tabel tiket lama...")
    cur.execute("""
        TRUNCATE TABLE 
            soc_ops.ticket_aggregates,
            correlation.incident_stages,
            risk_engine.calculated_risk_scores,
            soc_ops.soc_triage_queue,
            correlation.correlated_incidents
        CASCADE;
    """)
    conn.commit()
    print("[+] Tabel lama berhasil dikosongkan.")

    # 4. Prepare batch tuples
    t2 = time.time()
    print("\n[*] 4. Menyiapkan data tuple untuk PostgreSQL bulk insert...")
    incident_tuples = []
    triage_tuples = []
    score_tuples = []
    stage_tuples = []
    agg_link_tuples = []

    for t in completed_tickets:
        prio = t["priority"]
        inc_hash = t["incident_id"].split("-", 2)[-1]
        t["incident_id"] = f"INC-{prio}-{inc_hash}"
        t["triage_id"] = f"TRG-{prio}-{inc_hash}"
        inc_id = t["incident_id"]
        trg_id = t["triage_id"]
        actor = t["actor"]
        target = t["target"]
        tenant = t["tenant_id"]
        w_start = t["first_seen_at"]
        w_end = t["last_seen_at"]
        p_est = t["priority_established_at"]
        sla_deadline = t["sla_deadline"]
        w_buffer = t["window_buffer_until"]
        ev_count = t["event_count"]
        rdesc = t["rule_desc"]
        reason = t["priority_reason"]

        actor_trunc = actor[:128]
        target_trunc = target[:128]
        tenant_trunc = tenant[:64]
        title = f"[{prio}] {rdesc} on {target_trunc} by {actor_trunc}"[:255]
        narrative = f"Consolidated security activity on [{target_trunc}] from [{actor_trunc}] ({ev_count} events). Priority: {reason}"

        incident_tuples.append((
            inc_id, "CORR-ENTITY", tenant_trunc, title, narrative, "NETWORK",
            actor_trunc, None, target_trunc, "DETECTED", w_start, w_end, w_start, []
        ))

        triage_tuples.append((
            trg_id, inc_id, None, prio, "OPEN", None, None,
            w_start, w_end, p_est, actor_trunc, target_trunc, tenant_trunc,
            t["induk_agg_id"], sla_deadline, w_buffer, w_start, p_est
        ))

        score_tuples.append((
            inc_id, 0, prio, "v5.0_cat_subcat", p_est
        ))

        for stg in t["stages"]:
            stage_tuples.append((
                inc_id, stg["sequence_order"], stg["stage_name"],
                stg["reference_id"], stg["evidence_type"],
                stg["stage_description"], stg["recorded_at"]
            ))

        for ta in t["ticket_aggregates"]:
            agg_link_tuples.append((
                trg_id, ta["aggregation_id"], ta["is_induk"],
                ta["is_escalation_trigger"], ta["added_at"]
            ))

    print(f"[+] Selesai siapkan data dalam {time.time()-t2:.2f}s:")
    print(f"    - Incidents        : {len(incident_tuples):,} rows")
    print(f"    - Triage Rows      : {len(triage_tuples):,} rows")
    print(f"    - Ticket Aggregates: {len(agg_link_tuples):,} rows")
    print(f"    - Incident Stages  : {len(stage_tuples):,} rows")

    # 5. Bulk insert
    t3 = time.time()
    print("\n[*] 5. Bulk insert ke PostgreSQL...")

    print("    -> Inserting correlation.correlated_incidents...")
    execute_values(
        cur,
        """
        INSERT INTO correlation.correlated_incidents (
            incident_id, correlation_rule_id, tenant_id, title, narrative,
            initial_access_vector, attacker_source_ip, compromised_account,
            target_host, incident_status, first_seen_at, last_seen_at,
            detected_at, related_incident_ids
        ) VALUES %s;
        """,
        incident_tuples,
        page_size=10000
    )
    conn.commit()
    print("       [+] Correlated incidents inserted.")

    print("    -> Inserting soc_ops.soc_triage_queue...")
    execute_values(
        cur,
        """
        INSERT INTO soc_ops.soc_triage_queue (
            triage_id, incident_id, assigned_analyst, priority, triage_status,
            resolution_outcome, false_positive_reason, created_at, updated_at,
            priority_established_at, actor, target, tenant_id,
            induk_aggregation_id, sla_deadline, window_buffer_until,
            first_detected_at, priority_changed_at
        ) VALUES %s;
        """,
        triage_tuples,
        page_size=10000
    )
    conn.commit()
    print("       [+] Triage rows inserted.")

    print("    -> Inserting risk_engine.calculated_risk_scores...")
    execute_values(
        cur,
        """
        INSERT INTO risk_engine.calculated_risk_scores (
            incident_id, total_score, soc_priority, scoring_version, calculated_at
        ) VALUES %s;
        """,
        score_tuples,
        page_size=10000
    )
    conn.commit()
    print("       [+] Risk scores inserted.")

    print("    -> Inserting correlation.incident_stages...")
    execute_values(
        cur,
        """
        INSERT INTO correlation.incident_stages (
            incident_id, sequence_order, stage_name, reference_id,
            evidence_type, stage_description, recorded_at
        ) VALUES %s;
        """,
        stage_tuples,
        page_size=10000
    )
    conn.commit()
    print("       [+] Incident stages inserted.")

    print("    -> Inserting soc_ops.ticket_aggregates...")
    execute_values(
        cur,
        """
        INSERT INTO soc_ops.ticket_aggregates (
            ticket_id, aggregation_id, is_induk, is_escalation_trigger, added_at
        ) VALUES %s
        ON CONFLICT (ticket_id, aggregation_id) DO NOTHING;
        """,
        agg_link_tuples,
        page_size=10000
    )
    conn.commit()
    print("       [+] Ticket aggregates inserted.")

    print("\n[*] 6. Menyegarkan metrics rollup...")
    try:
        from pipeline.database import DatabaseManager
        db = DatabaseManager()
        db.refresh_hourly_overview_rollup()
        print("       [+] Rollup metrics diperbarui.")
    except Exception as e_m:
        print(f"       [-] Rollup note: {e_m}")

    cur.close()
    conn.close()

    total_duration = time.time() - t0
    print("\n" + "=" * 80)
    print(f"[+] REGENERASI TIKET DENGAN SUBKATEGORI SUKSES 100% DALAM {total_duration:.2f} DETIK!")
    print("=" * 80)

if __name__ == "__main__":
    main()
