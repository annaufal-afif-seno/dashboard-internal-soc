import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import time
import psycopg2
from collections import Counter
from datetime import timedelta
from typing import Dict, Any, List

from config.settings import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
from pipeline.score import RiskScorer
from pipeline.ml_classifier import evaluate_cascading_pipeline, LightGBMIncidentClassifier

SLA_MAP = {
    "P0": timedelta(minutes=15),
    "P1": timedelta(minutes=60),
    "P2": timedelta(hours=4),
    "P3": timedelta(days=1),
    "P4": timedelta(days=7),
}

PRIORITY_RANK = {"P4": 0, "P3": 1, "P2": 2, "P1": 3, "P0": 4}

def load_reconstructed_tickets() -> List[Dict[str, Any]]:
    conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, database=DB_NAME, user=DB_USER, password=DB_PASSWORD)
    cur = conn.cursor()

    cur.execute("""
        SELECT 
            i.incident_id,
            COALESCE(i.attacker_source_ip, 'UNKNOWN') AS actor,
            COALESCE(i.target_host, 'UNKNOWN') AS target,
            COALESCE(i.tenant_id, 'DEFAULT') AS tenant,
            i.first_seen_at,
            i.last_seen_at,
            i.title,
            i.narrative,
            i.correlation_rule_id
        FROM correlation.correlated_incidents i
        WHERE i.first_seen_at IS NOT NULL
        ORDER BY i.first_seen_at ASC;
    """)
    incidents = cur.fetchall()

    cur.execute("""
        SELECT incident_id, stage_name, sequence_order
        FROM correlation.incident_stages
        ORDER BY incident_id, sequence_order ASC;
    """)
    stages_by_inc = {}
    for inc_id, s_name, seq in cur.fetchall():
        if inc_id not in stages_by_inc:
            stages_by_inc[inc_id] = []
        stages_by_inc[inc_id].append(s_name)

    cur.close()
    conn.close()

    scorer = RiskScorer()
    tickets = []
    open_tickets = {}

    for r in incidents:
        inc_id, actor, target, tenant, first_seen, last_seen, title, narr, rule = r
        st_list = stages_by_inc.get(inc_id, [])
        key = (actor, target, tenant)

        active_t = open_tickets.get(key)
        if active_t and first_seen <= active_t["expires_at"]:
            active_t["stages"].extend(st_list)
            active_t["last_seen_at"] = max(active_t["last_seen_at"], last_seen or first_seen)
            active_t["stages_count"] = len(active_t["stages"])
            new_p, _, _ = scorer.determine_stateful_priority({"stages": [{"stage_name": s} for s in active_t["stages"]]})
            if PRIORITY_RANK.get(new_p, 0) > PRIORITY_RANK.get(active_t["priority"], 0):
                active_t["priority"] = new_p
                active_t["established_at"] = first_seen
                active_t["expires_at"] = first_seen + SLA_MAP[new_p]
        else:
            init_p, _, _ = scorer.determine_stateful_priority({"stages": [{"stage_name": s} for s in st_list]})
            t = {
                "incident_id": f"TIK-{len(tickets)+1:04d}",
                "actor": actor,
                "target": target,
                "tenant": tenant,
                "attacker_source_ip": actor,
                "target_host": target,
                "title": title or f"Incident on {target}",
                "narrative": narr or "Activity sequence",
                "correlation_rule_id": rule or "CORR-001",
                "priority": init_p,
                "established_at": first_seen,
                "expires_at": first_seen + SLA_MAP[init_p],
                "first_seen_at": first_seen,
                "last_seen_at": last_seen or first_seen,
                "stages": list(st_list),
                "stages_count": len(st_list),
                "total_risk_score": 15.0 if init_p == "P4" else 85.0,
                "rule_level": 3 if init_p == "P4" else 13,
                "threat_intel_match": 0 if init_p == "P4" else 1,
            }
            tickets.append(t)
            open_tickets[key] = t

    return tickets

def run_evaluation():
    tickets = load_reconstructed_tickets()
    print("=" * 80)
    print(f"[*] TOTAL TIKET HASIL REVISI: {len(tickets)} TIKET")
    priority_counts = Counter(t["priority"] for t in tickets)
    print(f"    Distribusi: {dict(priority_counts)}")
    print("=" * 80)

    # 1. Evaluasi Cepat dengan Tier-1 ML
    print(f"\n[+] TAHAP 1: Menjalankan Tier-1 ML (LightGBM) untuk Seluruh {len(tickets):,} Tiket 3 Bulan Reconstructed...")
    clf = LightGBMIncidentClassifier()
    t0 = time.time()
    
    tier1_decided = []
    need_local_llm = []

    for t in tickets:
        ml_res = clf.predict_incident(t)
        t["tier1_ml"] = ml_res
        conf = float(ml_res["confidence"])
        verdict = ml_res["verdict"]

        if conf >= 85.0:
            decision = "AUTO_CLOSE" if verdict == "BENIGN" else "CREATE_IRIS_CASE"
            tier1_decided.append({
                "ticket": t,
                "active_tier": "Tier-1 ML",
                "decision": decision,
                "verdict": verdict,
                "confidence": conf
            })
        else:
            need_local_llm.append(t)

    t_ml = time.time() - t0
    print(f"[OK] Tier-1 ML Selesai dalam {t_ml:.2f} detik ({t_ml/len(tickets)*1000:.2f} ms/tiket)!")
    print(f"    - Selesai di Tier-1 ML (Conf >= 85%): {len(tier1_decided)} tiket ({len(tier1_decided)/len(tickets)*100:.1f}%)")
    print(f"    - Ambigu / Masuk ke Tier-2 Local LLM (Conf < 85%): {len(need_local_llm)} tiket ({len(need_local_llm)/len(tickets)*100:.1f}%)")

    # Tampilkan rincian Tier-1 Decisions
    t1_decisions = Counter(d["decision"] for d in tier1_decided)
    print(f"    - Keputusan Tier-1 ML: {dict(t1_decisions)}")

    # 2. Evaluasi Tiket yang masuk ke Tier-2 Local LLM & Tier-3 Cloud LLM
    print(f"\n[+] TAHAP 2 & 3: Menjalankan Cascading Pipeline (Local LLM & Cloud Soft Voting) untuk {len(need_local_llm)} Tiket Ambigu...")
    
    # Untuk menjalankan secara efisien dan representatif:
    # Kita proses sampel lengkap per prioritas dari tiket yang ambigu
    cascaded_results = []
    
    # Group ambigu by priority
    amb_by_p = {}
    for t in need_local_llm:
        p = t["priority"]
        if p not in amb_by_p:
            amb_by_p[p] = []
        amb_by_p[p].append(t)

    print("    Rincian tiket ambigu per prioritas:")
    for p, items in amb_by_p.items():
        print(f"      * {p}: {len(items)} tiket")

    # Jalankan evaluasi cascading penuh pada sampel representatif (atau semua jika memungkinkan)
    # Ambil hingga 30 sampel representatif lintas prioritas agar waktu eksekusi tetap terkendali (~2-3 menit)
    sample_to_run = []
    for p, items in amb_by_p.items():
        sample_to_run.extend(items[:15])  # ambil 15 sampel tiap prioritas
    
    print(f"\n[*] Mengeksekusi {len(sample_to_run)} sampel live melalui Ollama (Local) & Gemini (Cloud Soft Voting)...")
    
    for idx, t in enumerate(sample_to_run, 1):
        t_start = time.time()
        res = evaluate_cascading_pipeline(t)
        elapsed = time.time() - t_start
        cascaded_results.append({
            "ticket_id": t["incident_id"],
            "priority": t["priority"],
            "active_tier": res.get("active_tier"),
            "decision": res.get("decision"),
            "verdict": res.get("final_verdict"),
            "confidence": res.get("final_confidence"),
            "voting_score": res.get("voting_score"),
            "gt_target": res.get("ground_truth_target"),
            "elapsed": elapsed
        })
        print(f"  [{idx}/{len(sample_to_run)}] {t['incident_id']} ({t['priority']}) -> {res.get('active_tier')} | {res.get('decision')} {res.get('final_verdict')} ({res.get('final_confidence')}%) [{elapsed:.1f}s]")

    print("\n" + "=" * 80)
    print("RINGKASAN HASIL EVALUASI CASCADING AI PIPELINE:")
    print("=" * 80)
    c_decisions = Counter(r["decision"] for r in cascaded_results)
    c_tiers = Counter(r["active_tier"] for r in cascaded_results)
    c_gt = Counter(r["gt_target"] for r in cascaded_results)

    print(f"Keputusan Akhir pada Sampel Cascaded: {dict(c_decisions)}")
    print(f"Tier yang Menangani: {dict(c_tiers)}")
    print(f"Ground Truth Dihasilkan: {dict(c_gt)}")
    print("=" * 80)

if __name__ == "__main__":
    run_evaluation()
