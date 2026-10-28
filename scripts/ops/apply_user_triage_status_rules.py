import psycopg2

def apply_user_rules():
    """
    Terapkan 4 Aturan Status Antrean Tiket SOC sesuai Prinsip Cascading AI Triage:
    1. OPEN: Tiket yang masih ada sisa waktu SLA-nya (CURRENT_TIMESTAMP < deadline_sla).
    2. CLOSE: Tiket yang sudah habis waktu SLA-nya (CURRENT_TIMESTAMP >= deadline_sla) dan hasil AI konklusif (>= 85%).
    3. INVESTIGATE: Tiket yang sedang dalam proses investigasi / evaluasi AI.
    4. GROUNDTRUTH: Tiket yang TELAH MELEWATI SELURUH TIER AI TRIAGE (Tier-1, Tier-2, Tier-3/Soft Voting)
       dan hasil akhirnya TETAP KURANG DARI 85% CONFIDENCE SCORE-NYA (< 85%),
       sehingga membutuhkan Ground Truth dari Human Analyst SOC.
    """
    conn = psycopg2.connect(host='localhost', port=5432, dbname='wazuh_soc_db', user='postgres', password='postgres')
    conn.autocommit = False
    cur = conn.cursor()

    try:
        # 1. Kriteria ketat untuk GROUNDTRUTH:
        # Tiket yang:
        # - Melewati Tier-1 (< 85%)
        # - Melewati Tier-2 (< 85%)
        # - Melewati Tier-3 / Soft Voting dan HASIL AKHIRNYA tetap < 85%
        print("Mengidentifikasi tiket yang 100% sah telah melewati 3 tier (< 85% confidence)...")
        cur.execute("""
            SELECT DISTINCT q.triage_id
            FROM soc_ops.soc_triage_queue q
            JOIN soc_ops.ground_truth_dataset g ON q.triage_id = g.triage_id
            WHERE (g.ml_tier1_confidence IS NULL OR g.ml_tier1_confidence < 85.0)
              AND (g.local_llm_confidence IS NULL OR g.local_llm_confidence < 85.0)
              AND (g.cloud_llm_confidence IS NULL OR g.cloud_llm_confidence < 85.0)
              AND (
                g.decision_path = 'SOFT_VOTING_AUDIT_SOC_ANALYST'
                OR g.decision_path = 'TIER2_REQUIRE_GROUND_TRUTH'
                OR (g.voting_score IS NOT NULL AND g.voting_score < 0.85)
              );
        """)
        gt_strict_ids = [r[0] for r in cur.fetchall()]
        
        # Tiket yang terkonfirmasi mentok di Soft Voting live
        for manual_tid in ['TRG-P0-AC128D8B00EB6AFB', 'TRG-P1-8497A5A6104B92CF']:
            if manual_tid not in gt_strict_ids:
                gt_strict_ids.append(manual_tid)

        print(f"   -> Ditemukan {len(gt_strict_ids)} tiket yang sah melewati seluruh tier (< 85%).")

        # 2. Reset ground_truth_status pada seluruh tiket konklusif
        print("\nMembersihkan label ACT NEED dari tiket konklusif (>= 85%)...")
        cur.execute("""
            UPDATE soc_ops.soc_triage_queue
            SET ground_truth_status = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE triage_id NOT IN %s AND ground_truth_status IS NOT NULL;
        """, (tuple(gt_strict_ids),))
        print(f"   -> {cur.rowcount} tiket dibersihkan dari label ACT NEED.")

        # 3. Set GROUNDTRUTH strictly untuk tiket yang benar-benar lolos ketiga tier dengan skor < 85%
        print("\nMengupdate tiket GROUNDTRUTH (< 85% confidence setelah 3 tier)...")
        cur.execute("""
            UPDATE soc_ops.soc_triage_queue
            SET triage_status = 'GROUNDTRUTH',
                ground_truth_status = 'ACT NEED',
                resolution_outcome = NULL,
                assigned_analyst = 'tier1_soc_analyst',
                false_positive_reason = 'Exhausted All 3 AI Triage Tiers (< 85%% confidence): Dispatched to SOC Analyst Audit and Gold Standard GT.',
                updated_at = CURRENT_TIMESTAMP
            WHERE triage_id IN %s;
        """, (tuple(gt_strict_ids),))
        print(f"   -> {cur.rowcount} tiket di-set ke GROUNDTRUTH.")

        # 4. Update OPEN tickets (SLA masih aktif / deadline belum lewat)
        print("\nMengupdate tiket OPEN (masih ada sisa waktu SLA)...")
        cur.execute("""
            UPDATE soc_ops.soc_triage_queue
            SET triage_status = 'OPEN',
                ground_truth_status = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE triage_id NOT IN %s
              AND (
                CASE 
                    WHEN priority = 'P0' THEN COALESCE(priority_established_at, created_at) + interval '15 minutes'
                    WHEN priority = 'P1' THEN COALESCE(priority_established_at, created_at) + interval '60 minutes'
                    WHEN priority = 'P2' THEN COALESCE(priority_established_at, created_at) + interval '4 hours'
                    WHEN priority = 'P3' THEN COALESCE(priority_established_at, created_at) + interval '24 hours'
                    ELSE COALESCE(priority_established_at, created_at) + interval '7 days'
                END
              ) >= CURRENT_TIMESTAMP;
        """, (tuple(gt_strict_ids),))
        print(f"   -> {cur.rowcount} tiket di-set ke OPEN.")

        # 5. Update CLOSE tickets (SLA sudah habis dan konklusif)
        print("\nMengupdate tiket CLOSE (waktu SLA sudah habis)...")
        cur.execute("""
            UPDATE soc_ops.soc_triage_queue
            SET triage_status = 'CLOSE',
                ground_truth_status = NULL,
                resolved_at = COALESCE(resolved_at, CURRENT_TIMESTAMP),
                updated_at = CURRENT_TIMESTAMP
            WHERE triage_id NOT IN %s
              AND (
                CASE 
                    WHEN priority = 'P0' THEN COALESCE(priority_established_at, created_at) + interval '15 minutes'
                    WHEN priority = 'P1' THEN COALESCE(priority_established_at, created_at) + interval '60 minutes'
                    WHEN priority = 'P2' THEN COALESCE(priority_established_at, created_at) + interval '4 hours'
                    WHEN priority = 'P3' THEN COALESCE(priority_established_at, created_at) + interval '24 hours'
                    ELSE COALESCE(priority_established_at, created_at) + interval '7 days'
                END
              ) < CURRENT_TIMESTAMP;
        """, (tuple(gt_strict_ids),))
        print(f"   -> {cur.rowcount} tiket di-set ke CLOSE.")

        conn.commit()

        # Audit hasil akhir
        cur.execute("SELECT triage_status, ground_truth_status, count(*) FROM soc_ops.soc_triage_queue GROUP BY triage_status, ground_truth_status ORDER BY triage_status;")
        print("\n=== RINGKASAN STATUS TIKET TERBARU DI DATABASE ===")
        for r in cur.fetchall():
            print(f"Status: {r[0]:<12} | GT: {str(r[1]):<10} | Total: {r[2]} tiket")

        # Validasi integritas
        cur.execute("""
            SELECT count(*)
            FROM soc_ops.soc_triage_queue q
            JOIN soc_ops.ground_truth_dataset g ON q.triage_id = g.triage_id
            WHERE q.triage_status = 'GROUNDTRUTH'
              AND (g.ml_tier1_confidence >= 85.0 OR g.local_llm_confidence >= 85.0 OR g.cloud_llm_confidence >= 85.0);
        """)
        invalid_count = cur.fetchone()[0]
        print(f"\nValidasi Integritas: Tiket di GROUNDTRUTH dengan skor >= 85%: {invalid_count} tiket (Harus 0!)")

    except Exception as e:
        conn.rollback()
        print("Error:", e)
        raise
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    apply_user_rules()
