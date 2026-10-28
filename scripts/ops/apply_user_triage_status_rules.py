import psycopg2

gt_36_ids = [
    'TRG-P0-75CCEB043F6FD76F', 'TRG-P0-ED2A9C9B1BF4ED61', 'TRG-P0-FC0F2063FAA4AEDE',
    'TRG-P0-BFF44C5D80F158E1', 'TRG-P0-6DA3A688886ABFC0', 'TRG-P4-F7BAC4A9AB544C98',
    'TRG-P0-10F646D70F5D57C5', 'TRG-P0-AC128D8B00EB6AFB', 'TRG-P0-E3ECD6FDEDBFE3FA',
    'TRG-P4-E2E095F993C56249', 'TRG-P4-818A67790E00258D', 'TRG-P4-16600D942968A2EF',
    'TRG-P4-41E1CE6CC888579E', 'TRG-P3-AD931538FABDCC28', 'TRG-P4-1300C25533B3C66D',
    'TRG-P4-9C8AB4C16E2F6146', 'TRG-P4-4A8DA3778B01EBED', 'TRG-P4-58C84969925165E5',
    'TRG-P4-481F70E652A5DCEF', 'TRG-P0-6C5B7F050962343C', 'TRG-P4-ED672CD9100A6247',
    'TRG-P0-5BFB83597D69EADC', 'TRG-P0-2B677EE2B2972F5C', 'TRG-P4-6B9F2578E43272CA',
    'TRG-P4-B23D73A83955642A', 'TRG-P4-912E6E08541F9696', 'TRG-P4-762ED07DA41FE016',
    'TRG-P4-267CDEF86D7C7DFA', 'TRG-P3-BBE7B3F716616F60', 'TRG-P4-32C4E52806B74250',
    'TRG-P4-5EFEC93B36262A85', 'TRG-P3-C5B425DFD68F9FC0', 'TRG-P4-ADCE9375CC2386D1',
    'TRG-P4-EECEAC6A4D2595A4', 'TRG-P4-5A96898DBB923A3F', 'TRG-P3-FE9F4DE50C1571D7'
]

def apply_user_rules():
    conn = psycopg2.connect(host='localhost', port=5432, dbname='wazuh_soc_db', user='postgres', password='postgres')
    conn.autocommit = False
    cur = conn.cursor()

    try:
        # 1. Update GROUNDTRUTH tickets (< 85% confidence score from AI Triage)
        print("Mengupdate tiket Ground Truth (< 85% confidence)...")
        cur.execute("""
            UPDATE soc_ops.soc_triage_queue
            SET triage_status = 'GROUNDTRUTH',
                ground_truth_status = 'ACT NEED',
                resolution_outcome = NULL,
                assigned_analyst = 'tier1_soc_analyst',
                false_positive_reason = 'Inconclusive / Ambiguous (< 85%%): Dispatched to SOC Analyst Audit and Gold Standard GT.',
                updated_at = CURRENT_TIMESTAMP
            WHERE triage_id IN %s;
        """, (tuple(gt_36_ids),))
        gt_count = cur.rowcount
        print(f"   -> {gt_count} tiket di-set ke GROUNDTRUTH.")

        # 2. Update OPEN tickets (SLA masih aktif / deadline belum lewat)
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
        """, (tuple(gt_36_ids),))
        open_count = cur.rowcount
        print(f"   -> {open_count} tiket di-set ke OPEN.")

        # 3. Update CLOSE tickets (SLA sudah habis dan tidak ada kluster/agregat nyangkut)
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
        """, (tuple(gt_36_ids),))
        close_count = cur.rowcount
        print(f"   -> {close_count} tiket di-set ke CLOSE.")

        conn.commit()

        # Print summary
        cur.execute("SELECT triage_status, count(*) FROM soc_ops.soc_triage_queue GROUP BY triage_status ORDER BY triage_status;")
        print("\n=== RINGKASAN STATUS TIKET TERBARU DI DATABASE ===")
        for r in cur.fetchall():
            print(f"Status: {r[0]:<15} | Total: {r[1]} tiket")

    except Exception as e:
        conn.rollback()
        print("Error:", e)
        raise
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    apply_user_rules()
