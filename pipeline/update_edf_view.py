"""
Update Priority Queue View with Earliest Deadline First (EDF) Dynamic SLA Algorithm (Clean ASCII)
"""
import sys
from pathlib import Path
import psycopg2

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import DB_HOST, DB_PORT, DB_USER, DB_PASSWORD

def update_queue_view_edf(db_name="wazuh_soc_db"):
    schema_soc = "soc_ops." if db_name == "wazuh_soc_db" else "public."
    schema_corr = "correlation." if db_name == "wazuh_soc_db" else "public."
    schema_risk = "risk_engine." if db_name == "wazuh_soc_db" else "public."
    
    conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, database=db_name, user=DB_USER, password=DB_PASSWORD)
    cur = conn.cursor()
    
    view_sql = f"""
    DROP VIEW IF EXISTS {schema_soc}v_actionable_triage_queue CASCADE;
    CREATE VIEW {schema_soc}v_actionable_triage_queue AS
    SELECT 
        t.triage_id,
        t.priority,
        i.title AS judul_insiden,
        i.target_host,
        i.attacker_source_ip,
        t.triage_status,
        t.assigned_analyst,
        COALESCE(t.priority_established_at, t.created_at) AS waktu_muncul,
        CASE 
            WHEN t.priority = 'P0' THEN COALESCE(t.priority_established_at, t.created_at) + INTERVAL '15 minutes'
            WHEN t.priority = 'P1' THEN COALESCE(t.priority_established_at, t.created_at) + INTERVAL '60 minutes'
            WHEN t.priority = 'P2' THEN COALESCE(t.priority_established_at, t.created_at) + INTERVAL '4 hours'
            WHEN t.priority = 'P3' THEN COALESCE(t.priority_established_at, t.created_at) + INTERVAL '24 hours'
            ELSE COALESCE(t.priority_established_at, t.created_at) + INTERVAL '7 days'
        END AS batas_deadline_sla,
        CASE 
            WHEN t.priority = 'P0' THEN 'DARURAT TERTINGGI (< 15m)'
            WHEN t.priority = 'P1' THEN 'MENDESAK (< 60m)'
            WHEN t.priority = 'P2' THEN 'REVIEW SHIFT (< 4 Jam)'
            WHEN t.priority = 'P3' THEN 'REVIEW HARIAN (< 24 Jam)'
            ELSE 'REVIEW MINGGUAN (< 7 Hari)'
        END AS target_sla,
        CASE 
            WHEN (CASE 
                    WHEN t.priority = 'P0' THEN COALESCE(t.priority_established_at, t.created_at) + INTERVAL '15 minutes'
                    WHEN t.priority = 'P1' THEN COALESCE(t.priority_established_at, t.created_at) + INTERVAL '60 minutes'
                    WHEN t.priority = 'P2' THEN COALESCE(t.priority_established_at, t.created_at) + INTERVAL '4 hours'
                    WHEN t.priority = 'P3' THEN COALESCE(t.priority_established_at, t.created_at) + INTERVAL '24 hours'
                    ELSE COALESCE(t.priority_established_at, t.created_at) + INTERVAL '7 days'
                  END) < CURRENT_TIMESTAMP THEN 'SLA BREACH (LEWAT BATAS)'
            ELSE 'AKTIF DALAM SLA'
        END AS status_kepatuhan_sla
    FROM {schema_soc}soc_triage_queue t
    JOIN {schema_corr}correlated_incidents i ON t.incident_id = i.incident_id
    WHERE t.triage_status IN ('OPEN', 'INVESTIGATE', 'WAITING', 'NEW', 'ASSIGNED', 'INVESTIGATING', 'HOLDING_P4')
    ORDER BY 
        -- 1. UTAMAKAN BATAS DEADLINE SLA YANG PALING CEPAT HABIS (EARLIEST DEADLINE FIRST)!
        CASE 
            WHEN t.priority = 'P0' THEN COALESCE(t.priority_established_at, t.created_at) + INTERVAL '15 minutes'
            WHEN t.priority = 'P1' THEN COALESCE(t.priority_established_at, t.created_at) + INTERVAL '60 minutes'
            WHEN t.priority = 'P2' THEN COALESCE(t.priority_established_at, t.created_at) + INTERVAL '4 hours'
            WHEN t.priority = 'P3' THEN COALESCE(t.priority_established_at, t.created_at) + INTERVAL '24 hours'
            ELSE COALESCE(t.priority_established_at, t.created_at) + INTERVAL '7 days'
        END ASC,
        -- 2. JIKA DEADLINE SAMA PERSIS, UTAMAKAN PRIORITAS TERTINGGI
        CASE t.priority 
            WHEN 'P0' THEN 1 
            WHEN 'P1' THEN 2 
            WHEN 'P2' THEN 3 
            WHEN 'P3' THEN 4 
            ELSE 5 
        END ASC,
        -- 3. URUTKAN WAKTU MASUK TERLAMA
        COALESCE(t.priority_established_at, t.created_at) ASC;
    """
    cur.execute(view_sql)
    conn.commit()
    conn.close()
    print(f"[+] Successfully updated {schema_soc}v_actionable_triage_queue to Earliest Deadline First (EDF) in {db_name}!")

if __name__ == "__main__":
    update_queue_view_edf("wazuh_soc_db")
    try:
        update_queue_view_edf("wazuh_alerts")
    except Exception as e:
        print(f"[*] Note: secondary database wazuh_alerts skipped ({e})")
