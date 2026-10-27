"""
Synchronize Live Threat Intelligence Results into Normalized Events.
PRD Section 8 #6: Hitung ulang skor insiden berdasarkan IoC sudah dihapus.
Modul ini hanya menandai normalized_events yang match dengan TI feed.
"""
import psycopg2
from config.settings import DB_HOST, DB_PORT, DB_USER, DB_PASSWORD


def sync_live_ti_and_scores(db_name="wazuh_soc_db"):
    print("=" * 80)
    print(f"[*] SYNCHRONIZING LIVE THREAT INTEL RESULTS (DB: {db_name})")
    print("=" * 80)

    schema_ti = "enrichment." if db_name == "wazuh_soc_db" else "public."
    schema_tele = "telemetry." if db_name == "wazuh_soc_db" else "public."

    try:
        conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, database=db_name,
                                user=DB_USER, password=DB_PASSWORD)
        cur = conn.cursor()

        # Update normalized_events with TI match flags
        cur.execute(f"""
            UPDATE {schema_tele}normalized_events n
            SET threat_intel_match = (t.confidence_score >= 50 OR t.malware_family = 'MALICIOUS'),
                threat_intel_confidence = t.confidence_score
            FROM {schema_tele}raw_events r
            JOIN {schema_ti}threat_intelligence_iocs t ON r.source_ip = t.indicator_value
            WHERE n.raw_event_id = r.event_id
              AND n.threat_intel_match IS NULL;
        """)
        conn.commit()

        cur.execute(f"""
            SELECT count(*) as total_matched, avg(threat_intel_confidence) as avg_conf
            FROM {schema_tele}normalized_events
            WHERE threat_intel_match = TRUE;
        """)
        res = cur.fetchone()
        print(f"[+] Events with TI Match: {res[0]:,} (Avg Confidence: {res[1]:.1f}%)" if res[1] else f"[+] Events with TI Match: {res[0]:,}")

        conn.close()
    except Exception as e:
        print(f"[-] TI sync: {e}")

    print("[+] TI sync complete. (Score recalculation removed per PRD Section 8 #6)")


if __name__ == "__main__":
    sync_live_ti_and_scores("wazuh_soc_db")
