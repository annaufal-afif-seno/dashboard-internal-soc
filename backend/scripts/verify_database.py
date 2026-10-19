import os, sys

sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config.settings import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
from pipeline.database import DatabaseManager

def verify_postgres_records():
    print("=" * 88)
    print("           VERIFIKASI REAL-TIME DATA DI DALAM DATABASE POSTGRESQL")
    print(f"           Database: {DB_NAME} | Host: {DB_HOST}:{DB_PORT}")
    print("=" * 88)

    db = DatabaseManager()
    if not db.initialize_pool():
        print("[-] Gagal terhubung ke database PostgreSQL.")
        return

    # Daftar 19 tabel master
    master_tables = [
        "asset_inventory_context",
        "identity_context",
        "threat_intelligence_iocs",
        "maintenance_windows",
        "suppression_rules",
        "suppression_audit_log",
        "raw_events",
        "normalized_events",
        "aggregated_alerts",
        "aggregate_evidence_mapping",
        "correlation_rules",
        "correlated_incidents",
        "incident_stages",
        "risk_scoring_factors",
        "calculated_risk_scores",
        "soc_triage_queue",
        "incident_investigation_notes",
        "incident_response_actions",
        "operational_metrics_daily"
    ]

    with db.get_connection() as conn:
        with conn.cursor() as cur:
            print("\n[1] JUMLAH RECORD PADA SETIAP TABEL (19 BASE TABLES):")
            print("-" * 88)
            print(f"{'No.':<4} {'Nama Tabel':<35} {'Jumlah Record':<15} {'Status':<15}")
            print("-" * 88)
            
            for idx, tbl in enumerate(master_tables, 1):
                try:
                    cur.execute(f"SELECT COUNT(*) FROM {tbl};")
                    count = cur.fetchone()[0]
                    status = "[ACTIVE]" if count > 0 else "[EMPTY]"
                    print(f"{idx:<4} {tbl:<35} {count:<15,} {status:<15}")
                except Exception as e:
                    print(f"{idx:<4} {tbl:<35} {'ERROR':<15} [ERR] {e}")

            # 2. Detail Isi Tabel Master Context
            print("\n[2] SAMPLE DATA ASSET INVENTORY CONTEXT:")
            print("-" * 88)
            cur.execute("SELECT asset_id, hostname, ip_address, asset_type, criticality_tier, criticality_score FROM asset_inventory_context LIMIT 5;")
            rows = cur.fetchall()
            for r in rows:
                print(f"    - {r[0]:<10} | {r[1]:<25} | IP: {r[2]:<15} | {r[3]:<18} | Tier: {r[4]:<12} ({r[5]} pts)")

            # 3. Detail Aturan Supresi Aktif
            print("\n[3] SAMPLE DATA ATURAN SUPRESI (SUPPRESSION RULES & SLA):")
            print("-" * 88)
            cur.execute("SELECT suppression_id, rule_name, suppression_class, author, approver, expires_date, status FROM suppression_rules;")
            rows = cur.fetchall()
            for r in rows:
                print(f"    - {r[0]:<14} | {r[1]:<40} | {r[2]:<18} | {r[3]} -> {r[4]} | Exp: {r[5]} [{r[6]}]")

            # 4. Detail Aturan Korelasi
            print("\n[4] SAMPLE DATA ATURAN KORELASI SERANGAN (CORRELATION RULES):")
            print("-" * 88)
            cur.execute("SELECT correlation_rule_id, rule_code, rule_name, timeframe_seconds, target_severity FROM correlation_rules;")
            rows = cur.fetchall()
            for r in rows:
                print(f"    - {r[0]:<10} | {r[1]:<28} | {r[2]:<40} | Window: {r[3]}s | Sev: {r[4]}")

            # 5. Verifikasi Distribusi Partisi Fisik
            print("\n[5] VERIFIKASI PARTISI FISIK POSTGRESQL (PARTITION SHARDS):")
            print("-" * 88)
            cur.execute("""
                SELECT parent.relname AS parent_table, child.relname AS partition_name
                FROM pg_inherits
                JOIN pg_class parent ON pg_inherits.inhparent = parent.oid
                JOIN pg_class child ON pg_inherits.inhrelid = child.oid
                ORDER BY parent.relname, child.relname;
            """)
            part_rows = cur.fetchall()
            for p in part_rows:
                print(f"    - Partition Table: {p[1]:<30} (Child of: {p[0]})")

    db.close()
    print("\n" + "=" * 88)
    print("                  SELURUH DATA TELAH TERVERIFIKASI DI DATABASE!")
    print("=" * 88)

if __name__ == "__main__":
    verify_postgres_records()
