import os, sys
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

base_dir = r"c:\Users\Pongo\Downloads\wazuh alert grouping -"
sys.path.insert(0, base_dir)

from config.settings import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
from pipeline.database import DatabaseManager

def setup_live_database():
    print("=" * 80)
    print("      CONNECTING AND INITIALIZING POSTGRESQL PRODUCTION DATABASE")
    print("=" * 80)

    # 1. Connect to postgres default DB and create wazuh_alerts if not exists
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            dbname="postgres",
            connect_timeout=3
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM pg_database WHERE datname = %s;", (DB_NAME,))
        exists = cur.fetchone()
        if not exists:
            cur.execute(f"CREATE DATABASE {DB_NAME};")
            print(f"[+] Created database '{DB_NAME}' successfully!")
        else:
            print(f"[+] Database '{DB_NAME}' already exists.")
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[-] Could not connect to PostgreSQL default database: {e}")
        return

    # 2. Run migrations and seed data using DatabaseManager
    db_mgr = DatabaseManager()
    print("[*] Initializing pool and applying 19-table schema migrations...")
    mig_ok = db_mgr.run_migrations()
    print(f"[+] Migrations Applied: {mig_ok}")

    print("[*] Loading master seed data (Assets, Identity, IoCs, Suppression Rules)...")
    seed_ok = db_mgr.run_seed_data()
    print(f"[+] Seed Data Loaded: {seed_ok}")

    # 3. Verify tables count
    with db_mgr.get_connection() as c:
        with c.cursor() as cur:
            cur.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' AND table_type = 'BASE TABLE' 
                ORDER BY table_name;
            """)
            tables = [t[0] for t in cur.fetchall()]
            print(f"\\n[+] Total Tables in PostgreSQL database: {len(tables)}")
            for idx, t in enumerate(tables, 1):
                print(f"    {idx:>2}. {t}")

            # Check seed data count in asset_inventory_context
            cur.execute("SELECT COUNT(*) FROM asset_inventory_context;")
            asset_cnt = cur.fetchone()[0]
            print(f"\\n[+] Verified Seed Asset Context Records: {asset_cnt}")

            # Check seed data count in suppression_rules
            cur.execute("SELECT COUNT(*) FROM suppression_rules;")
            supp_cnt = cur.fetchone()[0]
            print(f"[+] Verified Seed Suppression Rules: {supp_cnt}")

            # Check seed data count in correlation_rules
            cur.execute("SELECT COUNT(*) FROM correlation_rules;")
            corr_cnt = cur.fetchone()[0]
            print(f"[+] Verified Seed Correlation Rules: {corr_cnt}")

    db_mgr.close()
    print("=" * 80)
    print("   POSTGRESQL DATABASE IS FULLY INITIALIZED, SEEDED, AND CONNECTED!")
    print("=" * 80)

if __name__ == "__main__":
    setup_live_database()
