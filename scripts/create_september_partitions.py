import os
import sys
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import psycopg2
from pipeline.database import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD

def create_partitions():
    print("=" * 80)
    print("[*] MEMULAI PEMBUATAN PARTISI TELEMETRI SEPTEMBER & OKTOBER 2026")
    print("=" * 80)

    conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, database=DB_NAME, user=DB_USER, password=DB_PASSWORD)
    conn.autocommit = False
    cur = conn.cursor()

    try:
        # Optimasi sesi untuk kecepatan migrasi
        cur.execute("SET session_replication_role = 'replica';")
        cur.execute("SET synchronous_commit = off;")
        cur.execute("SET maintenance_work_mem = '512MB';")

        # ----------------------------------------------------------------------
        # 1. PARTISI RAW_EVENTS
        # ----------------------------------------------------------------------
        print("\n[1/2] Menyiapkan Partisi telemetry.raw_events...")
        
        # Hapus dummy/test event yang pernah disisipkan saat unit testing
        cur.execute("DELETE FROM telemetry.raw_events_default WHERE timestamp >= '2026-09-01' AND timestamp < '2026-10-01';")
        deleted_raw_test = cur.rowcount
        if deleted_raw_test > 0:
            print(f"  [+] Menghapus {deleted_raw_test} test events dari raw_events_default.")

        # Buat partisi September 2026
        t0 = time.time()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS telemetry.raw_events_2026_09 PARTITION OF telemetry.raw_events
            FOR VALUES FROM ('2026-09-01 00:00:00+00') TO ('2026-10-01 00:00:00+00');
        """)
        print(f"  [+] Partisi telemetry.raw_events_2026_09 berhasil dibuat ({time.time() - t0:.2f}s).")

        # Buat partisi Oktober 2026
        t0 = time.time()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS telemetry.raw_events_2026_10 PARTITION OF telemetry.raw_events
            FOR VALUES FROM ('2026-10-01 00:00:00+00') TO ('2026-11-01 00:00:00+00');
        """)
        print(f"  [+] Partisi telemetry.raw_events_2026_10 berhasil dibuat ({time.time() - t0:.2f}s).")

        # ----------------------------------------------------------------------
        # 2. PARTISI NORMALIZED_EVENTS
        # ----------------------------------------------------------------------
        print("\n[2/2] Menyiapkan Partisi telemetry.normalized_events...")
        
        # Detach default partition terlebih dahulu agar range September & Oktober bisa didefinisikan
        t0 = time.time()
        cur.execute("ALTER TABLE telemetry.normalized_events DETACH PARTITION telemetry.normalized_events_default;")
        print(f"  [+] Detach normalized_events_default sukses ({time.time() - t0:.2f}s).")

        # Buat partisi September 2026
        t0 = time.time()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS telemetry.normalized_events_2026_09 PARTITION OF telemetry.normalized_events
            FOR VALUES FROM ('2026-09-01 00:00:00+00') TO ('2026-10-01 00:00:00+00');
        """)
        print(f"  [+] Partisi telemetry.normalized_events_2026_09 berhasil dibuat ({time.time() - t0:.2f}s).")

        # Buat partisi Oktober 2026
        t0 = time.time()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS telemetry.normalized_events_2026_10 PARTITION OF telemetry.normalized_events
            FOR VALUES FROM ('2026-10-01 00:00:00+00') TO ('2026-11-01 00:00:00+00');
        """)
        print(f"  [+] Partisi telemetry.normalized_events_2026_10 berhasil dibuat ({time.time() - t0:.2f}s).")

        # Pindahkan data September dari default table ke partition 2026_09
        print("  [*] Memindahkan baris September ke normalized_events_2026_09...")
        t0 = time.time()
        cur.execute("""
            INSERT INTO telemetry.normalized_events_2026_09
            SELECT * FROM telemetry.normalized_events_default
            WHERE processed_at >= '2026-09-01 00:00:00+00' AND processed_at < '2026-10-01 00:00:00+00';
        """)
        sept_moved = cur.rowcount
        print(f"  [+] {sept_moved:,} baris September dipindahkan ({time.time() - t0:.2f}s).")

        # Pindahkan data Oktober dari default table ke partition 2026_10
        print("  [*] Memindahkan baris Oktober ke normalized_events_2026_10...")
        t0 = time.time()
        cur.execute("""
            INSERT INTO telemetry.normalized_events_2026_10
            SELECT * FROM telemetry.normalized_events_default
            WHERE processed_at >= '2026-10-01 00:00:00+00' AND processed_at < '2026-11-01 00:00:00+00';
        """)
        oct_moved = cur.rowcount
        print(f"  [+] {oct_moved:,} baris Oktober dipindahkan ({time.time() - t0:.2f}s).")

        # Truncate default table yang sudah kosong
        t0 = time.time()
        cur.execute("TRUNCATE TABLE telemetry.normalized_events_default;")
        print(f"  [+] Truncate normalized_events_default sukses ({time.time() - t0:.2f}s).")

        # Re-attach default partition
        t0 = time.time()
        cur.execute("ALTER TABLE telemetry.normalized_events ATTACH PARTITION telemetry.normalized_events_default DEFAULT;")
        print(f"  [+] Re-attach normalized_events_default sukses ({time.time() - t0:.2f}s).")

        # Reset replication role
        cur.execute("SET session_replication_role = 'origin';")

        conn.commit()
        print("\n" + "=" * 80)
        print("[+] MIGRASI DAN PEMBUATAN PARTISI DATABASE BERHASIL 100%!")
        print("=" * 80)

    except Exception as e:
        conn.rollback()
        print(f"\n[-] ERROR SELAMA MIGRASI: {e}")
        raise e
    finally:
        conn.close()

if __name__ == "__main__":
    create_partitions()
