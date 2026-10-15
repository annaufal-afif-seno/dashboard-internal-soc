import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import psycopg2
from config.settings import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD

conn = psycopg2.connect(
    host=DB_HOST, port=DB_PORT, database=DB_NAME, user=DB_USER, password=DB_PASSWORD
)
cur = conn.cursor()
cur.execute("""
    SELECT conname, pg_get_constraintdef(oid) 
    FROM pg_constraint 
    WHERE conrelid = 'risk_engine.calculated_risk_scores'::regclass;
""")
for row in cur.fetchall():
    print(row)

cur.execute("""
    SELECT column_name, data_type 
    FROM information_schema.columns 
    WHERE table_schema = 'soc_ops' AND table_name = 'soc_triage_queue';
""")
print("\nsoc_triage_queue columns:")
for col in cur.fetchall():
    print(f"  {col[0]}: {col[1]}")

conn.close()
