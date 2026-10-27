import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('192.168.30.206', username='afif', password='test')

script = """
import psycopg2
from psycopg2 import extras
conn = psycopg2.connect(host='localhost', port=5432, dbname='wazuh_soc_db', user='postgres', password='postgres')
cur = conn.cursor(cursor_factory=extras.RealDictCursor)

agg_id = 'agg_256693a22cdb449e8b674b798ecd1800'

cur.execute('''
    SELECT *
    FROM suppression.aggregated_alerts
    WHERE aggregation_id = %s;
''', (agg_id,))
print("--- AGGREGATED ALERT ---")
row = cur.fetchone()
if row:
    for k, v in row.items():
        print(f"  {k}: {v}")

dedup_key = row['deduplication_key'] if row else None
if dedup_key:
    cur.execute('''
        SELECT *
        FROM suppression.cumulative_alerts
        WHERE deduplication_key = %s;
    ''', (dedup_key,))
    print("\\n--- CUMULATIVE ALERT ---")
    crow = cur.fetchone()
    if crow:
        for k, v in crow.items():
            print(f"  {k}: {v}")

# Also check telemetry.raw_events or normalized_events for this deduplication_key or timeframe
cur.execute('''
    SELECT *
    FROM telemetry.normalized_events
    WHERE agent_name ILIKE '%leaning-sgu-dimas-124%'
      AND event_timestamp >= '2026-10-16 18:10:00' AND event_timestamp <= '2026-10-16 18:35:00'
    LIMIT 5;
''')
print("\\n--- NORMALIZED EVENTS ---")
for r in cur.fetchall():
    print(dict(r))
"""

sftp = ssh.open_sftp()
with sftp.open('/tmp/investigate_ticket2.py', 'w') as f:
    f.write(script)
sftp.close()

stdin, stdout, stderr = ssh.exec_command('/opt/dashboard-internal-soc/backend/venv/bin/python /tmp/investigate_ticket2.py')
print(stdout.read().decode())
print(stderr.read().decode())
ssh.close()
