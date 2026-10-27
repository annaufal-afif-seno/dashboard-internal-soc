import paramiko
import json

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('192.168.30.206', username='afif', password='test')

script = """
import psycopg2
import json
from psycopg2 import extras
conn = psycopg2.connect(host='localhost', port=5432, dbname='wazuh_soc_db', user='postgres', password='postgres')
cur = conn.cursor(cursor_factory=extras.RealDictCursor)

cur.execute('''
    SELECT event_id, timestamp, agent_id, agent_name, raw_payload
    FROM telemetry.raw_events
    WHERE agent_id = '023'
      AND timestamp >= '2026-10-16 18:10:00' AND timestamp <= '2026-10-16 18:25:00'
    LIMIT 10;
''')

rows = cur.fetchall()
print(f"Raw events found: {len(rows)}")
for r in rows:
    print("Event ID:", r['event_id'], "Time:", r['timestamp'])
    payload = r['raw_payload']
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except:
            pass
    print(json.dumps(payload, indent=2))
    print("=" * 60)
"""

sftp = ssh.open_sftp()
with sftp.open('/tmp/investigate_raw.py', 'w') as f:
    f.write(script)
sftp.close()

stdin, stdout, stderr = ssh.exec_command('/opt/dashboard-internal-soc/backend/venv/bin/python /tmp/investigate_raw.py')
print(stdout.read().decode())
print(stderr.read().decode())
ssh.close()
