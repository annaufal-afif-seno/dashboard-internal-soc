import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('192.168.30.206', username='afif', password='test')

script = """
import psycopg2
from psycopg2 import extras
conn = psycopg2.connect(host='localhost', port=5432, dbname='wazuh_soc_db', user='postgres', password='postgres')
cur = conn.cursor(cursor_factory=extras.RealDictCursor)

cur.execute('''
    SELECT event_id, timestamp, location, decoder_name, raw_payload::jsonb->'rule'->>'id' as rule_id, raw_payload::jsonb->'rule'->>'description' as rule_desc
    FROM telemetry.raw_events
    WHERE agent_id = '023'
    ORDER BY timestamp ASC;
''')
print("All events for agent 023:")
for r in cur.fetchall():
    print(dict(r))
"""

sftp = ssh.open_sftp()
with sftp.open('/tmp/check_all_agent023.py', 'w') as f:
    f.write(script)
sftp.close()

stdin, stdout, stderr = ssh.exec_command('/opt/dashboard-internal-soc/backend/venv/bin/python /tmp/check_all_agent023.py')
print(stdout.read().decode())
print(stderr.read().decode())
ssh.close()
