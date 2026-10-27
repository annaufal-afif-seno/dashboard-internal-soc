import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('192.168.30.206', username='afif', password='test')

script = """
import psycopg2
from psycopg2 import extras
conn = psycopg2.connect(host='localhost', port=5432, dbname='wazuh_soc_db', user='postgres', password='postgres')
cur = conn.cursor(cursor_factory=extras.RealDictCursor)

inc_id = 'INC-P0-FC796C5A1338CBC8'
triage_id = 'TRG-P0-FC796C5A1338CBC8'

cur.execute('''
    SELECT *
    FROM correlation.incident_stages
    WHERE incident_id = %s;
''', (inc_id,))
print("--- STAGES ---")
for s in cur.fetchall():
    print(dict(s))

cur.execute('''
    SELECT *
    FROM soc_ops.ticket_aggregates
    WHERE ticket_id = %s OR ticket_id = %s;
''', (triage_id, inc_id))
print("\\n--- TICKET AGGREGATES ---")
for a in cur.fetchall():
    print(dict(a))

cur.execute('''
    SELECT column_name FROM information_schema.columns WHERE table_schema = 'telemetry' AND table_name = 'raw_events';
''')
print("telemetry.raw_events columns:", [r['column_name'] for r in cur.fetchall()])
"""

sftp = ssh.open_sftp()
with sftp.open('/tmp/investigate_ticket.py', 'w') as f:
    f.write(script)
sftp.close()

stdin, stdout, stderr = ssh.exec_command('/opt/dashboard-internal-soc/backend/venv/bin/python /tmp/investigate_ticket.py')
print(stdout.read().decode())
print(stderr.read().decode())
ssh.close()
