import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('192.168.30.206', username='afif', password='test')

script = """
import psycopg2
from psycopg2 import extras
conn = psycopg2.connect(host='localhost', port=5432, dbname='wazuh_soc_db', user='postgres', password='postgres')
cur = conn.cursor(cursor_factory=extras.RealDictCursor)

triage_id = 'TRG-P0-FC796C5A1338CBC8'

cur.execute('''
    SELECT triage_id, incident_id, priority, triage_status, ground_truth_status, ground_truth_verdict, resolution_outcome, analyst_notes, manager_review_notes, manager_reviewer
    FROM soc_ops.soc_triage_queue
    WHERE triage_id = %s;
''', (triage_id,))
print("Queue record:", dict(cur.fetchone()))

cur.execute('''
    SELECT *
    FROM soc_ops.ground_truth_dataset
    WHERE triage_id = %s OR incident_id = 'INC-P0-FC796C5A1338CBC8';
''', (triage_id,))
print("Ground truth dataset record:", dict(cur.fetchone() or {}))
"""

sftp = ssh.open_sftp()
with sftp.open('/tmp/check_record.py', 'w') as f:
    f.write(script)
sftp.close()

stdin, stdout, stderr = ssh.exec_command('/opt/dashboard-internal-soc/backend/venv/bin/python /tmp/check_record.py')
print(stdout.read().decode())
print(stderr.read().decode())
ssh.close()
