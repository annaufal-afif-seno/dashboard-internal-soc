import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('192.168.30.206', username='afif', password='test')

script = """
import psycopg2
from psycopg2 import extras
conn = psycopg2.connect(host='localhost', port=5432, dbname='wazuh_soc_db', user='postgres', password='postgres')
cur = conn.cursor(cursor_factory=extras.RealDictCursor)

start_dt = '2026-10-19 17:00:00'
end_dt = '2026-10-20 16:59:59'

cur.execute('''
    SELECT 
        t.triage_id,
        t.incident_id,
        t.priority,
        t.triage_status,
        t.assigned_analyst,
        t.ground_truth_status,
        t.ground_truth_verdict,
        t.resolution_outcome,
        t.analyst_notes,
        COALESCE(t.priority_established_at, t.created_at) as muncul,
        c.title,
        c.target_host,
        c.attacker_source_ip,
        c.first_seen_at,
        c.last_seen_at,
        c.narrative
    FROM soc_ops.soc_triage_queue t
    JOIN correlation.correlated_incidents c ON t.incident_id = c.incident_id
    WHERE t.triage_status IN ('GROUNDTRUTH', 'GROUND_TRUTH')
      AND COALESCE(t.created_at, c.first_seen_at) >= %s AND COALESCE(t.created_at, c.first_seen_at) <= %s;
''', (start_dt, end_dt))

rows = cur.fetchall()
print(f"Total groundtruth tickets today: {len(rows)}")
for r in rows:
    for k, v in r.items():
        print(f"  {k}: {v}")
    print("-" * 50)
"""

sftp = ssh.open_sftp()
with sftp.open('/tmp/inspect_gt_ticket.py', 'w') as f:
    f.write(script)
sftp.close()

stdin, stdout, stderr = ssh.exec_command('/opt/dashboard-internal-soc/backend/venv/bin/python /tmp/inspect_gt_ticket.py')
print(stdout.read().decode())
print(stderr.read().decode())
ssh.close()
