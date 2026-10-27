import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('192.168.30.206', username='afif', password='test')

script = """
import psycopg2
conn = psycopg2.connect(host='localhost', port=5432, dbname='wazuh_soc_db', user='postgres', password='postgres')
cur = conn.cursor()

triage_id = 'TRG-P0-FC796C5A1338CBC8'
analyst_notes = 'Investigasi mendalam FIM pada host leaning-sgu-dimas-124 mengonfirmasi perubahan checksum /usr/bin/curl dan /etc/ld.so.cache merupakan dampak pembaruan paket Debian rutin (dpkg update 2026-10-16 06:31:15 UTC). Tidak ditemukan payload jahat, koneksi C2, atau anomali jaringan. Ditetapkan sebagai BENIGN / FALSE POSITIVE (S4 Maintenance).'

cur.execute('''
    UPDATE soc_ops.soc_triage_queue
    SET ground_truth_verdict = 'FALSE_POSITIVE',
        analyst_notes = %s,
        assigned_analyst = 'senior_soc_analyst'
    WHERE triage_id = %s;
''', (analyst_notes, triage_id))
conn.commit()
print("Updated queue record with analyst verdict and notes!")
"""

sftp = ssh.open_sftp()
with sftp.open('/tmp/update_notes.py', 'w') as f:
    f.write(script)
sftp.close()

stdin, stdout, stderr = ssh.exec_command('/opt/dashboard-internal-soc/backend/venv/bin/python /tmp/update_notes.py')
print(stdout.read().decode())
print(stderr.read().decode())
ssh.close()
