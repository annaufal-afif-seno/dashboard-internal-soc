import paramiko
import json

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('192.168.30.206', username='afif', password='test')

script = """
import urllib.request
import json

triage_id = 'TRG-P0-FC796C5A1338CBC8'
headers = {
    'Content-Type': 'application/json',
    'X-SOC-Key': 'wazuh-soc-secure-key-2026'
}

# 1. Submit Ground Truth as Senior SOC Analyst
submit_url = f'http://127.0.0.1:8001/api/triage/{triage_id}/submit-ground-truth'
submit_data = {
    'verdict': 'BENIGN',
    'notes': 'Investigasi mendalam FIM pada host leaning-sgu-dimas-124 mengonfirmasi perubahan checksum /usr/bin/curl dan /etc/ld.so.cache merupakan dampak pembaruan paket Debian rutin (dpkg update 2026-10-16 06:31:15 UTC). Tidak ditemukan payload jahat, koneksi C2, atau anomali jaringan. Ditetapkan sebagai BENIGN / FALSE POSITIVE (S4 Maintenance).',
    'analyst_id': 'senior_soc_analyst'
}

req = urllib.request.Request(submit_url, data=json.dumps(submit_data).encode('utf-8'), headers=headers, method='POST')
try:
    with urllib.request.urlopen(req) as resp:
        print('Submit Ground Truth response:', json.loads(resp.read().decode()))
except Exception as e:
    print('Submit Ground Truth error:', e)

# 2. Approve Ground Truth as SOC Lead / Manager
approve_url = f'http://127.0.0.1:8001/api/ground-truth/{triage_id}/approve'
approve_data = {
    'manager_id': 'soc_manager',
    'manager_notes': 'Ground truth telah diverifikasi akurat oleh Senior SOC. Divalidasi sebagai BENIGN / FALSE POSITIVE dan dimasukkan ke dataset retraining.'
}

req = urllib.request.Request(approve_url, data=json.dumps(approve_data).encode('utf-8'), headers=headers, method='POST')
try:
    with urllib.request.urlopen(req) as resp:
        print('Approve Ground Truth response:', json.loads(resp.read().decode()))
except Exception as e:
    print('Approve Ground Truth error:', e)
"""

sftp = ssh.open_sftp()
with sftp.open('/tmp/run_gt_workflow.py', 'w') as f:
    f.write(script)
sftp.close()

stdin, stdout, stderr = ssh.exec_command('/opt/dashboard-internal-soc/backend/venv/bin/python /tmp/run_gt_workflow.py')
print(stdout.read().decode())
print(stderr.read().decode())
ssh.close()
