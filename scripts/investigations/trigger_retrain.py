import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('192.168.30.206', username='afif', password='test')

cmd = "python3 -c \"
import urllib.request
import json

req = urllib.request.Request('http://127.0.0.1:8001/api/ai/retrain', headers={'X-SOC-Key': 'wazuh-soc-secure-key-2026'}, method='POST')
try:
    with urllib.request.urlopen(req) as resp:
        print(json.loads(resp.read().decode()))
except Exception as e:
    print('Error calling /api/ai/retrain:', e)
\""
stdin, stdout, stderr = ssh.exec_command("/opt/dashboard-internal-soc/backend/venv/bin/python /tmp/test_retrain.py")
print(stdout.read().decode())
print(stderr.read().decode())
ssh.close()
