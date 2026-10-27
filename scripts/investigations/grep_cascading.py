import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('192.168.30.206', username='afif', password='test')

cmd = "grep -n -E 'def.*cascad|def.*auto_triage|@app.post.*triage' /opt/dashboard-internal-soc-v2/backend/pipeline/api.py -A 10"
stdin, stdout, stderr = ssh.exec_command(cmd)
print(stdout.read().decode())
ssh.close()
