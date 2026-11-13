import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('192.168.30.100', port=22, username='afif', password='test', timeout=5)

cmd = "cd /opt/dashboard-internal-soc-v3 && backend/venv/bin/python3 -c \"from config.settings import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD; print(DB_HOST, DB_PORT, DB_NAME, DB_USER, 'has_pass' if DB_PASSWORD else 'no_pass')\""
stdin, stdout, stderr = ssh.exec_command(cmd)
print(stdout.read().decode())
print(stderr.read().decode())
ssh.close()
