import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('192.168.30.100', port=22, username='afif', password='test', timeout=5)

cmd = "sudo -S -u postgres psql -d wazuh_soc_db -c \"SELECT pid, state, now() - query_start AS duration, query FROM pg_stat_activity WHERE state != 'idle';\""
stdin, stdout, stderr = ssh.exec_command(cmd)
stdin.write("test\n")
stdin.flush()
print(stdout.read().decode())
ssh.close()
