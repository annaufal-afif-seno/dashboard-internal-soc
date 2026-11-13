import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('192.168.30.100', port=22, username='afif', password='test', timeout=5)

cmd = "sudo -S -u postgres psql -d wazuh_soc_db -c \"SELECT count(*) FROM telemetry.raw_events WHERE apex_data IS NULL;\""
stdin, stdout, stderr = ssh.exec_command(cmd)
stdin.write("test\n")
stdin.flush()
print("Pending raw_events without apex_data:")
print(stdout.read().decode())
ssh.close()
