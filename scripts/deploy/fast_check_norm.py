import paramiko
import sys
import json

sys.stdout.reconfigure(encoding='utf-8')

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('192.168.30.100', port=22, username='afif', password='test', timeout=5)

fast_query = """
SELECT 
    schemaname, 
    relname, 
    n_live_tup 
FROM pg_stat_user_tables 
WHERE relname IN ('raw_events', 'normalized_events', 'aggregated_alerts', 'alert_activity_groups')
ORDER BY relname;
"""

cmd = f"sudo -S -u postgres psql -d wazuh_soc_db -c \"{fast_query}\""
stdin, stdout, stderr = ssh.exec_command(cmd)
stdin.write("test\n")
stdin.flush()
print("=== Perkiraan Jumlah Baris (Live Tuples) ===")
print(stdout.read().decode('utf-8', errors='replace'))

# Check recent normalized events apex_data
cmd2 = "sudo -S -u postgres psql -d wazuh_soc_db -c \"SELECT normalized_event_id, processed_at, apex_data IS NOT NULL as has_apex, apex_data->>'apex_engine_version' as ver, apex_data->>'schema_ref' as s_ref FROM telemetry.normalized_events ORDER BY processed_at DESC LIMIT 5;\""
stdin, stdout, stderr = ssh.exec_command(cmd2)
stdin.write("test\n")
stdin.flush()
print("=== 5 Data Ternormalisasi Paling Baru (Recent Live Ingest) ===")
print(stdout.read().decode('utf-8', errors='replace'))

# Check old normalized events
cmd3 = "sudo -S -u postgres psql -d wazuh_soc_db -c \"SELECT normalized_event_id, processed_at, apex_data IS NOT NULL as has_apex FROM telemetry.normalized_events WHERE processed_at < '2026-11-01' LIMIT 5;\""
stdin, stdout, stderr = ssh.exec_command(cmd3)
stdin.write("test\n")
stdin.flush()
print("=== Sampel Data Historis Lama (Sebelum November 2026) ===")
print(stdout.read().decode('utf-8', errors='replace'))

ssh.close()
