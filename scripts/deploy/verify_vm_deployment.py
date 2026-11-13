import paramiko
import json
import sys

sys.stdout.reconfigure(encoding='utf-8')

VM_HOST = '192.168.30.100'
VM_USER = 'afif'
VM_PASS = 'test'

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(VM_HOST, port=22, username=VM_USER, password=VM_PASS, timeout=10)

print("=" * 80)
print("[*] VERIFIKASI LANGSUNG DI MESIN VM (192.168.30.100)")
print("=" * 80)

# 1. Logs asoc-streamer
print("\n--- 1. Recent Logs: asoc-streamer.service ---")
stdin, stdout, stderr = ssh.exec_command("sudo -S journalctl -u asoc-streamer.service -n 25 --no-pager")
stdin.write(f"{VM_PASS}\n")
stdin.flush()
print(stdout.read().decode('utf-8', errors='replace'))

# 2. Logs asoc-backend
print("\n--- 2. Recent Logs: asoc-backend.service ---")
stdin, stdout, stderr = ssh.exec_command("sudo -S journalctl -u asoc-backend.service -n 20 --no-pager")
stdin.write(f"{VM_PASS}\n")
stdin.flush()
print(stdout.read().decode('utf-8', errors='replace'))

# 3. Database status of Track 1 and Track 2
print("\n--- 3. PostgreSQL Metrics: Track 1 vs Track 2 ---")
sql = """
SELECT 
    'Jalur 1: suppression.aggregated_alerts' AS track, count(*) AS total FROM suppression.aggregated_alerts
UNION ALL
SELECT 
    'Jalur 1: soc_ops.soc_triage_queue' AS track, count(*) AS total FROM soc_ops.soc_triage_queue
UNION ALL
SELECT 
    'Jalur 2: telemetry.alert_activity_groups' AS track, count(*) AS total FROM telemetry.alert_activity_groups
UNION ALL
SELECT 
    'Jalur 2: telemetry.activity_group_alerts' AS track, count(*) AS total FROM telemetry.activity_group_alerts;
"""
stdin, stdout, stderr = ssh.exec_command(f"sudo -S -u postgres psql -d wazuh_soc_db -c \"{sql}\"")
stdin.write(f"{VM_PASS}\n")
stdin.flush()
print(stdout.read().decode('utf-8', errors='replace'))

# 4. Check Apex v4.0 Sample in normalized_events
print("\n--- 4. Apex Normalizer v4.0 Sample in normalized_events ---")
sql_sample = "SELECT apex_data FROM telemetry.normalized_events WHERE apex_data IS NOT NULL ORDER BY processed_at DESC LIMIT 1;"
stdin, stdout, stderr = ssh.exec_command(f"sudo -S -u postgres psql -d wazuh_soc_db -t -c \"{sql_sample}\"")
stdin.write(f"{VM_PASS}\n")
stdin.flush()
sample_out = stdout.read().decode('utf-8', errors='replace').strip()
if sample_out:
    try:
        sample_json = json.loads(sample_out)
        print("Sample apex_data format:")
        print(json.dumps(sample_json, indent=2))
        print("\nSchema Ref:", sample_json.get("schema_ref"))
    except Exception as e:
        print("Raw output:", sample_out[:500])
else:
    print("No recent apex_data yet (streaming in progress).")

ssh.close()
print("=" * 80)
