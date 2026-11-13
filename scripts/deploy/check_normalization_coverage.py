import paramiko
import sys

sys.stdout.reconfigure(encoding='utf-8')

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('192.168.30.100', port=22, username='afif', password='test', timeout=10)

queries = [
    ("Total Raw Events", "SELECT count(*) FROM telemetry.raw_events;"),
    ("Total Normalized Events", "SELECT count(*) FROM telemetry.normalized_events;"),
    ("Breakdown apex_data in normalized_events", """
        SELECT 
            CASE 
                WHEN apex_data IS NULL THEN 'NULL (Belum dinormalisasi metode baru)'
                WHEN apex_data->>'apex_engine_version' = '4.0.0' THEN 'Apex v4.0 Compact (Metode Baru)'
                ELSE 'Format Lama / v3.4'
            END AS status_normalisasi,
            count(*) AS total_rows
        FROM telemetry.normalized_events
        GROUP BY 1;
    """),
    ("Recent 5 normalized_events with apex_data", """
        SELECT 
            normalized_event_id, 
            event_timestamp, 
            processed_at,
            apex_data->>'apex_engine_version' AS v,
            apex_data->>'schema_ref' AS schema_ref
        FROM telemetry.normalized_events 
        WHERE apex_data IS NOT NULL 
        ORDER BY processed_at DESC 
        LIMIT 5;
    """)
]

for title, q in queries:
    print(f"=== {title} ===")
    cmd = f"sudo -S -u postgres psql -d wazuh_soc_db -c \"{q}\""
    stdin, stdout, stderr = ssh.exec_command(cmd)
    stdin.write("test\n")
    stdin.flush()
    print(stdout.read().decode('utf-8', errors='replace').strip())
    print()

ssh.close()
