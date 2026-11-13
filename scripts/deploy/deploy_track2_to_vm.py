import paramiko
import os
import sys

sys.stdout.reconfigure(encoding='utf-8')

VM_HOST = '192.168.30.100'
VM_USER = 'afif'
VM_PASS = 'test'
REMOTE_BASE = '/opt/dashboard-internal-soc-v3'
VENV_PYTHON = f'{REMOTE_BASE}/backend/venv/bin/python3'

print("=" * 80)
print(f"[*] DEPLOYING DUAL-TRACK & APEX V4.0 COMPACT TO VM ({VM_HOST})...")
print("=" * 80)

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(VM_HOST, port=22, username=VM_USER, password=VM_PASS, timeout=10)

sftp = ssh.open_sftp()

files_to_upload = [
    ("pipeline/apex_normalizer.py", f"{REMOTE_BASE}/pipeline/apex_normalizer.py"),
    ("pipeline/models.py", f"{REMOTE_BASE}/pipeline/models.py"),
    ("pipeline/ingest.py", f"{REMOTE_BASE}/pipeline/ingest.py"),
    ("pipeline/database.py", f"{REMOTE_BASE}/pipeline/database.py"),
    ("pipeline/category_catalog.py", f"{REMOTE_BASE}/pipeline/category_catalog.py"),
    ("pipeline/fingerprint_engine.py", f"{REMOTE_BASE}/pipeline/fingerprint_engine.py"),
    ("pipeline/leaf_grouper.py", f"{REMOTE_BASE}/pipeline/leaf_grouper.py"),
    ("pipeline/rollup_engine.py", f"{REMOTE_BASE}/pipeline/rollup_engine.py"),
    ("pipeline/apex_correlation_engine.py", f"{REMOTE_BASE}/pipeline/apex_correlation_engine.py"),
    ("scripts/ops/stream_raw_events_to_pipeline.py", f"{REMOTE_BASE}/scripts/ops/stream_raw_events_to_pipeline.py"),
    ("database/migrations/jalur2_apex_dual_track_schema.sql", f"{REMOTE_BASE}/database/migrations/jalur2_apex_dual_track_schema.sql"),
    ("tests/test_apex_v40_normalization.py", f"{REMOTE_BASE}/tests/test_apex_v40_normalization.py"),
]

# Ensure remote directories exist
for rel_path, remote_path in files_to_upload:
    remote_dir = os.path.dirname(remote_path).replace("\\", "/")
    # mkdir if not exists
    try:
        ssh.exec_command(f"mkdir -p {remote_dir}")
    except Exception:
        pass
    print(f"[*] Uploading: {rel_path} -> {remote_path}")
    sftp.put(rel_path, remote_path)

sftp.close()
print("[+] All files uploaded successfully!")

# 1. Test compilation on remote
print("\n[*] 1. Compiling uploaded python files on remote...")
compile_cmd = f"{VENV_PYTHON} -m py_compile {REMOTE_BASE}/pipeline/apex_normalizer.py {REMOTE_BASE}/pipeline/models.py {REMOTE_BASE}/pipeline/ingest.py {REMOTE_BASE}/pipeline/database.py {REMOTE_BASE}/scripts/ops/stream_raw_events_to_pipeline.py"
stdin, stdout, stderr = ssh.exec_command(compile_cmd)
err = stderr.read().decode('utf-8', errors='replace')
if err:
    print("[-] Compilation error:", err)
    ssh.close()
    sys.exit(1)
print("[+] Remote python compilation clean (0 syntax errors)!")

# 2. Apply DB Migration
print("\n[*] 2. Applying non-destructive database migration on remote PostgreSQL...")
migrate_cmd = f"sudo -S -u postgres psql -d wazuh_soc_db -f {REMOTE_BASE}/database/migrations/jalur2_apex_dual_track_schema.sql"
stdin, stdout, stderr = ssh.exec_command(migrate_cmd)
stdin.write(f"{VM_PASS}\n")
stdin.flush()
mig_out = stdout.read().decode('utf-8', errors='replace')
mig_err = stderr.read().decode('utf-8', errors='replace')
print("DB Migration Output:\n", mig_out)
if "ERROR" in mig_err:
    print("[-] DB Migration Error:\n", mig_err)

# 3. Run Remote Automated Tests
print("\n[*] 3. Running automated test suite on remote VM...")
test_cmd = f"cd {REMOTE_BASE} && {VENV_PYTHON} -m pytest tests/test_apex_v40_normalization.py -v"
stdin, stdout, stderr = ssh.exec_command(test_cmd)
test_out = stdout.read().decode('utf-8', errors='replace')
test_err = stderr.read().decode('utf-8', errors='replace')
print(test_out)
if "failed" in test_out.lower():
    print("[-] Test failures on remote! Output:", test_err)

# 4. Restart Services
print("\n[*] 4. Restarting asoc-streamer and asoc-backend services...")
restart_cmd = "sudo -S systemctl restart asoc-streamer asoc-backend"
stdin, stdout, stderr = ssh.exec_command(restart_cmd)
stdin.write(f"{VM_PASS}\n")
stdin.flush()
stdout.read()

# 5. Check Service Status
print("\n[*] 5. Verifying service status...")
status_cmd = "systemctl is-active asoc-streamer asoc-backend"
stdin, stdout, stderr = ssh.exec_command(status_cmd)
print("Service active states:\n", stdout.read().decode())

ssh.close()
print("=" * 80)
print("[+] DEPLOYMENT TO VM FINISHED!")
print("=" * 80)
