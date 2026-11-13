import paramiko
import sys
import os

sys.stdout.reconfigure(encoding='utf-8')

VM_HOST = '192.168.30.100'
VM_USER = 'afif'
VM_PASS = 'test'
REMOTE_BASE = '/opt/dashboard-internal-soc-v3'
VENV_PYTHON = f'{REMOTE_BASE}/backend/venv/bin/python3'

print("=" * 80)
print(f"[*] MENYINKRONKAN FILE DAN MENJALANKAN RE-NORMALISASI HISTORIS DI VM ({VM_HOST})")
print("=" * 80)

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(VM_HOST, port=22, username=VM_USER, password=VM_PASS, timeout=10)

sftp = ssh.open_sftp()

files = [
    ("pipeline/database.py", f"{REMOTE_BASE}/pipeline/database.py"),
    ("scripts/ops/stream_raw_events_to_pipeline.py", f"{REMOTE_BASE}/scripts/ops/stream_raw_events_to_pipeline.py"),
    ("scripts/ops/re_normalize_all_historical_alerts.py", f"{REMOTE_BASE}/scripts/ops/re_normalize_all_historical_alerts.py"),
]

for local_f, remote_f in files:
    print(f"[*] Uploading: {local_f} -> {remote_f}")
    sftp.put(local_f, remote_f)

sftp.close()
print("[+] File berhasil diupload!")

# Compile check
print("\n[*] Memeriksa sintaks file pada remote VM...")
compile_cmd = f"{VENV_PYTHON} -m py_compile {REMOTE_BASE}/pipeline/database.py {REMOTE_BASE}/scripts/ops/stream_raw_events_to_pipeline.py {REMOTE_BASE}/scripts/ops/re_normalize_all_historical_alerts.py"
stdin, stdout, stderr = ssh.exec_command(compile_cmd)
err = stderr.read().decode('utf-8', errors='replace')
if err:
    print("[-] Compilation error:", err)
    ssh.close()
    sys.exit(1)
print("[+] Kompilasi bersih tanpa error!")

# Restart streamer to activate new DB mapping for live stream
print("\n[*] Me-restart asoc-streamer.service...")
stdin, stdout, stderr = ssh.exec_command("sudo -S systemctl restart asoc-streamer")
stdin.write(f"{VM_PASS}\n")
stdin.flush()
stdout.read()
print("[+] asoc-streamer.service aktif!")

# Jalankan re_normalize_all_historical_alerts.py
print("\n[*] Menjalankan proses re-normalisasi data historis secara langsung...")
run_cmd = f"cd {REMOTE_BASE} && {VENV_PYTHON} scripts/ops/re_normalize_all_historical_alerts.py"
stdin, stdout, stderr = ssh.exec_command(run_cmd, get_pty=True)

while True:
    line = stdout.readline()
    if not line:
        break
    print(line, end='', flush=True)

exit_status = stdout.channel.recv_exit_status()
print(f"\n[+] Status Selesai: Exit Code {exit_status}")

ssh.close()
