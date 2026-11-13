import paramiko
import sys

sys.stdout.reconfigure(encoding='utf-8')

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('192.168.30.100', port=22, username='afif', password='test', timeout=10)

test_script = """
import sys
sys.path.append('/opt/dashboard-internal-soc-v3')
import json
import time
import psycopg2
from psycopg2.extras import execute_values
from config.settings import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
from pipeline.apex_normalizer import ApexNormalizerV40

conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD)
cur = conn.cursor()

# Fetch 100 pending raw events
cur.execute("SELECT event_id, timestamp, raw_payload FROM telemetry.raw_events WHERE apex_data IS NULL LIMIT 100;")
rows = cur.fetchall()
print(f"Fetched {len(rows)} test rows")

if rows:
    t0 = time.time()
    update_data = []
    for eid, ts, raw_payload in rows:
        try:
            raw_dict = json.loads(raw_payload) if isinstance(raw_payload, str) else (raw_payload or {})
        except Exception:
            raw_dict = {'full_log': raw_payload} if raw_payload else {}
        
        if 'id' not in raw_dict:
            raw_dict['id'] = eid
        if 'timestamp' not in raw_dict:
            raw_dict['timestamp'] = ts.isoformat() if hasattr(ts, 'isoformat') else str(ts)
            
        apex_res = ApexNormalizerV40.normalize_compact(raw_dict)
        net = apex_res.get('network') or {}
        src_ip = net.get('src_ip')
        dst_ip = net.get('dst_ip')
        dst_port = net.get('dst_port')
        transport = net.get('transport') or 'ip'
        
        update_data.append((
            src_ip, dst_ip, dst_port, transport,
            json.dumps(apex_res).replace('\\\\u0000', '').replace('\\x00', ''),
            eid, ts
        ))
    
    cur.execute('''
        CREATE TEMP TABLE tmp_test_apex (
            src_ip varchar, dst_ip varchar, dst_port int, protocol varchar,
            apex_data jsonb, event_id varchar, timestamp timestamptz
        ) ON COMMIT DROP;
    ''')
    
    execute_values(cur, '''
        INSERT INTO tmp_test_apex (src_ip, dst_ip, dst_port, protocol, apex_data, event_id, timestamp)
        VALUES %s;
    ''', update_data)
    
    cur.execute('''
        UPDATE telemetry.raw_events r
        SET 
            source_ip = COALESCE(t.src_ip, r.source_ip),
            destination_ip = COALESCE(t.dst_ip, r.destination_ip),
            destination_port = COALESCE(t.dst_port, r.destination_port),
            protocol = t.protocol,
            apex_data = t.apex_data
        FROM tmp_test_apex t
        WHERE r.event_id = t.event_id AND r.timestamp = t.timestamp;
    ''')
    r_updated = cur.rowcount
    
    cur.execute('''
        UPDATE telemetry.normalized_events n
        SET apex_data = t.apex_data
        FROM tmp_test_apex t
        WHERE n.raw_event_id = t.event_id AND n.event_timestamp = t.timestamp;
    ''')
    n_updated = cur.rowcount
    
    conn.commit()
    dur = time.time() - t0
    print(f"Test batch successful in {dur:.3f}s: raw_events updated={r_updated}, normalized_events updated={n_updated}")

conn.close()
"""

cmd = f"/opt/dashboard-internal-soc-v3/backend/venv/bin/python3 -c \"{test_script}\""
stdin, stdout, stderr = ssh.exec_command(cmd)
print(stdout.read().decode('utf-8', errors='replace'))
print(stderr.read().decode('utf-8', errors='replace'))

ssh.close()
