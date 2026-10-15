import os
import sys
import time
import logging
from pathlib import Path
import psycopg2
from psycopg2 import extras

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from pipeline.database import DatabaseManager

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger('stream_processor')

def process_live_events():
    db = DatabaseManager(host='127.0.0.1', port=5432, dbname='wazuh_soc_db', user='postgres', password='postgres')
    
    with db.get_connection() as conn:
        with conn.cursor(cursor_factory=extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT event_id, event_timestamp, agent_id, agent_name, rule_id, rule_level, 
                       rule_description, source_ip, destination_ip, username, raw_payload
                FROM telemetry.events
                ORDER BY event_timestamp ASC;
            """)
            events = cur.fetchall()
            
            if not events:
                logger.info('No events found in telemetry.events.')
                return
                
            logger.info(f"Processing {len(events)} events into incident triage...")
            
            for ev in events:
                clean_eid = str(ev['event_id']).replace('.', '_')
                inc_id = f"INC-{clean_eid[:20]}"
                triage_id = f"TRG-{clean_eid[:20]}"
                prio = 'P0' if ev['rule_level'] >= 12 else ('P1' if ev['rule_level'] >= 9 else ('P2' if ev['rule_level'] >= 7 else 'P3'))
                
                # 1. Insert incident into correlation.correlated_incidents
                cur.execute("""
                    INSERT INTO correlation.correlated_incidents (
                        incident_id, correlation_rule_id, tenant_id, title, narrative,
                        attacker_source_ip, target_host, incident_status, first_seen_at, last_seen_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (incident_id) DO NOTHING;
                """, (
                    inc_id, 'CORR-001', 'DEFAULT', ev['rule_description'] or 'Wazuh Alert Correlation',
                    f"Automated Correlation from Alert Level {ev['rule_level']}: {ev['rule_description']}",
                    str(ev['source_ip']) if ev['source_ip'] else None,
                    str(ev['agent_name'] or 'wazuh-agent'),
                    'DETECTED', ev['event_timestamp'], ev['event_timestamp']
                ))
                
                # 2. Insert triage queue ticket into soc_ops.soc_triage_queue
                cur.execute("""
                    INSERT INTO soc_ops.soc_triage_queue (
                        triage_id, incident_id, priority, triage_status, created_at, updated_at
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (triage_id) DO NOTHING;
                """, (
                    triage_id, inc_id, prio, 'OPEN', ev['event_timestamp'], ev['event_timestamp']
                ))
                
            conn.commit()
            logger.info(f"Successfully escalated {len(events)} events into soc_ops.soc_triage_queue!")

if __name__ == '__main__':
    process_live_events()
