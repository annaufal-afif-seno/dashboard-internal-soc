"""
Script to batch reconstruct Threat Campaigns across all distinct victim hosts with P0/P1 breaches.
"""
import sys
import os
from pathlib import Path

# Add project root
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from pipeline.database import DatabaseManager
from pipeline.campaign_clustering import ThreatCampaignClusterer

def run_batch_reconstruction(limit: int = 15):
    print("=" * 80)
    print(f"[*] STARTING BATCH THREAT CAMPAIGN CLUSTERING (Target: {limit} Distinct Hosts)")
    print("=" * 80)

    db = DatabaseManager()
    clusterer = ThreatCampaignClusterer(db_manager=db, default_lookback_hours=72)

    with db.get_connection() as c:
        with c.cursor() as cur:
            cur.execute("""
                SELECT DISTINCT ON (i.target_host)
                    i.incident_id, i.tenant_id, i.title, i.attacker_source_ip, i.target_host,
                    i.incident_status, i.first_seen_at, i.last_seen_at, q.triage_id, q.priority
                FROM correlation.correlated_incidents i
                JOIN soc_ops.soc_triage_queue q ON i.incident_id = q.incident_id
                WHERE (q.resolution_outcome = 'TRUE_POSITIVE_ACTIONABLE' 
                       OR q.triage_status IN ('INVESTIGATE', 'ESCALATED') 
                       OR q.iris_case_id IS NOT NULL
                       OR i.incident_status = 'ESCALATED')
                  AND (q.resolution_outcome IS NULL OR q.resolution_outcome != 'FALSE_POSITIVE_TUNING_REQ')
                  AND i.target_host IS NOT NULL
                  AND i.target_host NOT IN ('unknown', '')
                ORDER BY i.target_host, i.last_seen_at DESC
                LIMIT %s;
            """, (limit,))
            rows = cur.fetchall()

    print(f"[+] Found {len(rows)} distinct victim hosts with confirmed THREAT incidents (P0-P4).")

    reconstructed = []
    for idx, r in enumerate(rows, 1):
        inc = {
            'incident_id': r[0],
            'tenant_id': r[1],
            'title': r[2],
            'attacker_source_ip': r[3],
            'target_host': r[4],
            'incident_status': r[5],
            'first_seen_at': r[6],
            'last_seen_at': r[7],
            'triage_id': r[8],
            'priority': r[9] or 'P0'
        }
        res = clusterer.cluster_threat_campaign(inc, lookback_hours=72)
        c_id = res.get("cluster_id")
        host = res.get("target_host")
        actors = res.get("total_distinct_actors")
        aggs = res.get("total_aggregates_count")
        logs = res.get("total_raw_events_count")
        cri = res.get("campaign_risk_score")
        prio = res.get("priority")
        print(f"  [{idx:2d}/{len(rows)}] [{prio}] {c_id:<22} | Host: {host:<25} | CRI: {cri:3d} | Actors: {actors:3d} | Aggs: {aggs:5d} | Logs: {logs:6d}")
        reconstructed.append(res)

    print("=" * 80)
    print(f"[+] Batch Reconstruction Completed: {len(reconstructed)} Threat Campaigns successfully generated!")
    print("=" * 80)

if __name__ == "__main__":
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 15
    run_batch_reconstruction(limit)
