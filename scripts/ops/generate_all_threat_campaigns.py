"""
Generate all Threat Campaign Attack Graph Clusters
===================================================
1. Selects the canonical pivot threat incident for each victim target host.
2. Executes 3-layer graph clustering with retrospective unmasking.
3. Persists consolidated attack graphs, member stages, and causality edges.
4. Executes SANS FOR508 Layer-2 session consolidation.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import psycopg2
from pipeline.campaign_clustering import ThreatCampaignClusterer
from scripts.reconstruct_all_campaigns import run_batch_reconstruction
import config.settings as s
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("GenerateAllCampaigns")

def generate_all():
    conn = psycopg2.connect(
        host=s.DB_HOST, port=s.DB_PORT, dbname=s.DB_NAME, user=s.DB_USER, password=s.DB_PASSWORD
    )
    cur = conn.cursor()

    logger.info("[*] Finding canonical pivot incident for each victim target host...")
    cur.execute("""
        WITH ranked AS (
            SELECT 
                i.*, q.triage_id, q.priority as triage_priority,
                ROW_NUMBER() OVER (
                    PARTITION BY i.target_host 
                    ORDER BY 
                        CASE q.priority WHEN 'P0' THEN 1 WHEN 'P1' THEN 2 WHEN 'P2' THEN 3 ELSE 4 END,
                        i.first_seen_at ASC
                ) as rn
            FROM correlation.correlated_incidents i
            JOIN soc_ops.soc_triage_queue q ON i.incident_id = q.incident_id
            WHERE i.incident_status = 'ESCALATED'
        )
        SELECT * FROM ranked WHERE rn = 1;
    """)
    cols = [desc[0] for desc in cur.description]
    pivots = [dict(zip(cols, r)) for r in cur.fetchall()]
    logger.info(f"[*] Found {len(pivots)} distinct threat target hosts to cluster.")

    cur.close()
    conn.close()

    clusterer = ThreatCampaignClusterer()

    for idx, inc in enumerate(pivots, 1):
        target = inc.get("target_host")
        prio = inc.get("triage_priority") or inc.get("priority")
        inc["priority"] = prio
        logger.info(f"[{idx}/{len(pivots)}] Clustering target '{target}' (Pivot: {inc.get('incident_id')}, {prio})...")
        try:
            res = clusterer.cluster_threat_campaign(inc)
            logger.info(f"    -> Created cluster: {res.get('cluster_id')} | Title: {res.get('campaign_title')}")
        except Exception as e:
            logger.error(f"    -> Failed for {target}: {e}")

    logger.info("[*] Running SANS FOR508 Layer-2 Session Consolidation...")
    try:
        run_batch_reconstruction()
    except Exception as e:
        logger.warning(f"Note on consolidation: {e}")

    conn = psycopg2.connect(
        host=s.DB_HOST, port=s.DB_PORT, dbname=s.DB_NAME, user=s.DB_USER, password=s.DB_PASSWORD
    )
    cur = conn.cursor()
    cur.execute("SELECT count(*) FROM correlation.threat_campaign_clusters;")
    total_clust = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM correlation.cluster_members;")
    total_mem = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM correlation.cluster_causality_edges;")
    total_edges = cur.fetchone()[0]

    logger.info("=" * 80)
    logger.info(f"[SUCCESS] All Threat Campaigns Generated:")
    logger.info(f"  • Total Campaigns (threat_campaign_clusters): {total_clust}")
    logger.info(f"  • Total Forensic Members (cluster_members):   {total_mem:,}")
    logger.info(f"  • Total Causality Edges (cluster_causality_edges): {total_edges:,}")
    logger.info("=" * 80)
    cur.close()
    conn.close()

if __name__ == "__main__":
    generate_all()
