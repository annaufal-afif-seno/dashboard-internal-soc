"""
Threat Campaign & Multi-Layer Attack Graph Clustering Engine (Stage 4.5)
========================================================================
Post-Threat Provenance Reconstruction & Retrospective Alert Unmasking:
- Layer 1 (Spatial & Entity Graph Expansion): Bipartite heterogeneous graph via NetworkX
- Layer 2 (Temporal Sequence & Causality DAG): Monotonic ordering, velocity, & inter-arrival delta
- Layer 3 (Longitudinal History & Feedback): Cumulative entity profiles & ground truth active learning
- Retrospective Unmasking: Resurrects previously closed/benign precursor probes into unified P0/P1 campaigns
"""

import os
import json
import logging
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Set, Tuple
from decimal import Decimal
import networkx as nx
from dateutil import parser as dt_parser

from config.settings import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
from pipeline.database import DatabaseManager

logger = logging.getLogger("CampaignClustering")


class ThreatCampaignClusterer:
    """
    State-of-the-art Threat Campaign Clusterer.
    Reconstructs the full end-to-end intrusion lifecycle when an alert/ticket is declared a THREAT.
    """

    def __init__(self, db_manager: Optional[DatabaseManager] = None, default_lookback_hours: int = 72):
        self.db = db_manager or DatabaseManager()
        self.default_lookback_hours = default_lookback_hours

    def cluster_threat_campaign(
        self,
        pivot_incident: Dict[str, Any],
        lookback_hours: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Executes post-threat 3-layer clustering on the pivot incident.
        Can be triggered automatically upon AI Triage escalation or on-demand via SOC API.
        """
        incident_id = pivot_incident.get("incident_id") or "UNKNOWN_INCIDENT"
        tenant_id = pivot_incident.get("tenant_id") or "DEFAULT"
        target_host = pivot_incident.get("target_host") or "unknown_host"
        pivot_actor = pivot_incident.get("attacker_source_ip") or pivot_incident.get("actor") or "unknown_actor"
        compromised_user = pivot_incident.get("compromised_account") or pivot_incident.get("username")
        priority = pivot_incident.get("priority") or pivot_incident.get("target_severity") or "P1"

        # Resolve pivot timestamp
        ref_time = pivot_incident.get("last_seen_at") or pivot_incident.get("created_at") or datetime.now(timezone.utc)
        if isinstance(ref_time, str):
            try:
                ref_time = dt_parser.parse(ref_time)
            except Exception:
                ref_time = datetime.now(timezone.utc)
        if getattr(ref_time, "tzinfo", None) is None:
            ref_time = ref_time.replace(tzinfo=timezone.utc)

        effective_lookback = lookback_hours or self.default_lookback_hours
        lookback_start = ref_time - timedelta(hours=effective_lookback)

        logger.info(
            f"[ClusterEngine] Clustering campaign for pivot {incident_id} on {target_host} "
            f"(Lookback: {effective_lookback}h from {ref_time.isoformat()})"
        )

        # ---------------------------------------------------------------------
        # LAYER 1: Spatial & Entity Graph Expansion (Status-Agnostic Query)
        # ---------------------------------------------------------------------
        candidate_aggs = self._fetch_candidate_aggregates(target_host, tenant_id, lookback_start, ref_time)
        
        G = nx.Graph()
        target_node = f"host:{target_host}"
        G.add_node(target_node, type="HOST", label=target_host)

        for agg in candidate_aggs:
            actor = agg.get("actor") or "unknown"
            rule_id = str(agg.get("rule_id", "0"))
            w_end = agg.get("window_end") or ref_time
            if getattr(w_end, "tzinfo", None) is None:
                w_end = w_end.replace(tzinfo=timezone.utc)

            actor_node = f"actor:{actor}"
            rule_node = f"rule:{rule_id}"
            G.add_node(actor_node, type="ACTOR", label=actor)
            G.add_node(rule_node, type="RULE", label=f"Rule {rule_id}")

            # Calculate time-decay weight
            delta_sec = max(1.0, (ref_time - w_end).total_seconds())
            decay_weight = round(1.0 / (1.0 + (delta_sec / 86400.0)), 3)

            G.add_edge(actor_node, target_node, weight=decay_weight)
            G.add_edge(actor_node, rule_node, weight=1.0)

            if agg.get("username"):
                user_node = f"user:{agg['username']}"
                G.add_node(user_node, type="USER", label=agg["username"])
                G.add_edge(actor_node, user_node, weight=0.9)

        # Community partition: get all actors connected to the victim host
        if target_node in G:
            connected_nodes = nx.node_connected_component(G, target_node)
            connected_actors = {
                n.replace("actor:", "") for n in connected_nodes if n.startswith("actor:")
            }
        else:
            connected_actors = {pivot_actor}

        # Ensure pivot actor is always included
        if pivot_actor and pivot_actor != "unknown_actor":
            connected_actors.add(pivot_actor)

        # ---------------------------------------------------------------------
        # LAYER 2: Chronological Sequence DAG & Temporal Dynamics
        # ---------------------------------------------------------------------
        correlated_events = [a for a in candidate_aggs if a.get("actor") in connected_actors]
        correlated_events.sort(key=lambda x: x.get("window_start") or ref_time)

        classified_stages: List[Dict[str, Any]] = []
        tactics_chain: Set[str] = set()
        edges_to_save: List[Dict[str, Any]] = []

        for agg in correlated_events:
            w_start = agg.get("window_start") or ref_time
            if getattr(w_start, "tzinfo", None) is None:
                w_start = w_start.replace(tzinfo=timezone.utc)

            offset_sec = int((w_start - ref_time).total_seconds())
            is_pivot = (agg.get("actor") == pivot_actor and abs(offset_sec) < 3600)
            role = self._classify_event_role(agg, is_pivot)
            
            tactics = agg.get("mitre_tactics") or []
            tactics_chain.update(tactics)

            classified_stages.append({
                "aggregation_id": agg.get("aggregation_id"),
                "actor": agg.get("actor"),
                "target": agg.get("target") or target_host,
                "role": role,
                "rule_id": agg.get("rule_id"),
                "event_timestamp": w_start,
                "temporal_offset_seconds": offset_sec,
                "confidence_weight": 1.0 if is_pivot else 0.85,
                "prior_status": agg.get("status", "OPEN"),
                "evidence_summary": agg.get("rule_description") or f"Activity by {agg.get('actor')}"
            })

            # Add causality edge
            edges_to_save.append({
                "source_node": f"actor:{agg.get('actor')}",
                "target_node": f"host:{target_host}",
                "relation_type": role,
                "weight": 1.0 if is_pivot else 0.85,
                "evidence_timestamp": w_start
            })

        # ---------------------------------------------------------------------
        # LAYER 1.5: Cross-Agent Spread & Privilege Lineage Tracking
        # ---------------------------------------------------------------------
        cross_agents = self._fetch_cross_agent_spread(connected_actors, target_host, tenant_id, lookback_start, ref_time)
        privilege_lineage = self._fetch_privilege_lineage(target_host, tenant_id, lookback_start, ref_time)

        for ca in cross_agents:
            edges_to_save.append({
                "source_node": f"actor:{ca['actor']}",
                "target_node": f"host:{ca['other_host']}",
                "relation_type": "CROSS_AGENT_SPRAY",
                "weight": 0.8,
                "evidence_timestamp": ref_time
            })

        for pe in privilege_lineage.get("privilege_events", []):
            edges_to_save.append({
                "source_node": f"user:{pe['user']}",
                "target_node": f"privilege:{pe['level']}",
                "relation_type": pe.get("role", "PRIVILEGE_TRANSITION"),
                "weight": 1.0,
                "evidence_timestamp": pe["timestamp"]
            })

        # ---------------------------------------------------------------------
        # LAYER 3: Longitudinal History, Cumulative Baseline & Closed-Loop Feedback
        # ---------------------------------------------------------------------
        cumulative_info = self._fetch_cumulative_context(connected_actors, tenant_id)
        ground_truth_precedent = self._fetch_analyst_precedent(connected_actors, target_host)

        # Calculate Campaign Risk Index (0-100) & Priority
        campaign_risk_score = self._calculate_campaign_risk_index(
            pivot_incident=pivot_incident,
            stages_count=len(classified_stages),
            distinct_actors=len(connected_actors),
            cumulative_info=cumulative_info,
            ground_truth_precedent=ground_truth_precedent
        )

        cluster_id = f"CAMP-{pivot_incident.get('incident_id', 'CLUST')[-12:].upper()}"
        first_act = classified_stages[0]["event_timestamp"] if classified_stages else ref_time
        last_act = ref_time

        # Compile Attack DAG Representation
        # Prioritize key attack stages over routine background web traffic
        meaningful_stages = [
            s for s in classified_stages
            if s["role"] in ("PIVOT_COMPROMISE", "PERSISTENCE", "C2_EXFIL", "BRUTE_FORCE_SPRAY", "PRECURSOR_RECON")
        ]
        if not meaningful_stages:
            meaningful_stages = classified_stages[:100]
        else:
            meaningful_stages.sort(key=lambda x: x["event_timestamp"])
            if len(meaningful_stages) > 150:
                meaningful_stages = meaningful_stages[:30] + meaningful_stages[-120:]

        causality_dag = {
            "total_stages": len(classified_stages),
            "distinct_actors": list(connected_actors),
            "cross_agent_spread": cross_agents,
            "privilege_lineage": privilege_lineage,
            "stages": [
                {
                    "step": idx + 1,
                    "actor": s["actor"],
                    "role": s["role"],
                    "rule_id": s["rule_id"],
                    "description": s.get("evidence_summary") or f"Rule {s.get('rule_id')} event",
                    "timestamp": s["event_timestamp"].isoformat(),
                    "offset_seconds": s["temporal_offset_seconds"],
                    "prior_status": s["prior_status"]
                }
                for idx, s in enumerate(meaningful_stages)
            ]
        }

        campaign_record = {
            "cluster_id": cluster_id,
            "pivot_incident_id": incident_id,
            "pivot_triage_id": pivot_incident.get("triage_id"),
            "tenant_id": tenant_id,
            "target_host": target_host,
            "compromised_account": compromised_user,
            "campaign_title": f"Coordinated Campaign against {target_host} ({len(connected_actors)} Actors)",
            "campaign_risk_score": campaign_risk_score,
            "priority": priority,  # Invariant: Inherits highest priority
            "mitre_tactics_chain": sorted(list(tactics_chain)),
            "first_activity_at": first_act,
            "last_activity_at": last_act,
            "total_distinct_actors": len(connected_actors),
            "total_aggregates_count": max(1, len(classified_stages)),
            "total_raw_events_count": sum(a.get("event_count", 1) for a in candidate_aggs if a.get("actor") in connected_actors) or 1,
            "causality_dag": causality_dag,
            "cluster_status": "CONFIRMED_THREAT"
        }

        # ---------------------------------------------------------------------
        # PERSISTENCE & RETROSPECTIVE UNMASKING IN DATABASE
        # ---------------------------------------------------------------------
        self._persist_campaign(campaign_record, classified_stages, edges_to_save)
        self._reclassify_precursor_tickets(cluster_id, classified_stages)

        logger.info(
            f"[ClusterEngine] Successfully built campaign {cluster_id} "
            f"with {len(connected_actors)} actors and {len(classified_stages)} stages."
        )

        return campaign_record

    def _fetch_candidate_aggregates(
        self,
        target_host: str,
        tenant_id: str,
        start_time: datetime,
        end_time: datetime
    ) -> List[Dict[str, Any]]:
        """
        Status-Agnostic Fetch: Queries ALL aggregated alerts targeting the host,
        including those previously marked 'CLOSED', 'AUTO_CLOSED', or 'BENIGN'.
        """
        st_naive = start_time.replace(tzinfo=None) if getattr(start_time, "tzinfo", None) else start_time
        et_naive = end_time.replace(tzinfo=None) if getattr(end_time, "tzinfo", None) else end_time

        query = """
            SELECT
                a.aggregation_id, a.rule_id, a.actor, a.target, a.category,
                a.window_start, a.window_end, a.event_count, a.rule_description,
                a.status, a.mitre_tactics, a.distinct_ioas, a.distinct_iocs,
                q.triage_id, q.triage_status, q.resolution_outcome
            FROM suppression.aggregated_alerts a
            LEFT JOIN soc_ops.soc_triage_queue q ON (q.actor = a.actor AND q.target = a.target)
            WHERE (a.target = %s OR a.agent_id = %s)
              AND (a.tenant_id = %s OR %s IS NULL)
              AND a.window_end >= %s
              AND a.window_start <= %s
            ORDER BY a.window_start ASC;
        """
        candidates = []
        try:
            with self.db.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(query, (target_host, target_host, tenant_id, tenant_id, st_naive, et_naive))
                    for row in cur.fetchall():
                        candidates.append({
                            "aggregation_id": row[0],
                            "rule_id": row[1],
                            "actor": row[2],
                            "target": row[3],
                            "category": row[4],
                            "window_start": row[5],
                            "window_end": row[6],
                            "event_count": row[7],
                            "rule_description": row[8],
                            "status": row[9],
                            "mitre_tactics": row[10] or [],
                            "distinct_ioas": row[11] or [],
                            "distinct_iocs": row[12] or [],
                            "triage_id": row[13],
                            "triage_status": row[14],
                            "resolution_outcome": row[15]
                        })
        except Exception as e:
            logger.error(f"[ClusterEngine] Error fetching candidate aggregates: {e}")
        return candidates

    def _fetch_cross_agent_spread(
        self,
        actors: Set[str],
        target_host: str,
        tenant_id: str,
        start_time: datetime,
        end_time: datetime
    ) -> List[Dict[str, Any]]:
        """Queries whether discovered actors targeted other agents across the enterprise."""
        import re
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        # Prioritize real external attacker IPs
        clean_actors = [
            a for a in actors
            if a and ip_pattern.match(a)
            and not (a.startswith("10.") or a.startswith("192.168.") or a.startswith("172.") or a.startswith("127."))
        ]
        if not clean_actors:
            clean_actors = [
                a for a in actors
                if a and not a.startswith(("user:", "proc:", "service:", "pkg:"))
                and a not in ("unknown", "sca-scanner", "rootcheck", "vulnerability-detector")
                and not (a.startswith("10.") or a.startswith("192.168.") or a.startswith("172.") or a.startswith("127."))
            ]
        if not clean_actors:
            return []

        st_naive = start_time.replace(tzinfo=None) if getattr(start_time, "tzinfo", None) else start_time
        et_naive = end_time.replace(tzinfo=None) if getattr(end_time, "tzinfo", None) else end_time

        query = """
            SELECT actor, target, count(*) as agg_count, sum(event_count) as total_events
            FROM suppression.aggregated_alerts
            WHERE actor = ANY(%s)
              AND target != %s AND (agent_id IS NULL OR agent_id != %s)
              AND (tenant_id = %s OR %s IS NULL)
              AND window_end >= %s AND window_start <= %s
            GROUP BY actor, target
            ORDER BY total_events DESC
            LIMIT 30;
        """
        results = []
        try:
            with self.db.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(query, (clean_actors, target_host, target_host, tenant_id, tenant_id, st_naive, et_naive))
                    for row in cur.fetchall():
                        results.append({
                            "actor": row[0],
                            "other_host": row[1],
                            "agg_count": row[2],
                            "total_events": row[3]
                        })
        except Exception as e:
            logger.warning(f"[ClusterEngine] Cross-agent fetch warning: {e}")
        return results

    def _fetch_privilege_lineage(
        self,
        target_host: str,
        tenant_id: str,
        start_time: datetime,
        end_time: datetime
    ) -> Dict[str, Any]:
        """Tracks account authentication, sudo execution, and privilege escalation to root."""
        st_naive = start_time.replace(tzinfo=None) if getattr(start_time, "tzinfo", None) else start_time
        et_naive = end_time.replace(tzinfo=None) if getattr(end_time, "tzinfo", None) else end_time

        query = """
            SELECT actor, rule_id, rule_description, event_count, window_start
            FROM suppression.aggregated_alerts
            WHERE (target = %s OR agent_id = %s)
              AND (tenant_id = %s OR %s IS NULL)
              AND (
                  actor ILIKE 'user:%%' OR actor ILIKE '%%root%%' OR
                  rule_id IN (5402, 5403, 5405, 5406, 5407, 5501, 5502, 5503, 5715, 5716, 5760, 5901, 5902)
              )
              AND window_end >= %s AND window_start <= %s
            ORDER BY window_start ASC;
        """
        lineage = {
            "has_root_compromise": False,
            "entry_users": [],
            "escalated_users": [],
            "privilege_events": []
        }
        try:
            with self.db.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(query, (target_host, target_host, tenant_id, tenant_id, st_naive, et_naive))
                    for row in cur.fetchall():
                        actor, rule_id, rule_desc, count, w_start = row
                        clean_user = actor.replace("user:", "") if actor.startswith("user:") else actor
                        is_root = (clean_user == "root" or rule_id in (5407, 5715))
                        if is_root:
                            lineage["has_root_compromise"] = True
                            if clean_user not in lineage["escalated_users"]:
                                lineage["escalated_users"].append(clean_user)
                        else:
                            if clean_user not in lineage["entry_users"]:
                                lineage["entry_users"].append(clean_user)

                        level = "ROOT_UID_0" if is_root else "STANDARD_USER"
                        lineage["privilege_events"].append({
                            "user": clean_user,
                            "rule_id": rule_id,
                            "level": level,
                            "role": "SUDO_ESCALATION" if rule_id == 5407 else ("AUTH_SUCCESS" if rule_id == 5715 else "SESSION_ACTIVITY"),
                            "description": rule_desc,
                            "timestamp": w_start.isoformat() if hasattr(w_start, "isoformat") else str(w_start)
                        })
        except Exception as e:
            logger.warning(f"[ClusterEngine] Privilege lineage fetch warning: {e}")
        return lineage

    def _classify_event_role(self, agg: Dict[str, Any], is_pivot: bool) -> str:
        """Classifies event role within the MITRE kill-chain."""
        cat = str(agg.get("category") or "").upper()
        rule_desc = str(agg.get("rule_description") or "").upper()
        rule_id = str(agg.get("rule_id") or "")

        if is_pivot or "INITIAL_ACCESS" in cat or "AUTH_SUCCESS" in cat or rule_id in ("5715", "100050", "31106", "31430") or "200 (SUCCESS)" in rule_desc:
            return "PIVOT_COMPROMISE"
        if "RECON" in cat or "DISCOVERY" in cat or "SCANNER" in rule_desc or rule_id in ("100002", "100003", "31151"):
            return "PRECURSOR_RECON"
        if "AUTH_FAILURE" in cat or "CREDENTIAL" in cat or rule_id in ("5716", "5710"):
            return "BRUTE_FORCE_SPRAY"
        if "LATERAL" in cat:
            return "LATERAL_MOVE"
        if "PERSISTENCE" in cat or "PRIVILEGE_ESCALATION" in cat or rule_id in ("5407", "550", "5901", "5902"):
            return "PERSISTENCE"
        if "COMMAND_AND_CONTROL" in cat or "EXFILTRATION" in cat:
            return "C2_EXFIL"
        return "GENERAL_ACTIVITY"

    def _fetch_cumulative_context(self, actors: Set[str], tenant_id: str) -> Dict[str, Any]:
        """Queries suppression.cumulative_alerts for lifetime sightings and dormancy status."""
        if not actors:
            return {"max_sightings": 0, "dormant_actors": []}

        actor_list = list(actors)
        query = """
            SELECT actor, sighting_count, status, first_seen_at, last_seen_at, peak_risk_score
            FROM suppression.cumulative_alerts
            WHERE actor = ANY(%s) AND (tenant_id = %s OR %s IS NULL);
        """
        info = {"max_sightings": 0, "dormant_actors": [], "lifetime_records": len(actors)}
        try:
            with self.db.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(query, (actor_list, tenant_id, tenant_id))
                    for row in cur.fetchall():
                        act, sightings, status, f_seen, l_seen, peak = row
                        if sightings and sightings > info["max_sightings"]:
                            info["max_sightings"] = sightings
                        if status == "DORMANT":
                            info["dormant_actors"].append(act)
        except Exception as e:
            logger.warning(f"[ClusterEngine] Cumulative context fetch warning: {e}")
        return info

    def _fetch_analyst_precedent(self, actors: Set[str], target_host: str) -> Dict[str, Any]:
        """Queries soc_ops.ground_truth_dataset for historical analyst verdicts."""
        result = {"has_true_positive_precedent": False, "precedent_confidence": 0.0}
        try:
            with self.db.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT ground_truth_label, resolution_outcome, ml_tier1_confidence
                        FROM soc_ops.ground_truth_dataset
                        WHERE target_host = %s AND ground_truth_label = 1
                        ORDER BY recorded_at DESC
                        LIMIT 1;
                    """, (target_host,))
                    row = cur.fetchone()
                    if row:
                        result["has_true_positive_precedent"] = True
                        result["precedent_confidence"] = float(row[2] or 90.0)
        except Exception:
            pass
        return result

    def _calculate_campaign_risk_index(
        self,
        pivot_incident: Dict[str, Any],
        stages_count: int,
        distinct_actors: int,
        cumulative_info: Dict[str, Any],
        ground_truth_precedent: Dict[str, Any]
    ) -> int:
        """Calculates a calibrated Campaign Risk Index (CRI) 0-100."""
        base_score = 60
        if pivot_incident.get("priority") == "P0":
            base_score = 85
        elif pivot_incident.get("priority") == "P1":
            base_score = 75

        # Penalty for distributed actors (multi-IP coordination)
        actor_bonus = min(15, (distinct_actors - 1) * 5)
        # Stages depth bonus
        stage_bonus = min(15, stages_count * 3)
        # Precedent bonus
        prec_bonus = 10 if ground_truth_precedent.get("has_true_positive_precedent") else 0
        # Dormancy anomaly bonus
        dormant_bonus = 10 if cumulative_info.get("dormant_actors") else 0

        final_cri = min(100, max(0, base_score + actor_bonus + stage_bonus + prec_bonus + dormant_bonus))
        return int(final_cri)

    def _persist_campaign(
        self,
        campaign: Dict[str, Any],
        stages: List[Dict[str, Any]],
        edges: List[Dict[str, Any]]
    ):
        """Persists the cluster, member links, and graph edges to PostgreSQL."""
        c_id = campaign["cluster_id"]
        try:
            with self.db.get_connection() as conn:
                with conn.cursor() as cur:
                    # 1. Upsert threat_campaign_clusters
                    cur.execute("""
                        INSERT INTO correlation.threat_campaign_clusters (
                            cluster_id, pivot_incident_id, pivot_triage_id, tenant_id,
                            target_host, compromised_account, campaign_title,
                            campaign_risk_score, priority, mitre_tactics_chain,
                            first_activity_at, last_activity_at, total_distinct_actors,
                            total_aggregates_count, total_raw_events_count, causality_dag,
                            cluster_status, updated_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                        ON CONFLICT (cluster_id) DO UPDATE SET
                            campaign_risk_score = EXCLUDED.campaign_risk_score,
                            total_distinct_actors = EXCLUDED.total_distinct_actors,
                            total_aggregates_count = EXCLUDED.total_aggregates_count,
                            total_raw_events_count = EXCLUDED.total_raw_events_count,
                            causality_dag = EXCLUDED.causality_dag,
                            updated_at = CURRENT_TIMESTAMP;
                    """, (
                        c_id, campaign["pivot_incident_id"], campaign.get("pivot_triage_id"),
                        campaign["tenant_id"], campaign["target_host"], campaign.get("compromised_account"),
                        campaign["campaign_title"], campaign["campaign_risk_score"], campaign["priority"],
                        campaign["mitre_tactics_chain"], campaign["first_activity_at"], campaign["last_activity_at"],
                        campaign["total_distinct_actors"], campaign["total_aggregates_count"],
                        campaign["total_raw_events_count"], json.dumps(campaign["causality_dag"], default=str),
                        campaign["cluster_status"]
                    ))

                    # 2. Insert cluster_members
                    cur.execute("DELETE FROM correlation.cluster_members WHERE cluster_id = %s;", (c_id,))
                    for s in stages:
                        cur.execute("""
                            INSERT INTO correlation.cluster_members (
                                cluster_id, aggregation_id, entity_role, actor_entity,
                                target_entity, rule_id, event_timestamp, temporal_offset_seconds,
                                confidence_weight, prior_status, evidence_summary
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                        """, (
                            c_id, s.get("aggregation_id"), s["role"], s["actor"],
                            s["target"], s.get("rule_id"), s["event_timestamp"],
                            s["temporal_offset_seconds"], s["confidence_weight"],
                            s.get("prior_status", "OPEN"), s.get("evidence_summary")
                        ))

                    # 3. Insert cluster_causality_edges
                    cur.execute("DELETE FROM correlation.cluster_causality_edges WHERE cluster_id = %s;", (c_id,))
                    for e in edges:
                        cur.execute("""
                            INSERT INTO correlation.cluster_causality_edges (
                                cluster_id, source_node, target_node, relation_type, weight, evidence_timestamp
                            ) VALUES (%s, %s, %s, %s, %s, %s);
                        """, (
                            c_id, e["source_node"], e["target_node"],
                            e["relation_type"], e["weight"], e["evidence_timestamp"]
                        ))
            logger.info(f"[ClusterEngine] Persisted campaign {c_id} to database.")
        except Exception as e:
            logger.error(f"[ClusterEngine] Failed to persist campaign {c_id}: {e}")

    def _reclassify_precursor_tickets(self, cluster_id: str, stages: List[Dict[str, Any]]):
        """
        Retrospective Unmasking: Updates previously benign or holding tickets
        to indicate they have been unmasked and subsumed as precursors into the campaign.
        """
        precursor_aggs = [s.get("aggregation_id") for s in stages if s.get("role") in ("PRECURSOR_RECON", "BRUTE_FORCE_SPRAY") and s.get("aggregation_id")]
        if not precursor_aggs:
            return

        try:
            with self.db.get_connection() as conn:
                with conn.cursor() as cur:
                    # Update soc_triage_queue where induk_aggregation_id in precursor_aggs
                    cur.execute("""
                        UPDATE soc_ops.soc_triage_queue
                        SET false_positive_reason = 'Unmasked: Subsumed as precursor into ' || %s,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE induk_aggregation_id = ANY(%s)
                          AND triage_status IN ('CLOSE', 'AUTO_CLOSED', 'CLOSED', 'WAITING_SLA');
                    """, (cluster_id, precursor_aggs))
            logger.info(f"[ClusterEngine] Reclassified precursor tickets for cluster {cluster_id}")
        except Exception as e:
            logger.warning(f"[ClusterEngine] Reclassification note: {e}")
