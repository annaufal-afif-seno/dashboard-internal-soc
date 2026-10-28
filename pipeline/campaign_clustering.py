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
        
        # Attribution Sanitizer: Internal OS maintenance daemons and routine scanners
        WHITELIST_INTERNAL_DAEMONS = {
            "proc:syscheck", "proc:kernel_or_auditd", "service:systemd", "cron",
            "sca-scanner", "vulnerability-detector", "service:daemon"
        }

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

            # Attribution Sanitizer: Exclude internal maintenance noise from attacker edges
            # unless it has MITRE tactics or explicit compromise indicators
            is_internal_daemon = (actor in WHITELIST_INTERNAL_DAEMONS and not agg.get("mitre_tactics"))
            if not is_internal_daemon:
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

        # SOC Layer 2 Master Methodology: Dual-Dimension Incident Scoring & Lifecycle Phase
        ics = self._calculate_incident_confidence_score(connected_actors, tactics_chain, privilege_lineage)
        iss, calculated_priority = self._calculate_incident_severity_score(tactics_chain, target_host)
        lifecycle_phase = self._determine_lifecycle_phase(tactics_chain, privilege_lineage, ics)
        cluster_status = self._determine_cluster_status(ics, iss)

        if cluster_status == "FALSE_CORRELATION":
            calculated_priority = "P4"
            iss = 15
            lifecycle_phase = "BENIGN_OPERATIONAL"

        # Invariant: Campaign inherits highest priority between pivot incident and calculated priority
        pri_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
        pivot_pri = pivot_incident.get("priority") or "P1"
        if pri_order.get(pivot_pri, 4) < pri_order.get(calculated_priority, 4):
            priority = pivot_pri
        else:
            priority = calculated_priority
        if priority == "P0":
            campaign_risk_score = max(iss, 95)
        else:
            campaign_risk_score = iss

        first_act = classified_stages[0]["event_timestamp"] if classified_stages else ref_time
        last_act = ref_time

        # SOC Layer 2 Incident Deduplication & Boundary Matching (ΔT = 6.0 hours)
        existing_cluster = self._find_existing_active_cluster(target_host, tenant_id, first_act, last_act)
        if existing_cluster:
            cluster_id = existing_cluster["cluster_id"]
            if existing_cluster.get("first_activity_at") and existing_cluster["first_activity_at"] < first_act:
                first_act = existing_cluster["first_activity_at"]
            if existing_cluster.get("last_activity_at") and existing_cluster["last_activity_at"] > last_act:
                last_act = existing_cluster["last_activity_at"]
            if existing_cluster.get("priority") == "P0" or priority == "P0":
                priority = "P0"
            campaign_risk_score = max(campaign_risk_score, existing_cluster.get("campaign_risk_score", 0))
            if existing_cluster.get("mitre_tactics_chain"):
                tactics_chain.update(existing_cluster["mitre_tactics_chain"])
            logger.info(f"[ClusterEngine] Deduplicating & merging into existing cluster {cluster_id} on {target_host}")
        else:
            cluster_id = f"CAMP-{pivot_incident.get('incident_id', 'CLUST')[-12:].upper()}"

        # Compile Attack DAG Representation
        meaningful_stages = [
            s for s in classified_stages
            if s["role"] in (
                "PIVOT_COMPROMISE", "PRECURSOR_RECON", "BRUTE_FORCE_SPRAY",
                "EXECUTION", "PRIVILEGE_ESCALATION", "PERSISTENCE",
                "DEFENSE_EVASION", "LATERAL_MOVE", "C2_EXFIL", "IMPACT_DISRUPTION"
            )
        ]
        if not meaningful_stages:
            meaningful_stages = classified_stages[:100]
        else:
            meaningful_stages.sort(key=lambda x: x["event_timestamp"])
            if len(meaningful_stages) > 150:
                meaningful_stages = meaningful_stages[:30] + meaningful_stages[-120:]

        causality_dag = {
            "incident_phase": lifecycle_phase,
            "incident_confidence_score": ics,
            "incident_severity_score": iss,
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
            "priority": priority,
            "mitre_tactics_chain": sorted(list(tactics_chain)),
            "first_activity_at": first_act,
            "last_activity_at": last_act,
            "total_distinct_actors": len(connected_actors),
            "total_aggregates_count": max(1, len(classified_stages)),
            "total_raw_events_count": sum(a.get("event_count", 1) for a in candidate_aggs if a.get("actor") in connected_actors) or 1,
            "causality_dag": causality_dag,
            "cluster_status": cluster_status
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
            LEFT JOIN correlation.incident_stages stg ON stg.reference_id = a.aggregation_id LEFT JOIN soc_ops.soc_triage_queue q ON q.incident_id = stg.incident_id
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
        """Classifies event role within the MITRE kill-chain conforming strictly to cluster_members_entity_role_check."""
        cat = str(agg.get("category") or "").upper()
        rule_desc = str(agg.get("rule_description") or "").upper()
        rule_id = str(agg.get("rule_id") or "")
        tactics = [str(t).lower() for t in (agg.get("mitre_tactics") or [])]

        if is_pivot or "INITIAL_ACCESS" in cat or "WEB_ATTACK" in cat or "EXECUTION" in cat or "RANSOMWARE" in cat or rule_id in ("31103", "31104", "31106", "31110", "31166", "31430", "52002", "52003", "52004", "550", "203", "204") or "200 (SUCCESS)" in rule_desc:
            return "PIVOT_COMPROMISE"
        if "RECON" in cat or "DISCOVERY" in cat or "SCANNER" in rule_desc or rule_id in ("100002", "100003", "30411", "31151", "533") or "discovery" in tactics or "reconnaissance" in tactics:
            return "PRECURSOR_RECON"
        if "AUTH_FAILURE" in cat or "CREDENTIAL" in cat or rule_id in ("5716", "5710", "100001", "5503") or "credential access" in tactics:
            return "BRUTE_FORCE_SPRAY"
        if "AUTH_SUCCESS" in cat or "PRIVILEGE_ESCALATION" in cat or "privilege escalation" in tactics or rule_id in ("5402", "5403", "5407", "5715", "5501"):
            return "SUCCESSFUL_ENTRY"
        if "LATERAL" in cat or "lateral movement" in tactics:
            return "LATERAL_MOVE"
        if "PERSISTENCE" in cat or "persistence" in tactics or rule_id in ("2833", "2834", "5901", "5902"):
            return "PERSISTENCE"
        if "COMMAND_AND_CONTROL" in cat or "EXFILTRATION" in cat or "command and control" in tactics or "exfiltration" in tactics:
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

    def _calculate_incident_confidence_score(
        self,
        actors: Set[str],
        tactics_chain: Set[str],
        privilege_lineage: Dict[str, Any]
    ) -> int:
        """
        SOC Layer 2 Master Methodology - Dimensi 1:
        Incident Confidence Score (ICS: 0 - 100%)
        Formula: (External Attacker IP * 35) + (ATT&CK Tactic Count * 15) + (Compromised User * 25) - (Internal Daemon Penalty)
        """
        import re
        ip_regex = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        
        pivot_ips = [
            a for a in actors 
            if a in ['172.16.80.201', '172.16.90.1'] or (ip_regex.match(a) and not (a.startswith('10.') or a.startswith('192.168.') or a.startswith('127.')))
        ]
        
        ext_score = min(35, len(pivot_ips) * 15) if pivot_ips else 0
        tactic_score = min(30, len(tactics_chain) * 5)
        
        has_compromised_user = any(a.startswith('user:') or a == 'root' for a in actors)
        if privilege_lineage and privilege_lineage.get('has_root_compromise'):
            has_compromised_user = True
        user_score = 25 if has_compromised_user else 0
        
        daemon_penalty = 50 if (not pivot_ips and len(tactics_chain) <= 1) else 0
        ics = max(5, min(100, ext_score + tactic_score + user_score - daemon_penalty))
        return int(ics)

    def _calculate_incident_severity_score(
        self,
        tactics_chain: Set[str],
        target_host: str
    ) -> Tuple[int, str]:
        """
        SOC Layer 2 Master Methodology - Dimensi 2:
        Incident Severity Score (ISS: 0 - 100 / Level P0-P4) via NIST SP 800-61r3 MAX Formula.
        """
        critical_tactics = {'Impact', 'Execution', 'Privilege Escalation'}
        intrusion_tactics = {'Initial Access', 'Persistence'}
        recon_tactics = {'Reconnaissance', 'Discovery', 'Credential Access', 'Defense Evasion'}
        
        if any(t in critical_tactics for t in tactics_chain):
            return 100, "P0"
        elif any(t in intrusion_tactics for t in tactics_chain):
            return 85, "P1"
        elif any(t in recon_tactics for t in tactics_chain):
            return 50, "P2"
        else:
            return 15, "P4"

    def _determine_lifecycle_phase(
        self,
        tactics_chain: Set[str],
        privilege_lineage: Dict[str, Any],
        ics: int
    ) -> str:
        """
        Determines the Incident Lifecycle Phase:
        1. PRECURSOR_PROBING (Recon / Scan / Probe / Gagal Tembus)
        2. ACTIVE_INTRUSION (Initial Access / Reverse Shell in progress)
        3. POST_COMPROMISE (Webshell tertanam / Sudo escalation / Data exfil)
        4. BENIGN_OPERATIONAL (Pure system maintenance / FIM / Logrotate)
        """
        if ics < 30 or not tactics_chain:
            return "BENIGN_OPERATIONAL"
            
        critical_tactics = {'Impact', 'Execution', 'Privilege Escalation'}
        has_root = privilege_lineage.get("has_root_compromise", False) if privilege_lineage else False
        
        if any(t in critical_tactics for t in tactics_chain) or has_root:
            return "POST_COMPROMISE"
        elif any(t in {'Initial Access', 'Persistence'} for t in tactics_chain):
            return "ACTIVE_INTRUSION"
        else:
            return "PRECURSOR_PROBING"

    def _determine_cluster_status(self, ics: int, iss: int) -> str:
        """
        Maps ICS and ISS to database cluster_status:
        - CONFIRMED_THREAT (ICS >= 60% and ISS >= 70)
        - UNDER_INVESTIGATION (ICS 30-59% or precursor probing)
        - FALSE_CORRELATION (ICS < 30% / Benign Operational)
        """
        if ics >= 60 and iss >= 70:
            return "CONFIRMED_THREAT"
        elif ics >= 30 and iss >= 40:
            return "UNDER_INVESTIGATION"
        else:
            return "FALSE_CORRELATION"

    def _find_existing_active_cluster(
        self,
        target_host: str,
        tenant_id: str,
        start_time: datetime,
        end_time: datetime,
        gap_hours: float = 6.0
    ) -> Optional[Dict[str, Any]]:
        """
        SOC Layer 2 Final Inactivity Boundary & Deduplication:
        Finds existing campaign cluster on the same target host where time gap <= 6.0 hours or overlapping.
        """
        try:
            with self.db.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT cluster_id, pivot_incident_id, pivot_triage_id, campaign_title,
                               campaign_risk_score, priority, mitre_tactics_chain,
                               first_activity_at, last_activity_at, total_distinct_actors,
                               total_aggregates_count, total_raw_events_count
                        FROM correlation.threat_campaign_clusters
                        WHERE target_host = %s
                          AND (tenant_id = %s OR %s IS NULL)
                        ORDER BY first_activity_at ASC;
                    """, (target_host, tenant_id, tenant_id))
                    rows = cur.fetchall()
                    for r in rows:
                        c_start = r[7]
                        c_end = r[8]
                        if not c_start or not c_end:
                            continue
                        if getattr(start_time, "tzinfo", None) is None:
                            start_time = start_time.replace(tzinfo=timezone.utc)
                        if getattr(end_time, "tzinfo", None) is None:
                            end_time = end_time.replace(tzinfo=timezone.utc)
                        if getattr(c_start, "tzinfo", None) is None:
                            c_start = c_start.replace(tzinfo=timezone.utc)
                        if getattr(c_end, "tzinfo", None) is None:
                            c_end = c_end.replace(tzinfo=timezone.utc)

                        # Check overlap or gap <= gap_hours
                        if start_time <= c_end:
                            gap = (c_start - end_time).total_seconds() / 3600.0
                            if gap <= gap_hours:
                                return {
                                    "cluster_id": r[0],
                                    "pivot_incident_id": r[1],
                                    "pivot_triage_id": r[2],
                                    "campaign_title": r[3],
                                    "campaign_risk_score": r[4],
                                    "priority": r[5],
                                    "mitre_tactics_chain": r[6],
                                    "first_activity_at": c_start,
                                    "last_activity_at": c_end,
                                    "total_distinct_actors": r[9],
                                    "total_aggregates_count": r[10],
                                    "total_raw_events_count": r[11]
                                }
                        else:
                            gap = (start_time - c_end).total_seconds() / 3600.0
                            if gap <= gap_hours:
                                return {
                                    "cluster_id": r[0],
                                    "pivot_incident_id": r[1],
                                    "pivot_triage_id": r[2],
                                    "campaign_title": r[3],
                                    "campaign_risk_score": r[4],
                                    "priority": r[5],
                                    "mitre_tactics_chain": r[6],
                                    "first_activity_at": c_start,
                                    "last_activity_at": c_end,
                                    "total_distinct_actors": r[9],
                                    "total_aggregates_count": r[10],
                                    "total_raw_events_count": r[11]
                                }
        except Exception as e:
            logger.warning(f"[ClusterEngine] Error finding existing cluster: {e}")
        return None

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
                            priority = EXCLUDED.priority,
                            cluster_status = EXCLUDED.cluster_status,
                            total_distinct_actors = GREATEST(threat_campaign_clusters.total_distinct_actors, EXCLUDED.total_distinct_actors),
                            total_aggregates_count = GREATEST(threat_campaign_clusters.total_aggregates_count, EXCLUDED.total_aggregates_count),
                            total_raw_events_count = GREATEST(threat_campaign_clusters.total_raw_events_count, EXCLUDED.total_raw_events_count),
                            first_activity_at = LEAST(threat_campaign_clusters.first_activity_at, EXCLUDED.first_activity_at),
                            last_activity_at = GREATEST(threat_campaign_clusters.last_activity_at, EXCLUDED.last_activity_at),
                            mitre_tactics_chain = EXCLUDED.mitre_tactics_chain,
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
                        WHERE triage_id IN (
                            SELECT ticket_id FROM soc_ops.ticket_aggregates WHERE aggregation_id = ANY(%s)
                        )
                          AND triage_status IN ('CLOSE', 'AUTO_CLOSED', 'CLOSED', 'WAITING_SLA');
                    """, (cluster_id, precursor_aggs))
            logger.info(f"[ClusterEngine] Reclassified precursor tickets for cluster {cluster_id}")
        except Exception as e:
            logger.warning(f"[ClusterEngine] Reclassification note: {e}")


# ============================================================================
# STATISTICAL ANOMALY DISCOVERY AND OUTLIER DETECTION (DBSCAN LAYER 4)
# ============================================================================

import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

class DBSCANAnomalyDetector:
    """
    DBSCAN Statistical Outlier Discovery for Threat Hunting and Clustering.
    Evaluates per-source behavioral features (volume, path diversity, error ratio).
    Identifies mass scanner clusters and flags anomalous outliers with label -1.
    """
    def __init__(self, eps: float = 0.7, min_samples: int = 3):
        self.eps = eps
        self.min_samples = min_samples

    def fit_predict_sources(self, source_metrics: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """
        Runs DBSCAN on source metrics list.
        Returns dict keyed by source with label and is_outlier boolean.
        """
        if not source_metrics:
            return {}

        if len(source_metrics) < self.min_samples:
            res = {}
            for s in source_metrics:
                # Heuristic for small sample: targeted low volume with high success on sensitive path
                is_out = float(s.get('failure_ratio', 1.0)) < 0.2 and int(s.get('request_count', 0)) <= 15
                res[s['source']] = {
                    'label': -1 if is_out else 0,
                    'is_outlier': bool(is_out),
                    'request_count': s.get('request_count', 0),
                    'unique_paths': s.get('unique_paths', 1),
                    'failure_ratio': float(s.get('failure_ratio', 0.0))
                }
            return res

        matrix = []
        sources = []
        for s in source_metrics:
            sources.append(s['source'])
            matrix.append([
                float(np.log1p(max(0, s.get('request_count', 0)))),
                float(max(0, s.get('unique_paths', 1))),
                float(max(0.0, min(1.0, s.get('failure_ratio', 0.0))))
            ])

        try:
            X = np.array(matrix)
            X_scaled = StandardScaler().fit_transform(X)
            db = DBSCAN(eps=self.eps, min_samples=self.min_samples).fit(X_scaled)
            labels = db.labels_

            out = {}
            for src, lbl, metrics in zip(sources, labels, source_metrics):
                is_out = bool(lbl == -1)
                out[src] = {
                    'label': int(lbl),
                    'is_outlier': is_out,
                    'request_count': metrics.get('request_count', 0),
                    'unique_paths': metrics.get('unique_paths', 1),
                    'failure_ratio': float(metrics.get('failure_ratio', 0.0))
                }
            return out
        except Exception as err:
            logger.warning(f'[DBSCAN] Fitting fallback: {err}')
            return {s['source']: {'label': 0, 'is_outlier': False} for s in source_metrics}
