"""
PostgreSQL High-Performance Database Manager & Ingestion Engine
Handles Connection Pooling, Batch Insertions, Stored Procedures, and Incident Triage Persistence
Production Hardened: Includes Bulk Inserters for Incidents, Stages, Factors, Scores, and Triage Queue
"""
import os
import glob
import logging
from typing import List, Dict, Any, Optional, Tuple
from contextlib import contextmanager
from datetime import datetime, date, timedelta, timezone
import json
import psycopg2
from psycopg2 import pool, extras
from psycopg2.extras import execute_values

from pipeline.score import SLA_MATRIX_MINUTES

from config.settings import (
    DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD,
    DB_MINCONN, DB_MAXCONN, DB_SYNCHRONOUS_COMMIT, BASE_DIR
)

logger = logging.getLogger("pipeline.database")


class DatabaseManager:
    """
    Threaded Connection Pool Manager for high-throughput PostgreSQL operations.
    Provides batch ingestion utilities, transactional execution, and partition automation.
    """

    def __init__(
        self,
        host: str = DB_HOST,
        port: int = DB_PORT,
        dbname: str = DB_NAME,
        user: str = DB_USER,
        password: str = DB_PASSWORD,
        minconn: int = DB_MINCONN,
        maxconn: int = DB_MAXCONN,
    ):
        self.host = host
        self.port = port
        self.dbname = dbname
        self.user = user
        self.password = password
        self.minconn = minconn
        self.maxconn = maxconn
        self._pool: Optional[pool.ThreadedConnectionPool] = None

    def initialize_pool(self) -> bool:
        """Initialize the connection pool. Returns True if successful, False if DB unreachable."""
        if self._pool is not None:
            return True
        try:
            self._pool = pool.ThreadedConnectionPool(
                minconn=self.minconn,
                maxconn=self.maxconn,
                host=self.host,
                port=self.port,
                dbname=self.dbname,
                user=self.user,
                password=self.password,
                connect_timeout=3
            )
            logger.info(f"Database connection pool initialized: {self.dbname}@{self.host}:{self.port}")
            return True
        except Exception as e:
            logger.warning(f"Could not connect to PostgreSQL ({e}). Operating in standalone/offline mode.")
            self._pool = None
            return False

    @contextmanager
    def get_connection(self):
        """Context manager to obtain and release a connection from the pool."""
        if self._pool is None:
            if not self.initialize_pool():
                raise ConnectionError("PostgreSQL pool not available.")

        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("SET search_path TO telemetry, enrichment, suppression, correlation, risk_engine, soc_ops, metrics, public;")
                if DB_SYNCHRONOUS_COMMIT:
                    cur.execute(f"SET synchronous_commit TO {DB_SYNCHRONOUS_COMMIT};")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            if self._pool and conn:
                self._pool.putconn(conn)

    def run_migrations(self, migration_sql_path: Optional[str] = None) -> bool:
        """Execute DDL migration scripts in sequential order."""
        if migration_sql_path is not None:
            migration_files = [migration_sql_path]
        else:
            migrations_dir = BASE_DIR / "database" / "migrations"
            if not migrations_dir.exists():
                raise FileNotFoundError(f"Migrations directory not found: {migrations_dir}")
            migration_files = sorted(glob.glob(str(migrations_dir / "*.sql")))

        all_ok = True
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS public.schema_migrations (
                            version VARCHAR(255) PRIMARY KEY,
                            applied_at TIMESTAMPTZ DEFAULT NOW()
                        );
                    """)
                    cur.execute("SELECT version FROM public.schema_migrations;")
                    applied_versions = {row[0] for row in cur.fetchall()}
        except Exception as e:
            logger.error(f"Failed to initialize schema_migrations tracking table: {e}")
            applied_versions = set()

        for m_path in migration_files:
            if not os.path.exists(m_path):
                raise FileNotFoundError(f"Migration file not found: {m_path}")

            m_name = os.path.basename(m_path)
            if m_name in applied_versions and migration_sql_path is None:
                logger.debug(f"Migration {m_name} already applied, skipping.")
                continue

            with open(m_path, "r", encoding="utf-8") as f:
                sql_script = f.read()

            try:
                with self.get_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(sql_script)
                        cur.execute(
                            "INSERT INTO public.schema_migrations (version) VALUES (%s) ON CONFLICT (version) DO NOTHING;",
                            (m_name,)
                        )
                logger.info(f"Successfully executed database migration: {m_name}")
            except Exception as e:
                logger.error(f"Migration failed for {m_name}: {e}")
                all_ok = False
                break
        return all_ok

    def run_seed_data(self, seed_sql_path: Optional[str] = None) -> bool:
        """Execute the master reference and seed data script."""
        if seed_sql_path is None:
            seed_sql_path = str(BASE_DIR / "database" / "seed_data.sql")

        if not os.path.exists(seed_sql_path):
            raise FileNotFoundError(f"Seed file not found: {seed_sql_path}")

        with open(seed_sql_path, "r", encoding="utf-8") as f:
            seed_script = f.read()

        try:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(seed_script)
            logger.info("Successfully loaded master seed data.")
            return True
        except Exception as e:
            logger.error(f"Seed data insertion failed: {e}")
            return False

    def bulk_insert_raw_events(self, events: List[Dict[str, Any]]) -> int:
        """Bulk insert raw events using psycopg2 execute_values for high throughput."""
        if not events:
            return 0

        query = """
        INSERT INTO raw_events (
            event_id, timestamp, agent_id, tenant_id, agent_name, agent_ip,
            source_ip, destination_ip, source_port, destination_port, protocol,
            username, location, decoder_name, raw_payload
        ) VALUES %s
        ON CONFLICT (event_id, timestamp) DO NOTHING;
        """

        records = [
            (
                e.get("event_id"),
                e.get("timestamp"),
                e.get("agent_id", "000"),
                e.get("tenant_id", "DEFAULT"),
                e.get("agent_name"),
                e.get("agent_ip"),
                e.get("source_ip"),
                e.get("destination_ip"),
                e.get("source_port"),
                e.get("destination_port"),
                e.get("protocol"),
                e.get("username"),
                e.get("location"),
                e.get("decoder_name"),
                e.get("raw_payload", "")
            )
            for e in events
        ]

        with self.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SET LOCAL synchronous_commit = off;")
                execute_values(cur, query, records, page_size=5000)
        return len(records)

    def bulk_insert_normalized_events(self, events: List[Dict[str, Any]]) -> int:
        """Bulk insert normalized events into PostgreSQL."""
        if not events:
            return 0

        query = """
        INSERT INTO normalized_events (
            normalized_event_id, raw_event_id, event_timestamp, rule_id,
            rule_level, rule_description, classification_groups, mitre_attack_ids,
            mitre_tactics, mitre_techniques, compliance_frameworks,
            asset_criticality_tier, is_asset_internet_exposed, is_privileged_user,
            is_service_account, threat_intel_match, threat_intel_confidence
        ) VALUES %s
        ON CONFLICT (normalized_event_id, processed_at) DO NOTHING;
        """

        records = [
            (
                e.get("normalized_event_id"),
                e.get("raw_event_id"),
                e.get("event_timestamp"),
                e.get("rule_id"),
                e.get("rule_level"),
                e.get("rule_description"),
                e.get("classification_groups", []),
                e.get("mitre_attack_ids", []),
                e.get("mitre_tactics", []),
                e.get("mitre_techniques", []),
                extras.Json(e.get("compliance_frameworks", {})),
                e.get("asset_criticality_tier", "STANDARD"),
                e.get("is_asset_internet_exposed", False),
                e.get("is_privileged_user", False),
                e.get("is_service_account", False),
                e.get("threat_intel_match", False),
                e.get("threat_intel_confidence", 0)
            )
            for e in events
        ]

        with self.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SET LOCAL synchronous_commit = off;")
                execute_values(cur, query, records, page_size=5000)
        return len(records)

    def upsert_aggregated_alert(self, agg: Dict[str, Any]) -> str:
        """Atomic upsert for sliding window aggregated alert."""
        query = """
        INSERT INTO aggregated_alerts (
            aggregation_id, rule_id, deduplication_key, tenant_id, agent_id,
            source_ip, destination_ip, username, event_count, window_start, window_end, status,
            category, rule_description, actor, target, window_duration_seconds, ioa_summary,
            is_suppressed, suppression_rule_id, suppression_reason,
            max_inline_risk_score, ocsf_severity_id,
            tlp_level, mitre_technique_id, os_platform,
            mitre_tactics, classification_groups,
            log_source, distinct_ioas, distinct_iocs,
            dominant_http_status, is_scanner_ua
        ) VALUES (%(aggregation_id)s, %(rule_id)s, %(deduplication_key)s, %(tenant_id)s, %(agent_id)s,
                  %(source_ip)s, %(destination_ip)s, %(username)s, %(event_count)s, %(window_start)s, %(window_end)s, %(status)s,
                  %(category)s, %(rule_description)s, %(actor)s, %(target)s, %(window_duration_seconds)s, %(ioa_summary)s,
                  %(is_suppressed)s, %(suppression_rule_id)s, %(suppression_reason)s,
                  %(max_inline_risk_score)s, %(ocsf_severity_id)s,
                  %(tlp_level)s, %(mitre_technique_id)s, %(os_platform)s,
                  %(mitre_tactics)s, %(classification_groups)s,
                  %(log_source)s, %(distinct_ioas)s, %(distinct_iocs)s,
                  %(dominant_http_status)s, %(is_scanner_ua)s)
        ON CONFLICT (aggregation_id) DO UPDATE
        SET event_count = aggregated_alerts.event_count + EXCLUDED.event_count,
            status = EXCLUDED.status,
            category = EXCLUDED.category,
            rule_description = EXCLUDED.rule_description,
            actor = EXCLUDED.actor,
            target = EXCLUDED.target,
            window_duration_seconds = EXCLUDED.window_duration_seconds,
            ioa_summary = COALESCE(EXCLUDED.ioa_summary, aggregated_alerts.ioa_summary),
            is_suppressed = EXCLUDED.is_suppressed,
            suppression_rule_id = EXCLUDED.suppression_rule_id,
            suppression_reason = EXCLUDED.suppression_reason,
            max_inline_risk_score = GREATEST(COALESCE(aggregated_alerts.max_inline_risk_score, 0), EXCLUDED.max_inline_risk_score),
            ocsf_severity_id = GREATEST(aggregated_alerts.ocsf_severity_id, EXCLUDED.ocsf_severity_id),
            tlp_level = EXCLUDED.tlp_level,
            mitre_technique_id = COALESCE(EXCLUDED.mitre_technique_id, aggregated_alerts.mitre_technique_id),
            os_platform = EXCLUDED.os_platform,
            mitre_tactics = COALESCE(EXCLUDED.mitre_tactics, aggregated_alerts.mitre_tactics),
            classification_groups = COALESCE(EXCLUDED.classification_groups, aggregated_alerts.classification_groups),
            log_source = COALESCE(EXCLUDED.log_source, aggregated_alerts.log_source),
            distinct_ioas = EXCLUDED.distinct_ioas,
            distinct_iocs = EXCLUDED.distinct_iocs,
            dominant_http_status = COALESCE(EXCLUDED.dominant_http_status, aggregated_alerts.dominant_http_status),
            is_scanner_ua = (aggregated_alerts.is_scanner_ua OR EXCLUDED.is_scanner_ua);
        """
        # Ensure default fallbacks if missing
        agg_payload = dict(agg)
        agg_payload.setdefault("status", "CLOSED")
        agg_payload.setdefault("category", "SYSTEM_HEALTH")
        agg_payload.setdefault("rule_description", None)
        agg_payload.setdefault("actor", agg.get("source_ip") or f"agent:{agg.get('agent_id')}")
        agg_payload.setdefault("target", agg.get("username") or agg.get("destination_ip") or f"agent:{agg.get('agent_id')}")
        agg_payload.setdefault("window_duration_seconds", 900)
        agg_payload.setdefault("ioa_summary", None)
        agg_payload.setdefault("is_suppressed", False)
        agg_payload.setdefault("suppression_rule_id", None)
        agg_payload.setdefault("suppression_reason", None)
        agg_payload.setdefault("max_inline_risk_score", 0)
        agg_payload.setdefault("ocsf_severity_id", None)
        agg_payload.setdefault("tlp_level", "TLP:AMBER")
        agg_payload.setdefault("mitre_technique_id", None)
        agg_payload.setdefault("os_platform", "unknown")
        agg_payload.setdefault("log_source", None)
        agg_payload.setdefault("dominant_http_status", None)
        agg_payload.setdefault("is_scanner_ua", False)
        agg_payload["mitre_tactics"] = json.dumps(agg.get("mitre_tactics") or [])
        agg_payload["classification_groups"] = json.dumps(agg.get("classification_groups") or [])
        agg_payload["distinct_ioas"] = json.dumps(agg.get("distinct_ioas") or [])
        agg_payload["distinct_iocs"] = json.dumps(agg.get("distinct_iocs") or [])

        with self.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query, agg_payload)
        return agg.get("aggregation_id")

    def bulk_upsert_aggregated_alerts(self, aggs: List[Dict[str, Any]]) -> int:
        """High-performance batch upsert for sliding window aggregated alerts & auto-sync to cumulative alerts."""
        if not aggs:
            return 0
        query = """
        INSERT INTO aggregated_alerts (
            aggregation_id, rule_id, deduplication_key, tenant_id, agent_id,
            source_ip, destination_ip, username, event_count, window_start, window_end, status,
            category, rule_description, actor, target, window_duration_seconds, ioa_summary,
            is_suppressed, suppression_rule_id, suppression_reason,
            max_inline_risk_score, ocsf_severity_id,
            tlp_level, mitre_technique_id, os_platform,
            mitre_tactics, classification_groups,
            log_source, distinct_ioas, distinct_iocs,
            dominant_http_status, is_scanner_ua,
            domain, target_category, action_ttp, lifecycle_role, disposition, confidence_score,
            composite_cluster_key, who_cluster, what_cluster, source_type, distinct_targets,
            smart_evidence, cluster_metrics, exact_source_ip, distinct_src_ips, wazuh_query_pointer,
            is_high_value, bypass_reason, success_indicator, external_auth_success, pkg_activity_nearby,
            parent_cluster_id, first_seen_event_time, last_seen_event_time, is_backfill
        ) VALUES %s
        ON CONFLICT (aggregation_id) DO UPDATE
        SET event_count = aggregated_alerts.event_count + EXCLUDED.event_count,
            status = EXCLUDED.status,
            category = EXCLUDED.category,
            rule_description = EXCLUDED.rule_description,
            actor = EXCLUDED.actor,
            target = EXCLUDED.target,
            window_duration_seconds = EXCLUDED.window_duration_seconds,
            ioa_summary = COALESCE(EXCLUDED.ioa_summary, aggregated_alerts.ioa_summary),
            is_suppressed = EXCLUDED.is_suppressed,
            suppression_rule_id = EXCLUDED.suppression_rule_id,
            suppression_reason = EXCLUDED.suppression_reason,
            max_inline_risk_score = GREATEST(COALESCE(aggregated_alerts.max_inline_risk_score, 0), EXCLUDED.max_inline_risk_score),
            ocsf_severity_id = GREATEST(aggregated_alerts.ocsf_severity_id, EXCLUDED.ocsf_severity_id),
            tlp_level = EXCLUDED.tlp_level,
            mitre_technique_id = COALESCE(EXCLUDED.mitre_technique_id, aggregated_alerts.mitre_technique_id),
            os_platform = EXCLUDED.os_platform,
            mitre_tactics = COALESCE(EXCLUDED.mitre_tactics, aggregated_alerts.mitre_tactics),
            classification_groups = COALESCE(EXCLUDED.classification_groups, aggregated_alerts.classification_groups),
            log_source = COALESCE(EXCLUDED.log_source, aggregated_alerts.log_source),
            distinct_ioas = EXCLUDED.distinct_ioas,
            distinct_iocs = EXCLUDED.distinct_iocs,
            dominant_http_status = COALESCE(EXCLUDED.dominant_http_status, aggregated_alerts.dominant_http_status),
            is_scanner_ua = (aggregated_alerts.is_scanner_ua OR EXCLUDED.is_scanner_ua),
            domain = COALESCE(EXCLUDED.domain, aggregated_alerts.domain),
            target_category = COALESCE(EXCLUDED.target_category, aggregated_alerts.target_category),
            action_ttp = COALESCE(EXCLUDED.action_ttp, aggregated_alerts.action_ttp),
            lifecycle_role = COALESCE(EXCLUDED.lifecycle_role, aggregated_alerts.lifecycle_role),
            disposition = COALESCE(EXCLUDED.disposition, aggregated_alerts.disposition),
            confidence_score = COALESCE(EXCLUDED.confidence_score, aggregated_alerts.confidence_score),
            composite_cluster_key = COALESCE(EXCLUDED.composite_cluster_key, aggregated_alerts.composite_cluster_key),
            who_cluster = COALESCE(EXCLUDED.who_cluster, aggregated_alerts.who_cluster),
            what_cluster = COALESCE(EXCLUDED.what_cluster, aggregated_alerts.what_cluster),
            source_type = COALESCE(EXCLUDED.source_type, aggregated_alerts.source_type),
            distinct_targets = COALESCE(EXCLUDED.distinct_targets, aggregated_alerts.distinct_targets),
            smart_evidence = COALESCE(EXCLUDED.smart_evidence, aggregated_alerts.smart_evidence),
            cluster_metrics = COALESCE(EXCLUDED.cluster_metrics, aggregated_alerts.cluster_metrics),
            exact_source_ip = COALESCE(EXCLUDED.exact_source_ip, aggregated_alerts.exact_source_ip),
            distinct_src_ips = COALESCE(EXCLUDED.distinct_src_ips, aggregated_alerts.distinct_src_ips),
            wazuh_query_pointer = COALESCE(EXCLUDED.wazuh_query_pointer, aggregated_alerts.wazuh_query_pointer),
            is_high_value = (aggregated_alerts.is_high_value OR EXCLUDED.is_high_value),
            bypass_reason = COALESCE(EXCLUDED.bypass_reason, aggregated_alerts.bypass_reason),
            success_indicator = COALESCE(EXCLUDED.success_indicator, aggregated_alerts.success_indicator),
            external_auth_success = (aggregated_alerts.external_auth_success OR EXCLUDED.external_auth_success),
            pkg_activity_nearby = (aggregated_alerts.pkg_activity_nearby OR EXCLUDED.pkg_activity_nearby),
            parent_cluster_id = COALESCE(EXCLUDED.parent_cluster_id, aggregated_alerts.parent_cluster_id),
            first_seen_event_time = LEAST(aggregated_alerts.first_seen_event_time, EXCLUDED.first_seen_event_time),
            last_seen_event_time = GREATEST(aggregated_alerts.last_seen_event_time, EXCLUDED.last_seen_event_time),
            is_backfill = (aggregated_alerts.is_backfill OR EXCLUDED.is_backfill);
        """
        # Pre-collapse batch by aggregation_id to prevent PostgreSQL ON CONFLICT multiple affect error
        merged_aggs: Dict[str, Dict[str, Any]] = {}
        for a in aggs:
            k = str(a.get("aggregation_id"))
            if k not in merged_aggs:
                merged_aggs[k] = dict(a)
            else:
                merged_aggs[k]["event_count"] = merged_aggs[k].get("event_count", 1) + a.get("event_count", 1)
                if not merged_aggs[k].get("ioa_summary") and a.get("ioa_summary"):
                    merged_aggs[k]["ioa_summary"] = a.get("ioa_summary")
                if not merged_aggs[k].get("log_source") and a.get("log_source"):
                    merged_aggs[k]["log_source"] = a.get("log_source")
                if a.get("is_suppressed") is not None:
                    merged_aggs[k]["is_suppressed"] = a.get("is_suppressed")
                    merged_aggs[k]["status"] = a.get("status", merged_aggs[k].get("status"))
                    merged_aggs[k]["suppression_rule_id"] = a.get("suppression_rule_id")
                    merged_aggs[k]["suppression_reason"] = a.get("suppression_reason")
                if a.get("dominant_http_status") is not None and not merged_aggs[k].get("dominant_http_status"):
                    merged_aggs[k]["dominant_http_status"] = a.get("dominant_http_status")
                if a.get("is_scanner_ua"):
                    merged_aggs[k]["is_scanner_ua"] = True
                if a.get("is_high_value"):
                    merged_aggs[k]["is_high_value"] = True
                if a.get("external_auth_success"):
                    merged_aggs[k]["external_auth_success"] = True
            # Preserve highest risk/severity across duplicate aggregation_ids in same batch
            incoming_risk = int(a.get("max_inline_risk_score", 0) or 0)
            if incoming_risk > merged_aggs[k].get("max_inline_risk_score", 0):
                merged_aggs[k]["max_inline_risk_score"] = incoming_risk
            incoming_ocsf = a.get("ocsf_severity_id")
            existing_ocsf = merged_aggs[k].get("ocsf_severity_id")
            if incoming_ocsf is not None:
                if existing_ocsf is None or incoming_ocsf > existing_ocsf:
                    merged_aggs[k]["ocsf_severity_id"] = incoming_ocsf

        records = [
            (
                a.get("aggregation_id"),
                a.get("rule_id"),
                a.get("deduplication_key"),
                a.get("tenant_id", "DEFAULT"),
                a.get("agent_id"),
                a.get("source_ip"),
                a.get("destination_ip"),
                a.get("username"),
                a.get("event_count", 1),
                a.get("window_start"),
                a.get("window_end"),
                a.get("status", "CLOSED"),
                a.get("category", "SYSTEM_HEALTH"),
                a.get("rule_description"),
                a.get("actor") or a.get("source_ip") or f"agent:{a.get('agent_id')}",
                a.get("target") or a.get("username") or a.get("destination_ip") or f"agent:{a.get('agent_id')}",
                a.get("window_duration_seconds", 900),
                a.get("ioa_summary"),
                bool(a.get("is_suppressed", False)),
                a.get("suppression_rule_id"),
                a.get("suppression_reason"),
                int(a.get("max_inline_risk_score", 0) or 0),   # Peak risk score in this window
                max(1, min(6, int(a.get("ocsf_severity_id") or 1))), # Highest OCSF severity in this window (1-6)
                a.get("tlp_level", "TLP:AMBER"),                # MISP TLP level
                a.get("mitre_technique_id"),                    # ATT&CK technique ID
                a.get("os_platform", "unknown"),                # OS platform dimension
                json.dumps(a.get("mitre_tactics") or []),       # ATT&CK tactics metadata
                json.dumps(a.get("classification_groups") or []), # Classification groups metadata
                a.get("log_source"),                            # Log source path
                json.dumps(a.get("distinct_ioas") or []),       # Distinct IOAs collection
                json.dumps(a.get("distinct_iocs") or []),       # Distinct IOCs collection
                a.get("dominant_http_status"),
                bool(a.get("is_scanner_ua", False)),
                a.get("domain", a.get("primary_category", "SYSTEM")),
                a.get("target_category", "Host_Telemetry"),
                a.get("action_ttp", a.get("subcategory", "General")),
                a.get("lifecycle_role", "STATELESS"),
                a.get("disposition", "SAFE"),
                int(a.get("confidence_score") or 50),
                a.get("composite_cluster_key"),
                a.get("who_cluster"),
                a.get("what_cluster"),
                a.get("source_type", "system"),
                json.dumps(a.get("distinct_targets") or []),
                json.dumps(a.get("smart_evidence") or []),
                json.dumps(a.get("cluster_metrics") or {}),
                a.get("exact_source_ip") or a.get("source_ip"),
                json.dumps(a.get("distinct_src_ips") or ([a.get("source_ip")] if a.get("source_ip") else [])),
                json.dumps(a.get("wazuh_query_pointer") or {}),
                bool(a.get("is_high_value", False)),
                a.get("bypass_reason"),
                a.get("success_indicator", "none"),
                bool(a.get("external_auth_success", False)),
                bool(a.get("pkg_activity_nearby", False)),
                a.get("parent_cluster_id"),
                a.get("first_seen_event_time") or a.get("window_start"),
                a.get("last_seen_event_time") or a.get("window_end"),
                bool(a.get("is_backfill", False)),
            )
            for a in merged_aggs.values()
        ]
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                execute_values(cur, query, records, page_size=1000)

        # Auto-maintain cumulative lifetime entities
        self.bulk_upsert_cumulative_alerts(aggs)
        return len(records)

    def refresh_hourly_overview_rollup(self) -> int:
        """
        [100/100 Enterprise Performance] Compute and refresh metrics.hourly_overview_rollup
        from raw telemetry, suppression aggregated alerts, and correlation incidents.
        Enables sub-10ms dashboard API queries on 1.5M+ events.
        """
        query = """
        INSERT INTO metrics.hourly_overview_rollup (
            bucket_hour, raw_events_count, aggregated_count, suppressed_count,
            actionable_count, correlated_count, p0_count, p1_count, p2_count, p3_count, p4_count, updated_at
        )
        WITH raw_h AS (
            SELECT date_trunc('hour', timestamp) AS hr, COUNT(*) AS raw_cnt
            FROM telemetry.raw_events
            GROUP BY 1
        ),
        agg_h AS (
            SELECT 
                date_trunc('hour', window_end) AS hr,
                COUNT(*) AS agg_cnt,
                COUNT(CASE WHEN status = 'SUPPRESSED' OR is_suppressed THEN 1 END) AS sup_cnt,
                COUNT(CASE WHEN status = 'ACTIONABLE' OR (NOT is_suppressed AND status != 'SUPPRESSED') THEN 1 END) AS act_cnt
            FROM suppression.aggregated_alerts
            GROUP BY 1
        ),
        corr_h AS (
            SELECT 
                date_trunc('hour', c.first_seen_at) AS hr,
                COUNT(*) AS corr_cnt,
                COUNT(CASE WHEN t.priority = 'P0' THEN 1 END) AS p0,
                COUNT(CASE WHEN t.priority = 'P1' THEN 1 END) AS p1,
                COUNT(CASE WHEN t.priority = 'P2' THEN 1 END) AS p2,
                COUNT(CASE WHEN t.priority = 'P3' THEN 1 END) AS p3,
                COUNT(CASE WHEN t.priority = 'P4' THEN 1 END) AS p4
            FROM correlation.correlated_incidents c
            LEFT JOIN soc_ops.soc_triage_queue t ON c.incident_id = t.incident_id
            GROUP BY 1
        ),
        all_hours AS (
            SELECT hr FROM raw_h
            UNION
            SELECT hr FROM agg_h
            UNION
            SELECT hr FROM corr_h
        )
        SELECT 
            h.hr,
            COALESCE(r.raw_cnt, 0),
            COALESCE(a.agg_cnt, 0),
            COALESCE(a.sup_cnt, 0),
            COALESCE(a.act_cnt, 0),
            COALESCE(c.corr_cnt, 0),
            COALESCE(c.p0, 0),
            COALESCE(c.p1, 0),
            COALESCE(c.p2, 0),
            COALESCE(c.p3, 0),
            COALESCE(c.p4, 0),
            CURRENT_TIMESTAMP
        FROM all_hours h
        LEFT JOIN raw_h r ON r.hr = h.hr
        LEFT JOIN agg_h a ON a.hr = h.hr
        LEFT JOIN corr_h c ON c.hr = h.hr
        ON CONFLICT (bucket_hour) DO UPDATE
        SET raw_events_count = EXCLUDED.raw_events_count,
            aggregated_count = EXCLUDED.aggregated_count,
            suppressed_count = EXCLUDED.suppressed_count,
            actionable_count = EXCLUDED.actionable_count,
            correlated_count = EXCLUDED.correlated_count,
            p0_count = EXCLUDED.p0_count,
            p1_count = EXCLUDED.p1_count,
            p2_count = EXCLUDED.p2_count,
            p3_count = EXCLUDED.p3_count,
            p4_count = EXCLUDED.p4_count,
            updated_at = CURRENT_TIMESTAMP;
        """
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query)
                rowcount = cur.rowcount
        return rowcount

    def bulk_upsert_cumulative_alerts(self, cums: List[Dict[str, Any]]) -> int:
        """Upsert cumulative lifetime entity alerts across unconstrained time."""
        if not cums:
            return 0
        query = """
        INSERT INTO cumulative_alerts (
            cumulative_id, deduplication_key, category, rule_id, rule_description,
            actor, target, agent_id, tenant_id, total_event_count, total_burst_windows,
            first_seen_at, last_seen_at, status, ioa_summary, peak_risk_score,
            tlp_level, sighting_count, source_feed, stix_indicator_id, mitre_technique_id,
            os_platform
        ) VALUES %s
        ON CONFLICT (deduplication_key) DO UPDATE
        SET total_event_count = cumulative_alerts.total_event_count + EXCLUDED.total_event_count,
            total_burst_windows = cumulative_alerts.total_burst_windows + EXCLUDED.total_burst_windows,
            last_seen_at = GREATEST(cumulative_alerts.last_seen_at, EXCLUDED.last_seen_at),
            first_seen_at = LEAST(cumulative_alerts.first_seen_at, EXCLUDED.first_seen_at),
            rule_description = COALESCE(EXCLUDED.rule_description, cumulative_alerts.rule_description),
            ioa_summary = COALESCE(EXCLUDED.ioa_summary, cumulative_alerts.ioa_summary),
            peak_risk_score = GREATEST(COALESCE(cumulative_alerts.peak_risk_score, 0), EXCLUDED.peak_risk_score),
            sighting_count = cumulative_alerts.sighting_count + EXCLUDED.sighting_count,
            tlp_level = EXCLUDED.tlp_level,
            source_feed = COALESCE(EXCLUDED.source_feed, cumulative_alerts.source_feed),
            stix_indicator_id = COALESCE(EXCLUDED.stix_indicator_id, cumulative_alerts.stix_indicator_id),
            mitre_technique_id = COALESCE(EXCLUDED.mitre_technique_id, cumulative_alerts.mitre_technique_id),
            os_platform = EXCLUDED.os_platform,
            updated_at = CURRENT_TIMESTAMP;
        """

        def _to_datetime(val) -> Optional[datetime]:
            """Type-safe converter: str ISO → datetime. Returns None if unparseable."""
            if val is None:
                return None
            if isinstance(val, datetime):
                return val
            if isinstance(val, str):
                try:
                    from dateutil import parser as dt_parser
                    return dt_parser.parse(val)
                except Exception:
                    return None
            return None

        # Pre-collapse batch by deduplication_key to guarantee unique conflict targets per SQL command
        merged_cums: Dict[str, Dict[str, Any]] = {}
        for c in cums:
            k = c["deduplication_key"]

            # Type-safe timestamp extraction
            w_start = _to_datetime(c.get("first_seen_at") or c.get("window_start"))
            w_end   = _to_datetime(c.get("last_seen_at")  or c.get("window_end"))

            if k not in merged_cums:
                merged_cums[k] = {
                    "cumulative_id": c.get("cumulative_id") or f"cum_{k[:16]}",
                    "deduplication_key": k,
                    "category": c.get("category", "SYSTEM_HEALTH"),
                    "rule_id": c["rule_id"],
                    "rule_description": c.get("rule_description"),
                    "actor": c.get("actor") or c.get("source_ip") or f"agent:{c.get('agent_id')}",
                    "target": c.get("target") or c.get("username") or c.get("destination_ip") or f"agent:{c.get('agent_id')}",
                    "agent_id": c.get("agent_id", "000"),
                    "tenant_id": c.get("tenant_id", "DEFAULT"),
                    "total_event_count": c.get("total_event_count", c.get("event_count", 1)),
                    "total_burst_windows": c.get("total_burst_windows", 1),
                    "first_seen_at": w_start,
                    "last_seen_at": w_end,
                    "status": c.get("status") if c.get("status") in ("ACTIVE", "DORMANT") else "ACTIVE",
                    "ioa_summary": c.get("ioa_summary"),
                    "peak_risk_score": int(c.get("max_inline_risk_score", 0) or 0),
                    "tlp_level": c.get("tlp_level", "TLP:AMBER"),
                    "sighting_count": c.get("sighting_count", 0),
                    "source_feed": c.get("source_feed", "wazuh-pipeline"),
                    "stix_indicator_id": c.get("stix_indicator_id"),
                    "mitre_technique_id": c.get("mitre_technique_id"),
                    "os_platform": c.get("os_platform", "unknown"),
                }
            else:
                m = merged_cums[k]
                m["total_event_count"] += c.get("total_event_count", c.get("event_count", 1))
                m["total_burst_windows"] += c.get("total_burst_windows", 1)
                # Type-safe LEAST / GREATEST — no more silent TypeError
                if w_start is not None:
                    if m["first_seen_at"] is None:
                        m["first_seen_at"] = w_start
                    else:
                        m["first_seen_at"] = min(m["first_seen_at"].replace(tzinfo=None) if m["first_seen_at"].tzinfo else m["first_seen_at"],
                                                  w_start.replace(tzinfo=None) if w_start.tzinfo else w_start)
                if w_end is not None:
                    if m["last_seen_at"] is None:
                        m["last_seen_at"] = w_end
                    else:
                        m["last_seen_at"] = max(m["last_seen_at"].replace(tzinfo=None) if m["last_seen_at"].tzinfo else m["last_seen_at"],
                                                 w_end.replace(tzinfo=None) if w_end.tzinfo else w_end)
                if c.get("rule_description"):
                    m["rule_description"] = c["rule_description"]
                if not m.get("ioa_summary") and c.get("ioa_summary"):
                    m["ioa_summary"] = c.get("ioa_summary")
                # Track all-time peak risk score for this entity
                incoming_risk = int(c.get("max_inline_risk_score", 0) or 0)
                if incoming_risk > m.get("peak_risk_score", 0):
                    m["peak_risk_score"] = incoming_risk
                # Propagate MISP fields — prefer non-null incoming values
                if c.get("stix_indicator_id") and not m.get("stix_indicator_id"):
                    m["stix_indicator_id"] = c["stix_indicator_id"]
                if c.get("mitre_technique_id") and not m.get("mitre_technique_id"):
                    m["mitre_technique_id"] = c["mitre_technique_id"]
                m["sighting_count"] = m.get("sighting_count", 0) + c.get("sighting_count", 0)

        records = [
            (
                c["cumulative_id"],
                c["deduplication_key"],
                c["category"],
                c["rule_id"],
                c["rule_description"],
                c["actor"],
                c["target"],
                c["agent_id"],
                c["tenant_id"],
                c["total_event_count"],
                c["total_burst_windows"],
                c["first_seen_at"],
                c["last_seen_at"],
                c["status"],
                c.get("ioa_summary"),
                c.get("peak_risk_score", 0),
                c.get("tlp_level", "TLP:AMBER"),
                c.get("sighting_count", 0),
                c.get("source_feed", "wazuh-pipeline"),
                c.get("stix_indicator_id"),
                c.get("mitre_technique_id"),
                c.get("os_platform", "unknown"),
            )
            for c in merged_cums.values()
        ]
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                execute_values(cur, query, records, page_size=1000)
        return len(records)

    def refresh_cumulative_dormancy(self, reference_time: Optional[datetime] = None, inactive_hours: int = 24) -> int:
        """Dynamically transition entities to DORMANT if inactive past the threshold relative to reference time."""
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                if reference_time:
                    cutoff = reference_time - timedelta(hours=inactive_hours)
                    cur.execute("""
                        UPDATE cumulative_alerts
                        SET status = CASE WHEN last_seen_at >= %s THEN 'ACTIVE' ELSE 'DORMANT' END;
                    """, (cutoff,))
                else:
                    cur.execute(f"""
                        UPDATE cumulative_alerts
                        SET status = CASE WHEN last_seen_at >= CURRENT_TIMESTAMP - INTERVAL '{inactive_hours} hours' THEN 'ACTIVE' ELSE 'DORMANT' END;
                    """)
                return cur.rowcount

    def link_aggregate_evidence(self, aggregation_id: str, raw_event_id: str, event_timestamp: datetime):
        """Link a single raw evidence record to an aggregated alert (single-row, backward compat)."""
        self.bulk_insert_evidence_mapping([(aggregation_id, raw_event_id, event_timestamp)])

    def bulk_insert_evidence_mapping(self, evidence_links: List[Tuple[str, str, datetime]]) -> int:
        """
        High-performance batch insert for aggregate_evidence_mapping.
        Links raw event IDs to their parent aggregated alert window.

        Args:
            evidence_links: List of (aggregation_id, raw_event_id, event_timestamp) tuples.
        Returns:
            Number of links inserted (excluding duplicates).
        """
        if not evidence_links:
            return 0
        query = """
        INSERT INTO aggregate_evidence_mapping (aggregation_id, raw_event_id, event_timestamp)
        VALUES %s
        ON CONFLICT (aggregation_id, raw_event_id) DO NOTHING;
        """
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SET LOCAL synchronous_commit = off;")
                    execute_values(cur, query, evidence_links, page_size=5000)
            return len(evidence_links)
        except Exception as e:
            logger.warning(f"bulk_insert_evidence_mapping skipped batch ({len(evidence_links)} links): {e}")
            return 0

    def bulk_insert_incidents_and_triage(self, incidents: List[Dict[str, Any]]) -> int:
        """Atomic bulk insert for Correlated Incidents, Stages, Factors, Scores, and Triage Queue."""
        if not incidents:
            return 0

        with self.get_connection() as conn:
            with conn.cursor() as cur:
                for inc in incidents:
                    is_reopen = inc.get("is_reopen", False)
                    parent_id = inc.get("parent_incident_id")

                    # [F10] Cooldown-aware Re-open Logic:
                    # Jika incident ini adalah re-open dari tiket yang masih dalam cooldown,
                    # UPDATE tiket lama (last_seen_at, narrative) daripada INSERT tiket baru.
                    # Ini mengimplementasikan "append to existing ticket" pattern dari MS Sentinel.
                    if is_reopen and parent_id:
                        cur.execute("""
                        UPDATE correlated_incidents
                        SET last_seen_at = GREATEST(last_seen_at, %s),
                            incident_status = CASE
                                WHEN incident_status IN ('RESOLVED', 'CLOSED_FP') THEN 'IN_TRIAGE'
                                ELSE incident_status
                            END,
                            narrative = narrative || E'\n[RE-OPEN ' || to_char(CURRENT_TIMESTAMP, 'YYYY-MM-DD HH24:MI') || '] ' || %s
                        WHERE incident_id = %s;
                        """, (inc["last_seen_at"], inc.get("narrative", "")[:500], parent_id))

                        # Re-open triage jika sudah RESOLVED
                        cur.execute("""
                        UPDATE soc_triage_queue
                        SET triage_status = CASE
                                WHEN triage_status = 'RESOLVED' THEN 'INVESTIGATING'
                                ELSE triage_status
                            END,
                            resolved_at = NULL,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE incident_id = %s AND triage_status = 'RESOLVED';
                        """, (parent_id,))

                        # Append stages ke tiket lama (dengan offset sequence_order)
                        cur.execute("""
                        SELECT COALESCE(MAX(sequence_order), 0) FROM incident_stages WHERE incident_id = %s;
                        """, (parent_id,))
                        max_seq = (cur.fetchone() or [0])[0]
                        for i, stg in enumerate(inc.get("stages", []), 1):
                            cur.execute("""
                            INSERT INTO incident_stages
                                (incident_id, sequence_order, stage_name, reference_id, evidence_type, stage_description)
                            VALUES (%s, %s, %s, %s, %s, %s)
                            ON CONFLICT (incident_id, sequence_order) DO NOTHING;
                            """, (parent_id, max_seq + i, stg["stage_name"],
                                  stg["reference_id"], stg["evidence_type"],
                                  stg.get("stage_description")))
                        # Skip ke incident berikutnya — tidak perlu insert tiket baru
                        continue

                    # 1. Insert Correlated Incident (new ticket — normal flow)
                    cur.execute("""
                    INSERT INTO correlated_incidents (
                        incident_id, correlation_rule_id, tenant_id, title, narrative,
                        initial_access_vector, attacker_source_ip, compromised_account,
                        target_host, incident_status, first_seen_at, last_seen_at, related_incident_ids
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (incident_id) DO NOTHING;
                    """, (
                        inc["incident_id"], inc["correlation_rule_id"], inc.get("tenant_id", "DEFAULT"),
                        inc["title"], inc["narrative"], inc.get("initial_access_vector"),
                        inc.get("attacker_source_ip"), inc.get("compromised_account"),
                        inc.get("target_host"), inc.get("incident_status", "DETECTED"),
                        inc["first_seen_at"], inc["last_seen_at"],
                        inc.get("related_incident_ids", [])
                    ))

                    # 2. Insert Stages
                    for stg in inc.get("stages", []):
                        cur.execute("""
                        INSERT INTO incident_stages (incident_id, sequence_order, stage_name, reference_id, evidence_type, stage_description)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (incident_id, sequence_order) DO NOTHING;
                        """, (stg["incident_id"], stg["sequence_order"], stg["stage_name"], stg["reference_id"], stg["evidence_type"], stg.get("stage_description")))

                    # PRD Section 8 #2: Risk scoring factors sudah dihapus.
                    # Tidak ada lagi INSERT ke risk_scoring_factors.

                    # PRD Section 8 #2: Calculated risk scores sudah dihapus.
                    # Priority ditentukan oleh kategori aggregate saja.

                    # 5. Insert SOC Triage Queue Item
                    triage = inc.get("triage_queue") or {}
                    if not triage and inc.get("incident_id"):
                        triage = {
                            "triage_id": inc.get("triage_id") or f"TRG-{inc['incident_id'][4:]}",
                            "incident_id": inc["incident_id"],
                            "assigned_analyst": inc.get("assigned_analyst"),
                            "priority": inc.get("priority", "P4"),
                            "triage_status": inc.get("triage_status", "OPEN"),
                            "cooldown_until": inc.get("cooldown_until"),
                            "resolution_outcome": inc.get("resolution_outcome"),
                            "false_positive_reason": inc.get("false_positive_reason"),
                            "first_detected_at": inc.get("first_detected_at") or inc.get("first_seen_at"),
                            "priority_changed_at": inc.get("priority_changed_at") or inc.get("last_seen_at"),
                            "priority_established_at": inc.get("priority_established_at") or inc.get("first_seen_at"),
                            "sla_deadline": inc.get("sla_deadline"),
                            "sla_minutes": inc.get("sla_minutes"),
                        }
                    if triage:
                        ts_first = (
                            triage.get("first_detected_at")
                            or inc.get("first_detected_at")
                            or inc.get("first_seen_at")
                            or inc.get("created_at")
                            or datetime.now(timezone.utc)
                        )
                        ts_changed = (
                            triage.get("priority_changed_at")
                            or triage.get("priority_established_at")
                            or inc.get("priority_changed_at")
                            or inc.get("priority_established_at")
                            or inc.get("last_seen_at")
                            or inc.get("created_at")
                            or ts_first
                        )
                        sla_deadline = triage.get("sla_deadline")
                        if not sla_deadline:
                            sla_mins = inc.get("sla_minutes") or triage.get("sla_minutes") or SLA_MATRIX_MINUTES.get(triage.get("priority", "P4"), 10080)
                            if isinstance(ts_changed, datetime):
                                sla_deadline = ts_changed + timedelta(minutes=sla_mins)

                        cur.execute("""
                        INSERT INTO soc_triage_queue (
                            triage_id, incident_id, assigned_analyst, priority,
                            triage_status, cooldown_until, resolution_outcome, false_positive_reason,
                            priority_established_at, first_detected_at, priority_changed_at, sla_deadline
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (triage_id) DO UPDATE SET
                            triage_status = EXCLUDED.triage_status,
                            cooldown_until = COALESCE(EXCLUDED.cooldown_until, soc_triage_queue.cooldown_until),
                            resolution_outcome = EXCLUDED.resolution_outcome,
                            false_positive_reason = EXCLUDED.false_positive_reason,
                            priority = EXCLUDED.priority,
                            priority_established_at = COALESCE(EXCLUDED.priority_established_at, soc_triage_queue.priority_established_at),
                            first_detected_at = soc_triage_queue.first_detected_at,
                            priority_changed_at = COALESCE(EXCLUDED.priority_changed_at, soc_triage_queue.priority_changed_at),
                            sla_deadline = COALESCE(EXCLUDED.sla_deadline, soc_triage_queue.sla_deadline);
                        """, (
                            triage["triage_id"], triage["incident_id"],
                            triage.get("assigned_analyst"), triage["priority"],
                            triage.get("triage_status", "OPEN"), triage.get("cooldown_until"),
                            triage.get("resolution_outcome"), triage.get("false_positive_reason"),
                            ts_changed, ts_first, ts_changed, sla_deadline
                        ))

                        # Insert ticket_aggregates
                        for ta in inc.get("ticket_aggregates", []):
                            cur.execute("""
                            INSERT INTO soc_ops.ticket_aggregates
                                (ticket_id, aggregation_id, is_induk, is_escalation_trigger, added_at)
                            VALUES (%s, %s, %s, %s, %s)
                            ON CONFLICT (ticket_id, aggregation_id) DO NOTHING;
                            """, (
                                triage["triage_id"],
                                ta["aggregation_id"],
                                ta.get("is_induk", False),
                                ta.get("is_escalation_trigger", False),
                                ta.get("added_at", ts_changed)
                            ))

        return len(incidents)


    def create_monthly_partition(self, target_date: date):
        """Call PL/pgSQL stored procedure to create future month partitions."""
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("CALL create_monthly_partitions(%s);", (target_date,))

    def truncate_pipeline_tables(self):
        """Cleanly truncate pipeline telemetry, suppression, correlation, risk and SOC tables."""
        tables = [
            "telemetry.raw_events",
            "telemetry.normalized_events",
            "suppression.aggregated_alerts",
            "suppression.aggregate_evidence_mapping",
            "suppression.cumulative_alerts",
            "suppression.suppression_audit_log",
            "correlation.correlated_incidents",
            "correlation.incident_stages",
            "risk_engine.calculated_risk_scores",
            "risk_engine.risk_scoring_factors",
            "soc_ops.ticket_aggregates",
            "soc_ops.soc_triage_queue",
            "soc_ops.incident_investigation_notes",
            "soc_ops.incident_response_actions",
            "metrics.operational_metrics_daily",
        ]
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                for tbl in tables:
                    try:
                        cur.execute(f"TRUNCATE TABLE {tbl} CASCADE;")
                    except Exception:
                        pass
                conn.commit()

    def ensure_retention_indexes(self):
        """Ensure B-Tree indexes exist on timestamp columns for rapid retention sweeping."""
        index_sqls = [
            "CREATE INDEX IF NOT EXISTS idx_raw_events_timestamp ON telemetry.raw_events (timestamp);",
            "CREATE INDEX IF NOT EXISTS idx_normalized_events_timestamp ON telemetry.normalized_events (event_timestamp);",
            "CREATE INDEX IF NOT EXISTS idx_aggregated_alerts_window_end ON suppression.aggregated_alerts (window_end);",
            "CREATE INDEX IF NOT EXISTS idx_correlated_incidents_last_seen ON correlation.correlated_incidents (last_seen_at);"
        ]
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                for sql in index_sqls:
                    try:
                        cur.execute(sql)
                    except Exception as e:
                        logger.warning(f"Notice on retention index creation: {e}")

    def execute_rolling_retention(self, reference_time: Optional[datetime] = None, dry_run: bool = False) -> Dict[str, Any]:
        """Execute rolling 30-day retention manager sweep."""
        from pipeline.retention_manager import RollingRetentionManager
        manager = RollingRetentionManager()
        return manager.execute_retention_sweep(self, reference_time=reference_time, dry_run=dry_run)

    def update_ingest_checkpoint(self, file_name: str, last_event_id: Optional[str] = None, last_timestamp: Optional[datetime] = None, cursor_offset: int = 0):
        """Update or insert ingestion checkpoint in telemetry.ingest_checkpoints."""
        query = """
        INSERT INTO telemetry.ingest_checkpoints (tenant_id, last_event_id, last_timestamp, cursor_offset, updated_at)
        VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
        ON CONFLICT (tenant_id) DO UPDATE SET
            last_event_id = COALESCE(EXCLUDED.last_event_id, telemetry.ingest_checkpoints.last_event_id),
            last_timestamp = COALESCE(EXCLUDED.last_timestamp, telemetry.ingest_checkpoints.last_timestamp),
            cursor_offset = EXCLUDED.cursor_offset,
            updated_at = CURRENT_TIMESTAMP;
        """
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(query, (file_name, last_event_id, last_timestamp, cursor_offset))
                conn.commit()
        except Exception as e:
            logger.warning(f"Failed to update ingest checkpoint for {file_name}: {e}")

    def get_ingest_checkpoint(self, file_name: str) -> Optional[Dict[str, Any]]:
        """Retrieve ingestion checkpoint from telemetry.ingest_checkpoints."""
        query = """
        SELECT tenant_id, last_event_id, last_timestamp, cursor_offset, updated_at
        FROM telemetry.ingest_checkpoints
        WHERE tenant_id = %s;
        """
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(query, (file_name,))
                    row = cur.fetchone()
                    if row:
                        return {
                            "file_name": row[0],
                            "last_event_id": row[1],
                            "last_timestamp": row[2],
                            "cursor_offset": row[3],
                            "updated_at": row[4]
                        }
        except Exception as e:
            logger.warning(f"Failed to read ingest checkpoint for {file_name}: {e}")
        return None

    def close(self):
        """Close connection pool."""
        if self._pool:
            self._pool.closeall()
            self._pool = None
