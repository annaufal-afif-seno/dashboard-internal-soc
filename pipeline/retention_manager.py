"""
Enterprise Rolling 30-Day Retention & Data Lifecycle Manager
============================================================
Enforces precision rolling 30-day (720 hours) retention across raw, normalized,
aggregated, and incident tables, while strictly safeguarding cumulative_alerts
as permanent lifetime entity baseline intelligence.

Key Enterprise Capabilities:
  1. Precision Rolling Cutoff: Calculates cutoff down to the exact second (NOW - 30 days).
  2. Permanent Entity Safeguard: Invariant protection for suppression.cumulative_alerts.
  3. Chunked Batch Purging: Deletes in bounded chunks (5,000 rows) to prevent DB lock escalation.
  4. Post-Purge Optimization: Executes VACUUM ANALYZE to reclaim space and eliminate dead tuples.
  5. Audit Failure Monitoring: Logs every execution with row counts, duration, and alerting status.
"""
import os
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("pipeline.retention")


class RollingRetentionManager:
    """
    Manages automated sliding-window 30-day retention across database tables.
    """

    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                "config", "retention_policy.json"
            )
        self.config_path = config_path
        self.config = self._load_config()

        policy = self.config.get("retention_policy", {})
        self.retention_days = int(policy.get("retention_days", 30))
        self.retention_hours = int(policy.get("retention_hours", 720))
        self.batch_chunk_size = int(policy.get("batch_chunk_size", 5000))
        self.vacuum_enabled = bool(policy.get("vacuum_analyze_after_sweep", True))
        self.audit_logging = bool(policy.get("audit_logging", True))
        self.log_file = policy.get("log_file", "logs/retention_audit.log")

        self.target_tables = self.config.get("target_tables", {})
        self.permanently_preserved = {
            item["table"] for item in self.config.get("permanently_preserved_tables", [])
        }

    def _load_config(self) -> Dict[str, Any]:
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load retention_policy.json ({e}). Using defaults.")
        return {
            "retention_policy": {
                "retention_days": 30,
                "retention_hours": 720,
                "batch_chunk_size": 5000,
                "vacuum_analyze_after_sweep": True,
                "audit_logging": True,
            },
            "target_tables": {
                "telemetry.raw_events": {"timestamp_column": "timestamp"},
                "telemetry.normalized_events": {"timestamp_column": "event_timestamp"},
                "suppression.aggregated_alerts": {"timestamp_column": "window_end"},
                "correlation.correlated_incidents": {"timestamp_column": "last_seen_at"}
            },
            "permanently_preserved_tables": [
                {"table": "suppression.cumulative_alerts"}
            ]
        }

    def calculate_cutoff(self, reference_time: Optional[datetime] = None) -> datetime:
        """
        Compute the exact rolling retention cutoff timestamp down to the second.
        Data strictly older than (reference_time - 30 days) is eligible for purging.
        """
        ref = reference_time or datetime.now(timezone.utc)
        if ref.tzinfo is None:
            ref = ref.replace(tzinfo=timezone.utc)
        return ref - timedelta(days=self.retention_days)

    def is_table_protected(self, table_name: str) -> bool:
        """Check if table is strictly protected from retention purging."""
        clean = table_name.strip().lower()
        for p in self.permanently_preserved:
            if clean == p.lower() or clean.endswith(p.lower().split(".")[-1]):
                return True
        return False

    def execute_retention_sweep(
        self,
        db_manager: Any,
        reference_time: Optional[datetime] = None,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Execute precision rolling 30-day retention purge on all configured tables.

        Args:
            db_manager: DatabaseManager instance with active connection pool.
            reference_time: Optional reference datetime (defaults to UTC now).
            dry_run: If True, counts eligible rows without issuing DELETE statements.

        Returns:
            Dict containing detailed execution metrics, audit trail, and status.
        """
        t0 = time.time()
        cutoff_dt = self.calculate_cutoff(reference_time)
        cutoff_iso = cutoff_dt.isoformat()

        results = {
            "execution_time": datetime.now(timezone.utc).isoformat(),
            "cutoff_timestamp": cutoff_iso,
            "retention_days": self.retention_days,
            "dry_run": dry_run,
            "tables_purged": {},
            "total_rows_purged": 0,
            "vacuum_performed": False,
            "status": "SUCCESS",
            "errors": []
        }

        # Verify DB connection
        if not hasattr(db_manager, "get_connection") or db_manager._pool is None:
            if not db_manager.initialize_pool():
                results["status"] = "OFFLINE_SKIPPED"
                results["errors"].append("Database not reachable. Retention sweep skipped.")
                results["duration_seconds"] = round(time.time() - t0, 3)
                self._record_audit_log(results)
                return results

        try:
            with db_manager.get_connection() as conn:
                for table, meta in self.target_tables.items():
                    # Safety Guard: Never purge permanently preserved tables
                    if self.is_table_protected(table):
                        logger.error(f"[SECURITY ALERT] Attempted retention on permanently protected table: {table}")
                        results["errors"].append(f"Skipped protected table: {table}")
                        continue

                    col = meta.get("timestamp_column", "timestamp")
                    schema, tbl_name = table.split(".") if "." in table else ("public", table)

                    if dry_run:
                        # Count query only
                        count_sql = f"SELECT COUNT(*) FROM {schema}.{tbl_name} WHERE {col} < %s;"
                        with conn.cursor() as cur:
                            cur.execute(count_sql, (cutoff_dt,))
                            eligible = cur.fetchone()[0]
                            results["tables_purged"][table] = {
                                "eligible_rows": eligible,
                                "deleted_rows": 0,
                                "status": "DRY_RUN"
                            }
                            results["total_rows_purged"] += eligible
                    else:
                        # Chunked Purge Loop to avoid long transaction locks
                        deleted_in_table = 0
                        while True:
                            purge_sql = f"""
                            WITH to_delete AS (
                                SELECT ctid FROM {schema}.{tbl_name}
                                WHERE {col} < %s
                                LIMIT %s
                            )
                            DELETE FROM {schema}.{tbl_name}
                            WHERE ctid IN (SELECT ctid FROM to_delete);
                            """
                            with conn.cursor() as cur:
                                cur.execute(purge_sql, (cutoff_dt, self.batch_chunk_size))
                                count = cur.rowcount
                                deleted_in_table += max(0, count)
                                conn.commit()
                                if count < self.batch_chunk_size:
                                    break

                        results["tables_purged"][table] = {
                            "deleted_rows": deleted_in_table,
                            "status": "PURGED"
                        }
                        results["total_rows_purged"] += deleted_in_table

                # Gap 1 Resolution: Automatic VACUUM ANALYZE after sweep
                if self.vacuum_enabled and not dry_run and results["total_rows_purged"] > 0:
                    try:
                        # VACUUM cannot run inside a transaction block, so set isolation level
                        old_iso = conn.isolation_level
                        conn.set_isolation_level(0)  # autocommit mode
                        with conn.cursor() as cur:
                            for table in self.target_tables.keys():
                                if not self.is_table_protected(table):
                                    schema, tbl_name = table.split(".") if "." in table else ("public", table)
                                    cur.execute(f"VACUUM (ANALYZE) {schema}.{tbl_name};")
                        conn.set_isolation_level(old_iso)
                        results["vacuum_performed"] = True
                    except Exception as ve:
                        logger.warning(f"VACUUM ANALYZE completed with notice: {ve}")
                        results["vacuum_performed"] = False

        except Exception as e:
            results["status"] = "FAILED"
            results["errors"].append(str(e))
            logger.error(f"[RETENTION CRITICAL] Sweep failed: {e}")

        results["duration_seconds"] = round(time.time() - t0, 3)
        self._record_audit_log(results)
        return results

    def _record_audit_log(self, result: Dict[str, Any]):
        """Gap 2 Resolution: Save execution result to audit log file to prevent silent failures."""
        if not self.audit_logging:
            return
        log_dir = os.path.dirname(self.log_file)
        if log_dir and not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir, exist_ok=True)
            except Exception:
                pass
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(result) + "\n")
        except Exception as e:
            logger.warning(f"Could not append to retention audit log: {e}")
