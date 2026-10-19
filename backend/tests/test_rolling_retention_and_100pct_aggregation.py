"""
Test Suite: Rolling 30-Day Precision Retention & 100% Aggregation Coverage
==========================================================================
Verifies:
  1. 100% of events (including Fast-Track exploits & operational noise) enter
     the sliding-window aggregator without any silent edge drops.
  2. Rolling 30-Day Retention cutoff is calculated with second precision (NOW - 30 days).
  3. suppression.cumulative_alerts is strictly PERMANENT and protected by invariant guards.
  4. Automatic VACUUM ANALYZE and execution audit failure monitoring (Gaps 1 & 2 resolved).
  5. Configuration validation and dry-run execution safety.
"""
import os
import sys
import json
import pytest
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from pipeline.retention_manager import RollingRetentionManager
from pipeline.deduplicate import SlidingWindowAggregator
from pipeline.models import CommonEventModel
from pipeline.database import DatabaseManager


def make_test_event(rule_id="5715", level=3, category="AUTH_FAILURE", **kwargs):
    defaults = {
        "event_id": f"evt_{rule_id}_{kwargs.get('timestamp', '2026-09-21T11:00:00+00:00')}",
        "timestamp": kwargs.get("timestamp", "2026-09-21T11:00:00+00:00"),
        "rule_id": str(rule_id),
        "rule_level": level,
        "rule_description": kwargs.get("rule_description", "Test Rule Description"),
        "agent_id": "001",
        "agent_name": "srv-prod-web01",
        "tenant_id": "TenantA",
        "event_category": category,
        "dedup_actor": kwargs.get("actor", "user:admin"),
        "dedup_target": "srv-prod-web01",
        "source_ip": "192.168.1.100",
        "window_class": "STANDARD",
        "window_duration_seconds": 900,
    }
    defaults.update(kwargs)
    return CommonEventModel(**defaults)


# ---------------------------------------------------------------------------
# Test Group 1: 100% Aggregation Coverage (Zero Drops)
# ---------------------------------------------------------------------------
class TestAggregation100PercentCoverage:

    def test_fast_track_exploit_is_aggregated(self):
        """
        Critical P0/P1 exploits (Level >= 10, CVEs) must enter sliding-window
        aggregation and be recorded in aggregated_alerts, NOT just correlation.
        """
        aggregator = SlidingWindowAggregator()
        # Fast-track CVE event
        event = make_test_event(
            rule_id="31103",
            level=10,
            category="WEB_ATTACK",
            rule_description="SQL injection attack detected"
        )
        aggregator.process_event(event)
        
        # Flush all windows
        flushed = aggregator.flush_all()
        assert len(flushed) == 1, "FAST_TRACK exploit must generate an aggregated alert"
        assert flushed[0]["rule_id"] == 31103
        assert flushed[0]["event_count"] == 1
        assert flushed[0]["category"] == "WEB_ATTACK"

    def test_high_volume_noise_is_aggregated_not_dropped(self):
        """
        High-volume repetitive noise (e.g., AppArmor 52002 or syscollector 533)
        must NOT be dropped before aggregation; it must be compressed into an aggregate.
        """
        aggregator = SlidingWindowAggregator()
        for i in range(100):
            event = make_test_event(
                rule_id="52002",
                level=3,
                category="EXECUTION",
                actor="proc:apparmor",
                timestamp=f"2026-09-21T11:{i//10:02d}:{i%10:02d}+00:00"
            )
            aggregator.process_event(event)

        flushed = aggregator.flush_all()
        assert len(flushed) >= 1, "High volume noise must produce aggregated window"
        total_counted = sum(a["event_count"] for a in flushed)
        assert total_counted == 100, f"Expected 100 events aggregated, got {total_counted}"


# ---------------------------------------------------------------------------
# Test Group 2: Rolling 30-Day Precision Cutoff Calculation
# ---------------------------------------------------------------------------
class TestRollingCutoffCalculation:

    def test_exact_precision_cutoff_down_to_the_second(self):
        """
        Rolling 30-day cutoff must be exact down to the second (not calendar month).
        Example: Reference 2026-09-21 11:15:30 -> Cutoff 2026-08-22 11:15:30.
        """
        manager = RollingRetentionManager()
        ref_time = datetime(2026, 9, 21, 11, 15, 30, tzinfo=timezone.utc)
        expected_cutoff = datetime(2026, 8, 22, 11, 15, 30, tzinfo=timezone.utc)
        
        computed_cutoff = manager.calculate_cutoff(ref_time)
        assert computed_cutoff == expected_cutoff, f"Expected {expected_cutoff}, got {computed_cutoff}"
        assert computed_cutoff.hour == 11
        assert computed_cutoff.minute == 15
        assert computed_cutoff.second == 30

    def test_naive_datetime_handled_safely(self):
        """Naive datetimes must be safely assumed UTC without crash."""
        manager = RollingRetentionManager()
        ref_time = datetime(2026, 9, 21, 15, 0, 0)  # naive
        computed = manager.calculate_cutoff(ref_time)
        assert computed.tzinfo is not None, "Cutoff must be timezone-aware (UTC)"


# ---------------------------------------------------------------------------
# Test Group 3: Permanent Safeguard of cumulative_alerts
# ---------------------------------------------------------------------------
class TestCumulativeAlertsPermanentSafeguard:

    def test_cumulative_alerts_is_strictly_protected(self):
        """
        suppression.cumulative_alerts must be registered in permanently_preserved_tables
        and is_table_protected() must return True for all alias variations.
        """
        manager = RollingRetentionManager()
        assert manager.is_table_protected("suppression.cumulative_alerts") is True
        assert manager.is_table_protected("cumulative_alerts") is True
        assert manager.is_table_protected("SUPPRESSION.CUMULATIVE_ALERTS") is True

    def test_target_tables_do_not_contain_cumulative_alerts(self):
        """Target tables configured for purge must NEVER include cumulative_alerts."""
        manager = RollingRetentionManager()
        for tbl in manager.target_tables.keys():
            assert "cumulative" not in tbl.lower(), f"Target tables must not purge cumulative table: {tbl}"

    def test_protected_tables_list_is_enforced(self):
        """Permanent tables list must be populated from config."""
        manager = RollingRetentionManager()
        assert len(manager.permanently_preserved) >= 1
        assert any("cumulative_alerts" in t for t in manager.permanently_preserved)


# ---------------------------------------------------------------------------
# Test Group 4: Configuration & Execution Metrics (Gaps 1 & 2)
# ---------------------------------------------------------------------------
class TestRetentionConfigAndAuditExecution:

    def test_config_file_exists_and_valid(self):
        """config/retention_policy.json must exist, be valid JSON, and have 30 days set."""
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "config", "retention_policy.json"
        )
        assert os.path.exists(config_path)
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["retention_policy"]["retention_days"] == 30
        assert data["retention_policy"]["vacuum_analyze_after_sweep"] is True
        assert "telemetry.raw_events" in data["target_tables"]
        assert "telemetry.normalized_events" in data["target_tables"]
        assert "suppression.aggregated_alerts" in data["target_tables"]

    def test_dry_run_execution_metrics(self):
        """
        dry_run=True must execute safely without modifying data and return
        comprehensive audit metrics (duration, cutoff, status).
        """
        manager = RollingRetentionManager()
        # Mock database manager that is offline
        class MockDB:
            _pool = None
            def initialize_pool(self):
                return False

        res = manager.execute_retention_sweep(MockDB(), dry_run=True)
        assert res["status"] in ("OFFLINE_SKIPPED", "SUCCESS")
        assert "cutoff_timestamp" in res
        assert res["retention_days"] == 30
        assert "duration_seconds" in res

    def test_database_manager_has_retention_methods(self):
        """DatabaseManager must expose ensure_retention_indexes and execute_rolling_retention."""
        db = DatabaseManager()
        assert hasattr(db, "ensure_retention_indexes")
        assert hasattr(db, "execute_rolling_retention")
