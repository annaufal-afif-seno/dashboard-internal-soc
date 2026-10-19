"""
Unit Tests for Database Module, DDL Migration Scripts, Seed Data & Query Generators (Phase 3)
"""
import os
import pytest
from pipeline.database import DatabaseManager
from config.settings import BASE_DIR


def test_migration_sql_file_exists_and_valid():
    migration_path = BASE_DIR / "database" / "migrations" / "001_initial_schema.sql"
    assert migration_path.exists(), "Missing 001_initial_schema.sql"
    with open(migration_path, "r", encoding="utf-8") as f:
        sql = f.read()

    # Check for all 19 required tables in the DDL
    expected_tables = [
        "raw_events",
        "normalized_events",
        "asset_inventory_context",
        "identity_context",
        "threat_intelligence_iocs",
        "maintenance_windows",
        "suppression_rules",
        "suppression_audit_log",
        "aggregated_alerts",
        "aggregate_evidence_mapping",
        "correlation_rules",
        "correlated_incidents",
        "incident_stages",
        "risk_scoring_factors",
        "calculated_risk_scores",
        "soc_triage_queue",
        "incident_investigation_notes",
        "incident_response_actions",
        "operational_metrics_daily"
    ]

    import re
    for tbl in expected_tables:
        pattern = rf"CREATE TABLE IF NOT EXISTS (?:[a-zA-Z0-9_]+\.)?{tbl}\b"
        assert re.search(pattern, sql), f"Missing table DDL for: {tbl}"

    # Check constraints and stored procedures
    assert "chk_separation_of_duties" in sql
    assert "chk_score_priority_alignment" in sql
    assert "create_monthly_partitions" in sql
    assert "purge_expired_partitions" in sql


def test_seed_data_sql_file_exists_and_valid():
    seed_path = BASE_DIR / "database" / "seed_data.sql"
    assert seed_path.exists(), "Missing seed_data.sql"
    with open(seed_path, "r", encoding="utf-8") as f:
        sql = f.read()

    assert "INSERT INTO asset_inventory_context" in sql
    assert "INSERT INTO identity_context" in sql
    assert "INSERT INTO threat_intelligence_iocs" in sql
    assert "INSERT INTO suppression_rules" in sql
    assert "INSERT INTO correlation_rules" in sql
    assert "dc-01.prod.local" in sql
    assert "CROWN_JEWEL" in sql
    assert "SUP-2026-001" in sql


def test_database_manager_initialization():
    db = DatabaseManager(
        host="localhost",
        port=5432,
        dbname="wazuh_test",
        user="postgres",
        password="test_password"
    )
    assert db.host == "localhost"
    assert db.dbname == "wazuh_test"
    # Pool starts as None until initialized
    assert db._pool is None


def test_bulk_insert_evidence_mapping_method_exists():
    """[GAP 5 Fix] Pastikan DatabaseManager punya method bulk_insert_evidence_mapping."""
    db = DatabaseManager()
    assert hasattr(db, "bulk_insert_evidence_mapping"), (
        "bulk_insert_evidence_mapping missing dari DatabaseManager — GAP 5 regresi!"
    )
    assert callable(db.bulk_insert_evidence_mapping), (
        "bulk_insert_evidence_mapping bukan callable"
    )
    # Pastikan empty list returns 0 tanpa DB connection
    # (Method harus early-exit sebelum minta koneksi)
    result = db.bulk_insert_evidence_mapping([])
    assert result == 0, "Empty evidence_links harus return 0 tanpa menyentuh DB"


def test_pipeline_integrates_gap4_and_gap5():
    """
    [GAP 4 + GAP 5 Regression Guard]
    Verifikasi bahwa run_master_pipeline.py memanggil:
    - load_snapshot() — crash recovery
    - save_snapshot() — per-file checkpoint
    - bulk_insert_evidence_mapping() — forensic evidence links
    """
    pipeline_path = BASE_DIR / "run_master_pipeline.py"
    assert pipeline_path.exists(), "run_master_pipeline.py tidak ditemukan"
    with open(pipeline_path, "r", encoding="utf-8") as f:
        src = f.read()

    assert "load_snapshot" in src, (
        "load_snapshot() tidak dipanggil di run_master_pipeline.py — GAP 4 regresi!"
    )
    assert "save_snapshot" in src, (
        "save_snapshot() tidak dipanggil di run_master_pipeline.py — GAP 4 regresi!"
    )
    assert "bulk_insert_evidence_mapping" in src, (
        "bulk_insert_evidence_mapping() tidak dipanggil di run_master_pipeline.py — GAP 5 regresi!"
    )
    assert "evidence_batch" in src, (
        "evidence_batch buffer tidak ditemukan di run_master_pipeline.py — GAP 5 regresi!"
    )
    assert "total_evidence_links" in src, (
        "total_evidence_links counter tidak ditemukan — GAP 5 regresi!"
    )

