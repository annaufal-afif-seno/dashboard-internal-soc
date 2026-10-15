-- ==============================================================================
-- SCHEMA: METRICS (OPERATIONAL ROLLUPS & KPI TRACKING)
-- ==============================================================================

-- 1. HOURLY OVERVIEW ROLLUP
CREATE TABLE IF NOT EXISTS metrics.hourly_overview_rollup (
    bucket_hour TIMESTAMPTZ PRIMARY KEY,
    total_raw_events BIGINT DEFAULT 0,
    total_aggregates BIGINT DEFAULT 0,
    total_suppressed BIGINT DEFAULT 0,
    total_incidents BIGINT DEFAULT 0,
    noise_reduction_pct NUMERIC(5,2) DEFAULT 0.0,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 2. OPERATIONAL METRICS DAILY
CREATE TABLE IF NOT EXISTS metrics.operational_metrics_daily (
    metric_date DATE PRIMARY KEY,
    mean_time_to_detect_seconds INT DEFAULT 0,
    mean_time_to_triage_seconds INT DEFAULT 0,
    sla_compliance_rate_pct NUMERIC(5,2) DEFAULT 100.0,
    total_tickets_handled INT DEFAULT 0,
    total_false_positives INT DEFAULT 0,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
