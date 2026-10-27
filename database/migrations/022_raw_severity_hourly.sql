-- Migration 022: Create metrics.raw_severity_hourly rollup table
CREATE SCHEMA IF NOT EXISTS metrics;

CREATE TABLE IF NOT EXISTS metrics.raw_severity_hourly (
    bucket_hour TIMESTAMPTZ NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    total BIGINT DEFAULT 0,
    critical BIGINT DEFAULT 0,
    high BIGINT DEFAULT 0,
    medium BIGINT DEFAULT 0,
    low BIGINT DEFAULT 0,
    PRIMARY KEY (bucket_hour, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_raw_severity_hourly_tenant_time 
ON metrics.raw_severity_hourly (tenant_id, bucket_hour DESC);
