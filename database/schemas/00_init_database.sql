-- ==============================================================================
-- 00_INIT_DATABASE.SQL: EXTENSIONS & GLOBAL SCHEMA INITIALIZATION
-- ==============================================================================
-- Standard PostgreSQL Extensions for Enterprise SIEM & Similarity Search

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Domain Schemas (Separation of Concerns)
CREATE SCHEMA IF NOT EXISTS telemetry;     -- Raw & Normalized Log Ingestion
CREATE SCHEMA IF NOT EXISTS suppression;   -- Sliding-Window Deduplication & Noise Reduction
CREATE SCHEMA IF NOT EXISTS correlation;   -- Multi-Stage Attack Chain Correlation
CREATE SCHEMA IF NOT EXISTS risk_engine;   -- Multi-Factor Dynamic Risk Scoring
CREATE SCHEMA IF NOT EXISTS soc_ops;       -- Analyst Incident Triage, SLA, & AI Ground Truth
CREATE SCHEMA IF NOT EXISTS enrichment;    -- Threat Intelligence, Asset & Identity Context
CREATE SCHEMA IF NOT EXISTS metrics;       -- Operational Rollups & KPI Metrics
