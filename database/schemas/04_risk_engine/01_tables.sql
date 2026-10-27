-- ==============================================================================
-- SCHEMA: RISK_ENGINE (DYNAMIC RISK SCORING)
-- ==============================================================================

-- 1. CALCULATED RISK SCORES (Normalized 0-100 Score per Incident/Entity)
CREATE TABLE IF NOT EXISTS risk_engine.calculated_risk_scores (
    score_id BIGSERIAL PRIMARY KEY,
    entity_id VARCHAR(64) NOT NULL,
    entity_type VARCHAR(32) NOT NULL, -- INCIDENT, AGGREGATE, HOST, ACTOR
    total_score INT NOT NULL DEFAULT 0,
    priority VARCHAR(8) NOT NULL DEFAULT 'P3', -- P0, P1, P2, P3, P4
    urgency_score NUMERIC(5,2) DEFAULT 0.0,
    sla_hours INT DEFAULT 24,
    evaluated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 2. RISK SCORING FACTORS (Explainability Breakdown of Scores)
CREATE TABLE IF NOT EXISTS risk_engine.risk_scoring_factors (
    factor_id BIGSERIAL PRIMARY KEY,
    score_id BIGINT NOT NULL REFERENCES risk_engine.calculated_risk_scores(score_id) ON DELETE CASCADE,
    factor_name VARCHAR(64) NOT NULL,
    weight NUMERIC(4,2) NOT NULL,
    raw_value VARCHAR(64),
    score_contribution INT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_risk_scores_entity ON risk_engine.calculated_risk_scores (entity_id, entity_type);
CREATE INDEX IF NOT EXISTS idx_risk_scores_priority ON risk_engine.calculated_risk_scores (priority);
CREATE INDEX IF NOT EXISTS idx_risk_factors_score_id ON risk_engine.risk_scoring_factors (score_id);
