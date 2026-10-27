-- Migration 026: Create Cluster View Aliases & Disambiguate Terminology
-- Provides intuitive, unambiguous VIEW names matching the SOC Dashboard terminology
-- while maintaining 100% backward compatibility for all pipeline queries.

-- 1. Cluster Interval View (15-Minute Bursts / Aggregates)
CREATE OR REPLACE VIEW suppression.v_cluster_interval AS
SELECT * FROM suppression.aggregated_alerts;

COMMENT ON VIEW suppression.v_cluster_interval IS 
'Alias untuk Cluster Tipe Interval (15 Menit) - Merujuk ke suppression.aggregated_alerts (715k rows)';

-- 2. Cluster Cumulative View (Lifetime Entity / Cumulative Aggregates)
CREATE OR REPLACE VIEW suppression.v_cluster_cumulative AS
SELECT * FROM suppression.cumulative_alerts;

COMMENT ON VIEW suppression.v_cluster_cumulative IS 
'Alias untuk Cluster Tipe Kumulatif (Sepanjang Waktu) - Merujuk ke suppression.cumulative_alerts (266k rows)';

-- 3. Threat Campaign Attack Graph View (Stage 4.5 Correlation Clusters)
CREATE OR REPLACE VIEW correlation.v_threat_campaigns AS
SELECT * FROM correlation.threat_campaign_clusters;

COMMENT ON VIEW correlation.v_threat_campaigns IS 
'Alias untuk Stage 4.5 Threat Campaign Attack Graph Clusters (43 campaigns)';
