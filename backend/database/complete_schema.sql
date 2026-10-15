--
-- PostgreSQL database dump
--

\restrict VRbYBHMRXuuuce86N3IC0DdIiLrdEWEVzXIxsZ1d01jhHDen2fSHWea5SgQAyba

-- Dumped from database version 18.6
-- Dumped by pg_dump version 18.6

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: correlation; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA correlation;


--
-- Name: enrichment; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA enrichment;


--
-- Name: metrics; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA metrics;


--
-- Name: public; Type: SCHEMA; Schema: -; Owner: -
--

-- *not* creating schema, since initdb creates it


--
-- Name: SCHEMA public; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON SCHEMA public IS '';


--
-- Name: risk_engine; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA risk_engine;


--
-- Name: soc_ops; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA soc_ops;


--
-- Name: suppression; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA suppression;


--
-- Name: telemetry; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA telemetry;


--
-- Name: btree_gin; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS btree_gin WITH SCHEMA public;


--
-- Name: EXTENSION btree_gin; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION btree_gin IS 'support for indexing common datatypes in GIN';


--
-- Name: pg_trgm; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;


--
-- Name: EXTENSION pg_trgm; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pg_trgm IS 'text similarity measurement and index searching based on trigrams';


--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


--
-- Name: purge_expired_partitions(integer); Type: PROCEDURE; Schema: public; Owner: -
--

CREATE PROCEDURE public.purge_expired_partitions(IN retention_days integer)
    LANGUAGE plpgsql
    AS $_$
                    DECLARE
                        part_record RECORD;
                        cutoff_date DATE;
                        part_date DATE;
                        tbl_name TEXT;
                        parent_tbl TEXT;
                    BEGIN
                        cutoff_date := CURRENT_DATE - (retention_days || ' days')::INTERVAL;
                        
                        FOR parent_tbl IN VALUES ('normalized_events'), ('raw_events')
                        LOOP
                            FOR part_record IN 
                                SELECT c.relname AS child_table
                                FROM pg_inherits i
                                JOIN pg_class c ON i.inhrelid = c.oid
                                JOIN pg_class p ON i.inhparent = p.oid
                                JOIN pg_namespace n ON p.relnamespace = n.oid
                                WHERE p.relname = parent_tbl AND n.nspname = 'telemetry'
                            LOOP
                                tbl_name := part_record.child_table;
                                BEGIN
                                    part_date := TO_DATE(SUBSTRING(tbl_name FROM '_([0-9]{4}_[0-9]{2})$'), 'YYYY_MM');
                                    
                                    IF part_date < DATE_TRUNC('month', cutoff_date) THEN
                                        EXECUTE FORMAT('ALTER TABLE telemetry.%I DETACH PARTITION telemetry.%I;', parent_tbl, tbl_name);
                                        EXECUTE FORMAT('DROP TABLE telemetry.%I;', tbl_name);
                                    END IF;
                                EXCEPTION WHEN OTHERS THEN
                                    CONTINUE;
                                END;
                            END LOOP;
                        END LOOP;
                    END;
                    $_$;


--
-- Name: trigger_set_timestamp(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trigger_set_timestamp() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;


--
-- Name: capture_ground_truth_on_triage(); Type: FUNCTION; Schema: soc_ops; Owner: -
--

CREATE FUNCTION soc_ops.capture_ground_truth_on_triage() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_inc RECORD;
    v_score RECORD;
    v_asset RECORD;
    v_gt_label INT;
BEGIN
    -- Hanya rekam jika ada keputusan resolusi definitif
    IF NEW.resolution_outcome IS NOT NULL AND (
        OLD.resolution_outcome IS DISTINCT FROM NEW.resolution_outcome OR
        OLD.triage_status IS DISTINCT FROM NEW.triage_status
    ) THEN
        -- Tentukan Label Biner: 0 = Benign/Noise (Auto-Dismiss), 1 = True Threat/Actionable Incident
        IF NEW.resolution_outcome IN ('FALSE_POSITIVE_TUNING_REQ', 'OPERATIONAL_NOISE', 'BENIGN_AUTHORIZED', 'TRUE_POSITIVE_NO_ACTION') THEN
            v_gt_label := 0;
        ELSIF NEW.resolution_outcome IN ('TRUE_POSITIVE_ACTIONABLE') THEN
            v_gt_label := 1;
        ELSE
            -- Status lain seperti REJECTED atau CUSTOM tidak dijadikan training data otomatis
            RETURN NEW;
        END IF;

        -- Ambil data insiden
        SELECT * INTO v_inc 
        FROM correlation.correlated_incidents 
        WHERE incident_id = NEW.incident_id;

        -- Ambil data calculated score
        SELECT * INTO v_score 
        FROM risk_engine.calculated_risk_scores 
        WHERE incident_id = NEW.incident_id;

        -- Ambil data aset
        SELECT * INTO v_asset 
        FROM enrichment.asset_inventory_context 
        WHERE hostname = v_inc.target_host OR ip_address = v_inc.target_host
        LIMIT 1;

        -- Upsert record ke tabel ground_truth_dataset
        INSERT INTO soc_ops.ground_truth_dataset (
            incident_id,
            triage_id,
            tenant_id,
            rule_code,
            rule_level,
            event_count,
            max_inline_risk_score,
            total_risk_score,
            priority,
            target_host,
            host_criticality,
            is_internet_exposed,
            is_privileged_user,
            threat_intel_match,
            ioa_summary,
            ground_truth_label,
            resolution_outcome,
            analyst_id,
            analyst_notes,
            created_at
        ) VALUES (
            NEW.incident_id,
            NEW.triage_id,
            COALESCE(v_inc.tenant_id, 'DEFAULT'),
            COALESCE(v_inc.correlation_rule_id, 'UNKNOWN'),
            ROUND(COALESCE(v_score.total_score, 50) / 7.0)::INT,
            COALESCE((SELECT COUNT(*) FROM correlation.incident_stages WHERE incident_id = NEW.incident_id), 1),
            COALESCE(v_score.total_score, 50),
            COALESCE(v_score.total_score, 50),
            NEW.priority,
            v_inc.target_host,
            COALESCE(v_asset.criticality_tier, 'STANDARD'),
            COALESCE(v_asset.is_internet_exposed, FALSE),
            (v_inc.compromised_account ILIKE '%root%' OR v_inc.compromised_account ILIKE '%admin%'),
            (v_inc.attacker_source_ip IS NOT NULL AND v_inc.attacker_source_ip != 'unknown'),
            v_inc.narrative,
            v_gt_label,
            NEW.resolution_outcome,
            NEW.assigned_analyst,
            NEW.false_positive_reason,
            CURRENT_TIMESTAMP
        )
        ON CONFLICT (incident_id) DO UPDATE SET
            ground_truth_label = EXCLUDED.ground_truth_label,
            resolution_outcome = EXCLUDED.resolution_outcome,
            analyst_id = EXCLUDED.analyst_id,
            analyst_notes = EXCLUDED.analyst_notes,
            created_at = CURRENT_TIMESTAMP;
    END IF;

    RETURN NEW;
END;
$$;


--
-- Name: get_active_incident_for_cooldown(character varying, character varying, character varying); Type: FUNCTION; Schema: soc_ops; Owner: -
--

CREATE FUNCTION soc_ops.get_active_incident_for_cooldown(p_attacker_ip character varying, p_target_host character varying, p_tenant_id character varying) RETURNS TABLE(incident_id character varying, triage_id character varying, triage_status character varying, cooldown_until timestamp with time zone, last_seen_at timestamp with time zone)
    LANGUAGE sql STABLE
    AS $$
    SELECT
        i.incident_id,
        t.triage_id,
        t.triage_status,
        t.cooldown_until,
        i.last_seen_at
    FROM correlation.correlated_incidents i
    JOIN soc_ops.soc_triage_queue t ON i.incident_id = t.incident_id
    WHERE
        i.tenant_id = p_tenant_id
        AND (i.attacker_source_ip = p_attacker_ip OR i.target_host = p_target_host)
        AND t.triage_status NOT IN ('CLOSED')
        AND (t.cooldown_until IS NULL OR t.cooldown_until > CURRENT_TIMESTAMP)
    ORDER BY i.last_seen_at DESC
    LIMIT 1;
$$;


--
-- Name: FUNCTION get_active_incident_for_cooldown(p_attacker_ip character varying, p_target_host character varying, p_tenant_id character varying); Type: COMMENT; Schema: soc_ops; Owner: -
--

COMMENT ON FUNCTION soc_ops.get_active_incident_for_cooldown(p_attacker_ip character varying, p_target_host character varying, p_tenant_id character varying) IS 'Returns the most recent open/in-cooldown incident for an actor+target pair.
Used by the correlation engine to decide: append to existing ticket vs create new ticket.
Returns NULL if no active cooldown exists (= safe to create new ticket).';


--
-- Name: trigger_set_cooldown_on_resolve(); Type: FUNCTION; Schema: soc_ops; Owner: -
--

CREATE FUNCTION soc_ops.trigger_set_cooldown_on_resolve() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Saat status berubah ke RESOLVED, set cooldown_until = resolved_at + 72 jam (default)
    -- SOC dapat override cooldown_hours per correlation rule via incident metadata
    IF NEW.triage_status = 'RESOLVED' AND (OLD.triage_status IS DISTINCT FROM 'RESOLVED') THEN
        IF NEW.resolved_at IS NULL THEN
            NEW.resolved_at := CURRENT_TIMESTAMP;
        END IF;
        -- Default cooldown: 72 jam. Override dengan set cooldown_until manual sebelum commit.
        IF NEW.cooldown_until IS NULL THEN
            NEW.cooldown_until := NEW.resolved_at + INTERVAL '72 hours';
        END IF;
    END IF;
    -- Jika tiket di-re-open (status kembali ke IN_TRIAGE/INVESTIGATING), clear cooldown
    IF NEW.triage_status IN ('INVESTIGATING', 'IN_TRIAGE') AND OLD.triage_status = 'RESOLVED' THEN
        NEW.cooldown_until := NULL;
        NEW.resolved_at := NULL;
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: trigger_triage_resolved(); Type: FUNCTION; Schema: soc_ops; Owner: -
--

CREATE FUNCTION soc_ops.trigger_triage_resolved() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.triage_status = 'RESOLVED' AND (OLD.triage_status IS DISTINCT FROM 'RESOLVED') THEN
        IF NEW.resolved_at IS NULL THEN
            NEW.resolved_at := CURRENT_TIMESTAMP;
        END IF;
        NEW.mean_time_to_triage_seconds := ROUND(EXTRACT(EPOCH FROM (NEW.resolved_at - NEW.created_at)))::INT;
    END IF;

    -- Automatically set 24h cooldown for P2 & P3 when status changes to CLOSED
    IF NEW.triage_status = 'CLOSED' AND (OLD.triage_status IS DISTINCT FROM 'CLOSED') THEN
        IF NEW.resolved_at IS NULL THEN
            NEW.resolved_at := CURRENT_TIMESTAMP;
        END IF;
        IF NEW.priority IN ('P2', 'P3') AND NEW.cooldown_until IS NULL THEN
            NEW.cooldown_until := CURRENT_TIMESTAMP + INTERVAL '24 hours';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;


--
-- Name: create_monthly_partitions(date); Type: PROCEDURE; Schema: telemetry; Owner: -
--

CREATE PROCEDURE telemetry.create_monthly_partitions(IN target_date date)
    LANGUAGE plpgsql
    AS $$
DECLARE
    start_time TIMESTAMPTZ;
    end_time TIMESTAMPTZ;
    raw_part_name TEXT;
    norm_part_name TEXT;
BEGIN
    start_time := DATE_TRUNC('month', target_date);
    end_time   := start_time + INTERVAL '1 month';
    
    raw_part_name  := 'raw_events_' || TO_CHAR(start_time, 'YYYY_MM');
    norm_part_name := 'normalized_events_' || TO_CHAR(start_time, 'YYYY_MM');
    
    EXECUTE FORMAT(
        'CREATE TABLE IF NOT EXISTS telemetry.%I PARTITION OF telemetry.raw_events FOR VALUES FROM (%L) TO (%L);', 
        raw_part_name, start_time, end_time
    );
    EXECUTE FORMAT(
        'CREATE TABLE IF NOT EXISTS telemetry.%I PARTITION OF telemetry.normalized_events FOR VALUES FROM (%L) TO (%L);', 
        norm_part_name, start_time, end_time
    );
END;
$$;


--
-- Name: purge_expired_partitions(integer); Type: PROCEDURE; Schema: telemetry; Owner: -
--

CREATE PROCEDURE telemetry.purge_expired_partitions(IN retention_days integer)
    LANGUAGE plpgsql
    AS $_$
DECLARE
    part_record RECORD;
    cutoff_date DATE;
    part_date DATE;
    tbl_name TEXT;
    parent_tbl TEXT;
BEGIN
    cutoff_date := CURRENT_DATE - (retention_days || ' days')::INTERVAL;
    
    FOR parent_tbl IN VALUES ('normalized_events'), ('raw_events')
    LOOP
        FOR part_record IN 
            SELECT c.relname AS child_table
            FROM pg_inherits i
            JOIN pg_class c ON i.inhrelid = c.oid
            JOIN pg_class p ON i.inhparent = p.oid
            JOIN pg_namespace n ON p.relnamespace = n.oid
            WHERE p.relname = parent_tbl AND n.nspname = 'telemetry'
        LOOP
            tbl_name := part_record.child_table;
            BEGIN
                part_date := TO_DATE(SUBSTRING(tbl_name FROM '_([0-9]{4}_[0-9]{2})$'), 'YYYY_MM');
                
                IF part_date < DATE_TRUNC('month', cutoff_date) THEN
                    EXECUTE FORMAT('ALTER TABLE telemetry.%I DETACH PARTITION telemetry.%I;', parent_tbl, tbl_name);
                    EXECUTE FORMAT('DROP TABLE telemetry.%I;', tbl_name);
                END IF;
            EXCEPTION WHEN OTHERS THEN
                CONTINUE;
            END;
        END LOOP;
    END LOOP;
END;
$_$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: correlated_incidents; Type: TABLE; Schema: correlation; Owner: -
--

CREATE TABLE correlation.correlated_incidents (
    incident_id character varying(64) NOT NULL,
    correlation_rule_id character varying(32) NOT NULL,
    tenant_id character varying(64) DEFAULT 'DEFAULT'::character varying,
    title character varying(255) NOT NULL,
    narrative text NOT NULL,
    initial_access_vector character varying(128),
    attacker_source_ip character varying(45),
    compromised_account character varying(128),
    target_host character varying(128),
    incident_status character varying(32) DEFAULT 'DETECTED'::character varying,
    first_seen_at timestamp with time zone NOT NULL,
    last_seen_at timestamp with time zone NOT NULL,
    detected_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    related_incident_ids text[] DEFAULT '{}'::text[],
    CONSTRAINT correlated_incidents_incident_status_check CHECK (((incident_status)::text = ANY ((ARRAY['DETECTED'::character varying, 'IN_TRIAGE'::character varying, 'ESCALATED'::character varying, 'CONTAINED'::character varying, 'RESOLVED'::character varying, 'CLOSED_FP'::character varying])::text[])))
);


--
-- Name: correlation_rules; Type: TABLE; Schema: correlation; Owner: -
--

CREATE TABLE correlation.correlation_rules (
    correlation_rule_id character varying(32) NOT NULL,
    rule_code character varying(64) NOT NULL,
    rule_name character varying(128) NOT NULL,
    description text NOT NULL,
    timeframe_seconds integer NOT NULL,
    target_severity character varying(8) NOT NULL,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT correlation_rules_target_severity_check CHECK (((target_severity)::text = ANY ((ARRAY['P0'::character varying, 'P1'::character varying, 'P2'::character varying, 'P3'::character varying])::text[]))),
    CONSTRAINT correlation_rules_timeframe_seconds_check CHECK ((timeframe_seconds > 0))
);


--
-- Name: incident_stages; Type: TABLE; Schema: correlation; Owner: -
--

CREATE TABLE correlation.incident_stages (
    stage_id bigint NOT NULL,
    incident_id character varying(64) NOT NULL,
    sequence_order integer NOT NULL,
    stage_name character varying(64) NOT NULL,
    reference_id character varying(64) NOT NULL,
    evidence_type character varying(32) NOT NULL,
    stage_description text,
    recorded_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT incident_stages_evidence_type_check CHECK (((evidence_type)::text = ANY ((ARRAY['AGGREGATED_ALERT'::character varying, 'NORMALIZED_EVENT'::character varying, 'CUMULATIVE_PROFILE'::character varying])::text[]))),
    CONSTRAINT incident_stages_sequence_order_check CHECK ((sequence_order >= 1))
);


--
-- Name: incident_stages_stage_id_seq; Type: SEQUENCE; Schema: correlation; Owner: -
--

CREATE SEQUENCE correlation.incident_stages_stage_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: incident_stages_stage_id_seq; Type: SEQUENCE OWNED BY; Schema: correlation; Owner: -
--

ALTER SEQUENCE correlation.incident_stages_stage_id_seq OWNED BY correlation.incident_stages.stage_id;


--
-- Name: asset_inventory_context; Type: TABLE; Schema: enrichment; Owner: -
--

CREATE TABLE enrichment.asset_inventory_context (
    asset_id character varying(64) NOT NULL,
    hostname character varying(128) NOT NULL,
    ip_address character varying(45),
    asset_type character varying(32) NOT NULL,
    criticality_tier character varying(16) NOT NULL,
    criticality_score integer NOT NULL,
    environment character varying(32) DEFAULT 'PRODUCTION'::character varying,
    is_internet_exposed boolean DEFAULT false,
    owner_department character varying(128),
    last_synced_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT asset_inventory_context_criticality_score_check CHECK ((criticality_score = ANY (ARRAY[0, 5, 15, 20, 25]))),
    CONSTRAINT asset_inventory_context_criticality_tier_check CHECK (((criticality_tier)::text = ANY ((ARRAY['CROWN_JEWEL'::character varying, 'CRITICAL'::character varying, 'HIGH'::character varying, 'STANDARD'::character varying, 'LAB'::character varying])::text[]))),
    CONSTRAINT asset_inventory_context_environment_check CHECK (((environment)::text = ANY ((ARRAY['PRODUCTION'::character varying, 'STAGING'::character varying, 'DEVELOPMENT'::character varying, 'LAB'::character varying])::text[])))
);


--
-- Name: identity_context; Type: TABLE; Schema: enrichment; Owner: -
--

CREATE TABLE enrichment.identity_context (
    identity_id character varying(64) NOT NULL,
    username character varying(128) NOT NULL,
    account_type character varying(32) NOT NULL,
    is_privileged boolean DEFAULT false,
    department character varying(128),
    expected_hosts text[] DEFAULT '{}'::text[],
    risk_baseline_score integer DEFAULT 0,
    last_synced_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT identity_context_account_type_check CHECK (((account_type)::text = ANY ((ARRAY['STANDARD_USER'::character varying, 'PRIVILEGED_ADMIN'::character varying, 'SERVICE_ACCOUNT'::character varying, 'SYSTEM'::character varying, 'EXTERNAL_VENDOR'::character varying])::text[]))),
    CONSTRAINT identity_context_risk_baseline_score_check CHECK (((risk_baseline_score >= 0) AND (risk_baseline_score <= 100)))
);


--
-- Name: threat_intelligence_iocs; Type: TABLE; Schema: enrichment; Owner: -
--

CREATE TABLE enrichment.threat_intelligence_iocs (
    ioc_id bigint NOT NULL,
    indicator_value character varying(255) NOT NULL,
    indicator_type character varying(16) NOT NULL,
    threat_actor character varying(128),
    malware_family character varying(128),
    confidence_score integer NOT NULL,
    source_feed character varying(64) NOT NULL,
    description text,
    is_active boolean DEFAULT true,
    first_seen timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    last_seen timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp with time zone,
    CONSTRAINT threat_intelligence_iocs_confidence_score_check CHECK (((confidence_score >= 0) AND (confidence_score <= 100))),
    CONSTRAINT threat_intelligence_iocs_indicator_type_check CHECK (((indicator_type)::text = ANY ((ARRAY['IPV4'::character varying, 'IPV6'::character varying, 'DOMAIN'::character varying, 'MD5'::character varying, 'SHA256'::character varying, 'URL'::character varying])::text[])))
);


--
-- Name: threat_intelligence_iocs_ioc_id_seq; Type: SEQUENCE; Schema: enrichment; Owner: -
--

CREATE SEQUENCE enrichment.threat_intelligence_iocs_ioc_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: threat_intelligence_iocs_ioc_id_seq; Type: SEQUENCE OWNED BY; Schema: enrichment; Owner: -
--

ALTER SEQUENCE enrichment.threat_intelligence_iocs_ioc_id_seq OWNED BY enrichment.threat_intelligence_iocs.ioc_id;


--
-- Name: hourly_overview_rollup; Type: TABLE; Schema: metrics; Owner: -
--

CREATE TABLE metrics.hourly_overview_rollup (
    bucket_hour timestamp with time zone NOT NULL,
    raw_events_count bigint DEFAULT 0,
    normalized_count bigint DEFAULT 0,
    aggregated_count bigint DEFAULT 0,
    suppressed_count bigint DEFAULT 0,
    actionable_count bigint DEFAULT 0,
    correlated_count bigint DEFAULT 0,
    p0_count integer DEFAULT 0,
    p1_count integer DEFAULT 0,
    p2_count integer DEFAULT 0,
    p3_count integer DEFAULT 0,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    p4_count bigint DEFAULT 0
);


--
-- Name: operational_metrics_daily; Type: TABLE; Schema: metrics; Owner: -
--

CREATE TABLE metrics.operational_metrics_daily (
    metric_date date NOT NULL,
    raw_events_count bigint DEFAULT 0,
    wazuh_alerts_count bigint DEFAULT 0,
    suppressed_events_count bigint DEFAULT 0,
    aggregated_alerts_count bigint DEFAULT 0,
    correlated_incidents_count bigint DEFAULT 0,
    analyst_reviewed_count bigint DEFAULT 0,
    true_positives_count bigint DEFAULT 0,
    actionable_incidents_count bigint DEFAULT 0,
    suppression_escapes_count bigint DEFAULT 0,
    avg_mean_time_to_triage_sec double precision DEFAULT 0.0,
    alert_reduction_percentage numeric(5,2) GENERATED ALWAYS AS (
CASE
    WHEN (raw_events_count > 0) THEN round(((((raw_events_count - (aggregated_alerts_count + correlated_incidents_count)))::numeric / (raw_events_count)::numeric) * 100.0), 2)
    ELSE 0.00
END) STORED,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.schema_migrations (
    version character varying(255) NOT NULL,
    applied_at timestamp with time zone DEFAULT now()
);


--
-- Name: calculated_risk_scores; Type: TABLE; Schema: risk_engine; Owner: -
--

CREATE TABLE risk_engine.calculated_risk_scores (
    score_id bigint NOT NULL,
    incident_id character varying(64) NOT NULL,
    total_score integer NOT NULL,
    soc_priority character varying(4) NOT NULL,
    scoring_version character varying(16) DEFAULT 'v1.0'::character varying,
    calculated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT calculated_risk_scores_soc_priority_check CHECK (((soc_priority)::text = ANY ((ARRAY['P0'::character varying, 'P1'::character varying, 'P2'::character varying, 'P3'::character varying, 'P4'::character varying])::text[]))),
    CONSTRAINT calculated_risk_scores_total_score_check CHECK (((total_score >= 0) AND (total_score <= 100)))
);


--
-- Name: calculated_risk_scores_score_id_seq; Type: SEQUENCE; Schema: risk_engine; Owner: -
--

CREATE SEQUENCE risk_engine.calculated_risk_scores_score_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: calculated_risk_scores_score_id_seq; Type: SEQUENCE OWNED BY; Schema: risk_engine; Owner: -
--

ALTER SEQUENCE risk_engine.calculated_risk_scores_score_id_seq OWNED BY risk_engine.calculated_risk_scores.score_id;


--
-- Name: risk_scoring_factors; Type: TABLE; Schema: risk_engine; Owner: -
--

CREATE TABLE risk_engine.risk_scoring_factors (
    factor_id bigint NOT NULL,
    incident_id character varying(64) NOT NULL,
    factor_type character varying(64) NOT NULL,
    weight_added integer NOT NULL,
    justification text,
    evaluated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT risk_scoring_factors_factor_type_check CHECK (((factor_type)::text = ANY ((ARRAY['DETECTION_SEVERITY'::character varying, 'ASSET_CRITICALITY'::character varying, 'IDENTITY_RISK'::character varying, 'THREAT_INTELLIGENCE'::character varying, 'BEHAVIORAL_ANOMALY'::character varying, 'CORRELATION_CHAIN'::character varying, 'KNOWN_GOOD_OFFSET'::character varying, 'CONFIDENCE_DEPTH'::character varying])::text[]))),
    CONSTRAINT risk_scoring_factors_weight_added_check CHECK (((weight_added >= '-100'::integer) AND (weight_added <= 100)))
);


--
-- Name: risk_scoring_factors_factor_id_seq; Type: SEQUENCE; Schema: risk_engine; Owner: -
--

CREATE SEQUENCE risk_engine.risk_scoring_factors_factor_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: risk_scoring_factors_factor_id_seq; Type: SEQUENCE OWNED BY; Schema: risk_engine; Owner: -
--

ALTER SEQUENCE risk_engine.risk_scoring_factors_factor_id_seq OWNED BY risk_engine.risk_scoring_factors.factor_id;


--
-- Name: ground_truth_dataset; Type: TABLE; Schema: soc_ops; Owner: -
--

CREATE TABLE soc_ops.ground_truth_dataset (
    id bigint NOT NULL,
    incident_id character varying(64) NOT NULL,
    triage_id character varying(64) NOT NULL,
    tenant_id character varying(64) DEFAULT 'DEFAULT'::character varying,
    rule_code character varying(64),
    category character varying(64),
    rule_level integer,
    event_count integer,
    max_inline_risk_score integer DEFAULT 0,
    total_risk_score integer DEFAULT 0,
    priority character varying(4),
    target_host character varying(128),
    host_criticality character varying(32) DEFAULT 'STANDARD'::character varying,
    is_internet_exposed boolean DEFAULT false,
    is_privileged_user boolean DEFAULT false,
    is_service_account boolean DEFAULT false,
    threat_intel_match boolean DEFAULT false,
    mitre_tactics jsonb DEFAULT '[]'::jsonb,
    mitre_attack_ids jsonb DEFAULT '[]'::jsonb,
    ioa_summary text,
    log_source text,
    extracted_features jsonb DEFAULT '{}'::jsonb,
    ml_tier1_prediction integer,
    ml_tier1_confidence numeric(5,2),
    local_llm_verdict character varying(32),
    local_llm_confidence numeric(5,2),
    cloud_llm_verdict character varying(32),
    cloud_llm_confidence numeric(5,2),
    voting_score numeric(5,2),
    decision_path character varying(128),
    ground_truth_label integer NOT NULL,
    resolution_outcome character varying(64) NOT NULL,
    analyst_id character varying(128),
    analyst_notes text,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    is_used_in_training boolean DEFAULT false,
    trained_at timestamp with time zone,
    label_source character varying(32) DEFAULT 'HISTORICAL'::character varying,
    CONSTRAINT ground_truth_dataset_ground_truth_label_check CHECK ((ground_truth_label = ANY (ARRAY[0, 1])))
);


--
-- Name: ground_truth_dataset_id_seq; Type: SEQUENCE; Schema: soc_ops; Owner: -
--

CREATE SEQUENCE soc_ops.ground_truth_dataset_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ground_truth_dataset_id_seq; Type: SEQUENCE OWNED BY; Schema: soc_ops; Owner: -
--

ALTER SEQUENCE soc_ops.ground_truth_dataset_id_seq OWNED BY soc_ops.ground_truth_dataset.id;


--
-- Name: incident_investigation_notes; Type: TABLE; Schema: soc_ops; Owner: -
--

CREATE TABLE soc_ops.incident_investigation_notes (
    note_id bigint NOT NULL,
    incident_id character varying(64) NOT NULL,
    analyst_name character varying(128) NOT NULL,
    note_text text NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: incident_investigation_notes_note_id_seq; Type: SEQUENCE; Schema: soc_ops; Owner: -
--

CREATE SEQUENCE soc_ops.incident_investigation_notes_note_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: incident_investigation_notes_note_id_seq; Type: SEQUENCE OWNED BY; Schema: soc_ops; Owner: -
--

ALTER SEQUENCE soc_ops.incident_investigation_notes_note_id_seq OWNED BY soc_ops.incident_investigation_notes.note_id;


--
-- Name: incident_response_actions; Type: TABLE; Schema: soc_ops; Owner: -
--

CREATE TABLE soc_ops.incident_response_actions (
    action_id bigint NOT NULL,
    incident_id character varying(64) NOT NULL,
    action_type character varying(32) NOT NULL,
    target_entity character varying(128) NOT NULL,
    initiated_by character varying(128) NOT NULL,
    execution_status character varying(16) DEFAULT 'PENDING'::character varying,
    execution_output text,
    executed_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT incident_response_actions_action_type_check CHECK (((action_type)::text = ANY ((ARRAY['HOST_ISOLATION'::character varying, 'IP_BLOCK_FIREWALL'::character varying, 'USER_ACCOUNT_DISABLE'::character varying, 'PROCESS_TERMINATION'::character varying, 'ENABLE_AUDIT_MODE'::character varying, 'CUSTOM_SCRIPT'::character varying])::text[]))),
    CONSTRAINT incident_response_actions_execution_status_check CHECK (((execution_status)::text = ANY ((ARRAY['PENDING'::character varying, 'SUCCESS'::character varying, 'FAILED'::character varying, 'ROLLED_BACK'::character varying])::text[])))
);


--
-- Name: incident_response_actions_action_id_seq; Type: SEQUENCE; Schema: soc_ops; Owner: -
--

CREATE SEQUENCE soc_ops.incident_response_actions_action_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: incident_response_actions_action_id_seq; Type: SEQUENCE OWNED BY; Schema: soc_ops; Owner: -
--

ALTER SEQUENCE soc_ops.incident_response_actions_action_id_seq OWNED BY soc_ops.incident_response_actions.action_id;


--
-- Name: soc_triage_queue; Type: TABLE; Schema: soc_ops; Owner: -
--

CREATE TABLE soc_ops.soc_triage_queue (
    triage_id character varying(64) NOT NULL,
    incident_id character varying(64) NOT NULL,
    assigned_analyst character varying(128),
    priority character varying(4) NOT NULL,
    triage_status character varying(32) DEFAULT 'NEW'::character varying,
    resolution_outcome character varying(32),
    false_positive_reason text,
    mean_time_to_triage_seconds integer,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    resolved_at timestamp with time zone,
    cooldown_until timestamp with time zone,
    threat_intel_status character varying(32) DEFAULT 'AVAILABLE'::character varying,
    is_verified_true_positive boolean DEFAULT false,
    ground_truth_verdict character varying(30) DEFAULT NULL::character varying,
    analyst_notes text,
    manager_review_notes text,
    manager_reviewer character varying(100) DEFAULT NULL::character varying,
    manager_reviewed_at timestamp with time zone,
    reject_count integer DEFAULT 0,
    parent_triage_id character varying(64) DEFAULT NULL::character varying,
    priority_established_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_triage_status_user_flow_100pct CHECK (((triage_status)::text = ANY ((ARRAY['OPEN'::character varying, 'INVESTIGATE'::character varying, 'CLOSE'::character varying, 'WAITING'::character varying, 'APPROVE'::character varying, 'REJECT'::character varying, 'FP Reject'::character varying])::text[]))),
    CONSTRAINT soc_triage_queue_priority_check CHECK (((priority)::text = ANY ((ARRAY['P0'::character varying, 'P1'::character varying, 'P2'::character varying, 'P3'::character varying, 'P4'::character varying])::text[]))),
    CONSTRAINT soc_triage_queue_resolution_outcome_check CHECK (((resolution_outcome)::text = ANY ((ARRAY['TRUE_POSITIVE_ACTIONABLE'::character varying, 'TRUE_POSITIVE_NO_ACTION'::character varying, 'FALSE_POSITIVE_TUNING_REQ'::character varying, 'OPERATIONAL_NOISE'::character varying, 'BENIGN_AUTHORIZED'::character varying, 'REJECTED'::character varying, 'FALSE_POSITIVE_REJECTED'::character varying])::text[])))
);


--
-- Name: soc_users; Type: TABLE; Schema: soc_ops; Owner: -
--

CREATE TABLE soc_ops.soc_users (
    user_id integer NOT NULL,
    username character varying(64) NOT NULL,
    full_name character varying(128) NOT NULL,
    email character varying(128) NOT NULL,
    role character varying(32) NOT NULL,
    status character varying(20) DEFAULT 'ACTIVE'::character varying NOT NULL,
    department character varying(64) DEFAULT 'Cyber Defense Center'::character varying,
    avatar_letter character varying(2) DEFAULT 'U'::character varying,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    last_login timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    password_hash character varying(255),
    CONSTRAINT chk_user_roles CHECK (((role)::text = ANY ((ARRAY['SOC_ANALYST'::character varying, 'SOC_DEVELOPER'::character varying, 'SOC_LEAD'::character varying, 'SOC_MANAGER'::character varying, 'ADMIN'::character varying])::text[])))
);


--
-- Name: soc_users_user_id_seq; Type: SEQUENCE; Schema: soc_ops; Owner: -
--

CREATE SEQUENCE soc_ops.soc_users_user_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: soc_users_user_id_seq; Type: SEQUENCE OWNED BY; Schema: soc_ops; Owner: -
--

ALTER SEQUENCE soc_ops.soc_users_user_id_seq OWNED BY soc_ops.soc_users.user_id;


--
-- Name: v_actionable_triage_queue; Type: VIEW; Schema: soc_ops; Owner: -
--

CREATE VIEW soc_ops.v_actionable_triage_queue AS
 SELECT t.triage_id,
    t.priority,
    i.title AS judul_insiden,
    i.target_host,
    i.attacker_source_ip,
    t.triage_status,
    t.assigned_analyst,
    COALESCE(t.priority_established_at, t.created_at) AS waktu_muncul,
        CASE
            WHEN ((t.priority)::text = 'P0'::text) THEN (COALESCE(t.priority_established_at, t.created_at) + '00:15:00'::interval)
            WHEN ((t.priority)::text = 'P1'::text) THEN (COALESCE(t.priority_established_at, t.created_at) + '01:00:00'::interval)
            WHEN ((t.priority)::text = 'P2'::text) THEN (COALESCE(t.priority_established_at, t.created_at) + '04:00:00'::interval)
            WHEN ((t.priority)::text = 'P3'::text) THEN (COALESCE(t.priority_established_at, t.created_at) + '24:00:00'::interval)
            ELSE (COALESCE(t.priority_established_at, t.created_at) + '7 days'::interval)
        END AS batas_deadline_sla,
        CASE
            WHEN ((t.priority)::text = 'P0'::text) THEN 'DARURAT TERTINGGI (< 15m)'::text
            WHEN ((t.priority)::text = 'P1'::text) THEN 'MENDESAK (< 60m)'::text
            WHEN ((t.priority)::text = 'P2'::text) THEN 'REVIEW SHIFT (< 4 Jam)'::text
            WHEN ((t.priority)::text = 'P3'::text) THEN 'REVIEW HARIAN (< 24 Jam)'::text
            ELSE 'REVIEW MINGGUAN (< 7 Hari)'::text
        END AS target_sla,
        CASE
            WHEN (
            CASE
                WHEN ((t.priority)::text = 'P0'::text) THEN (COALESCE(t.priority_established_at, t.created_at) + '00:15:00'::interval)
                WHEN ((t.priority)::text = 'P1'::text) THEN (COALESCE(t.priority_established_at, t.created_at) + '01:00:00'::interval)
                WHEN ((t.priority)::text = 'P2'::text) THEN (COALESCE(t.priority_established_at, t.created_at) + '04:00:00'::interval)
                WHEN ((t.priority)::text = 'P3'::text) THEN (COALESCE(t.priority_established_at, t.created_at) + '24:00:00'::interval)
                ELSE (COALESCE(t.priority_established_at, t.created_at) + '7 days'::interval)
            END < CURRENT_TIMESTAMP) THEN 'SLA BREACH (LEWAT BATAS)'::text
            ELSE 'AKTIF DALAM SLA'::text
        END AS status_kepatuhan_sla
   FROM (soc_ops.soc_triage_queue t
     JOIN correlation.correlated_incidents i ON (((t.incident_id)::text = (i.incident_id)::text)))
  WHERE ((t.triage_status)::text = ANY ((ARRAY['OPEN'::character varying, 'INVESTIGATE'::character varying, 'WAITING'::character varying, 'NEW'::character varying, 'ASSIGNED'::character varying, 'INVESTIGATING'::character varying, 'HOLDING_P4'::character varying])::text[]))
  ORDER BY
        CASE
            WHEN ((t.priority)::text = 'P0'::text) THEN (COALESCE(t.priority_established_at, t.created_at) + '00:15:00'::interval)
            WHEN ((t.priority)::text = 'P1'::text) THEN (COALESCE(t.priority_established_at, t.created_at) + '01:00:00'::interval)
            WHEN ((t.priority)::text = 'P2'::text) THEN (COALESCE(t.priority_established_at, t.created_at) + '04:00:00'::interval)
            WHEN ((t.priority)::text = 'P3'::text) THEN (COALESCE(t.priority_established_at, t.created_at) + '24:00:00'::interval)
            ELSE (COALESCE(t.priority_established_at, t.created_at) + '7 days'::interval)
        END,
        CASE t.priority
            WHEN 'P0'::text THEN 1
            WHEN 'P1'::text THEN 2
            WHEN 'P2'::text THEN 3
            WHEN 'P3'::text THEN 4
            ELSE 5
        END, COALESCE(t.priority_established_at, t.created_at);


--
-- Name: v_ai_model_confusion_matrix; Type: VIEW; Schema: soc_ops; Owner: -
--

CREATE VIEW soc_ops.v_ai_model_confusion_matrix AS
 SELECT 'Local LLM'::text AS model_tier,
    count(*) AS total_samples,
    sum(
        CASE
            WHEN (((ground_truth_dataset.local_llm_verdict)::text = 'TRUE_POSITIVE'::text) AND (ground_truth_dataset.ground_truth_label = 1)) THEN 1
            ELSE 0
        END) AS true_positives,
    sum(
        CASE
            WHEN (((ground_truth_dataset.local_llm_verdict)::text = 'FALSE_POSITIVE'::text) AND (ground_truth_dataset.ground_truth_label = 0)) THEN 1
            ELSE 0
        END) AS true_negatives,
    sum(
        CASE
            WHEN (((ground_truth_dataset.local_llm_verdict)::text = 'TRUE_POSITIVE'::text) AND (ground_truth_dataset.ground_truth_label = 0)) THEN 1
            ELSE 0
        END) AS false_positives,
    sum(
        CASE
            WHEN (((ground_truth_dataset.local_llm_verdict)::text = 'FALSE_POSITIVE'::text) AND (ground_truth_dataset.ground_truth_label = 1)) THEN 1
            ELSE 0
        END) AS false_negatives,
    round((((sum(
        CASE
            WHEN ((((ground_truth_dataset.local_llm_verdict)::text = 'TRUE_POSITIVE'::text) AND (ground_truth_dataset.ground_truth_label = 1)) OR (((ground_truth_dataset.local_llm_verdict)::text = 'FALSE_POSITIVE'::text) AND (ground_truth_dataset.ground_truth_label = 0))) THEN 1
            ELSE 0
        END))::numeric / (NULLIF(count(*), 0))::numeric) * (100)::numeric), 2) AS accuracy_pct
   FROM soc_ops.ground_truth_dataset
  WHERE (ground_truth_dataset.local_llm_verdict IS NOT NULL)
UNION ALL
 SELECT 'Cloud LLM'::text AS model_tier,
    count(*) AS total_samples,
    sum(
        CASE
            WHEN (((ground_truth_dataset.cloud_llm_verdict)::text = 'TRUE_POSITIVE'::text) AND (ground_truth_dataset.ground_truth_label = 1)) THEN 1
            ELSE 0
        END) AS true_positives,
    sum(
        CASE
            WHEN (((ground_truth_dataset.cloud_llm_verdict)::text = 'FALSE_POSITIVE'::text) AND (ground_truth_dataset.ground_truth_label = 0)) THEN 1
            ELSE 0
        END) AS true_negatives,
    sum(
        CASE
            WHEN (((ground_truth_dataset.cloud_llm_verdict)::text = 'TRUE_POSITIVE'::text) AND (ground_truth_dataset.ground_truth_label = 0)) THEN 1
            ELSE 0
        END) AS false_positives,
    sum(
        CASE
            WHEN (((ground_truth_dataset.cloud_llm_verdict)::text = 'FALSE_POSITIVE'::text) AND (ground_truth_dataset.ground_truth_label = 1)) THEN 1
            ELSE 0
        END) AS false_negatives,
    round((((sum(
        CASE
            WHEN ((((ground_truth_dataset.cloud_llm_verdict)::text = 'TRUE_POSITIVE'::text) AND (ground_truth_dataset.ground_truth_label = 1)) OR (((ground_truth_dataset.cloud_llm_verdict)::text = 'FALSE_POSITIVE'::text) AND (ground_truth_dataset.ground_truth_label = 0))) THEN 1
            ELSE 0
        END))::numeric / (NULLIF(count(*), 0))::numeric) * (100)::numeric), 2) AS accuracy_pct
   FROM soc_ops.ground_truth_dataset
  WHERE (ground_truth_dataset.cloud_llm_verdict IS NOT NULL);


--
-- Name: aggregate_evidence_mapping; Type: TABLE; Schema: suppression; Owner: -
--

CREATE TABLE suppression.aggregate_evidence_mapping (
    aggregation_id character varying(64) NOT NULL,
    raw_event_id character varying(64) NOT NULL,
    event_timestamp timestamp with time zone NOT NULL,
    mapped_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: aggregated_alerts; Type: TABLE; Schema: suppression; Owner: -
--

CREATE TABLE suppression.aggregated_alerts (
    aggregation_id character varying(64) NOT NULL,
    rule_id integer NOT NULL,
    deduplication_key character varying(128) NOT NULL,
    tenant_id character varying(64) DEFAULT 'DEFAULT'::character varying,
    agent_id character varying(32) NOT NULL,
    source_ip character varying(45),
    destination_ip character varying(45),
    username character varying(128),
    event_count integer DEFAULT 1 NOT NULL,
    window_start timestamp with time zone NOT NULL,
    window_end timestamp with time zone NOT NULL,
    status character varying(32) DEFAULT 'OPEN'::character varying,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    category character varying(32) DEFAULT 'SYSTEM_HEALTH'::character varying,
    actor character varying(128),
    target character varying(128),
    window_duration_seconds integer DEFAULT 900,
    rule_description text,
    ioa_summary text,
    is_suppressed boolean DEFAULT false,
    suppression_rule_id character varying(32),
    suppression_reason text,
    max_inline_risk_score integer DEFAULT 0 NOT NULL,
    ocsf_severity_id integer,
    tlp_level character varying(12) DEFAULT 'TLP:AMBER'::character varying,
    mitre_technique_id character varying(32),
    os_platform character varying(16) DEFAULT 'unknown'::character varying NOT NULL,
    mitre_tactics jsonb DEFAULT '[]'::jsonb NOT NULL,
    classification_groups jsonb DEFAULT '[]'::jsonb NOT NULL,
    log_source text,
    distinct_ioas jsonb DEFAULT '[]'::jsonb NOT NULL,
    distinct_iocs jsonb DEFAULT '[]'::jsonb NOT NULL,
    dominant_http_status integer,
    is_scanner_ua boolean DEFAULT false,
    CONSTRAINT aggregated_alerts_event_count_check CHECK ((event_count >= 1)),
    CONSTRAINT aggregated_alerts_status_check CHECK (((status)::text = ANY ((ARRAY['CLOSED'::character varying, 'ACTIONABLE'::character varying, 'SUPPRESSED'::character varying, 'PENDING_REVIEW'::character varying])::text[]))),
    CONSTRAINT chk_agg_os_platform CHECK (((os_platform)::text = ANY ((ARRAY['linux'::character varying, 'windows'::character varying, 'macos'::character varying, 'unknown'::character varying])::text[]))),
    CONSTRAINT chk_ocsf_severity CHECK (((ocsf_severity_id IS NULL) OR ((ocsf_severity_id >= 1) AND (ocsf_severity_id <= 6)))),
    CONSTRAINT chk_risk_score_range CHECK (((max_inline_risk_score >= 0) AND (max_inline_risk_score <= 100))),
    CONSTRAINT chk_window_time CHECK ((window_end >= window_start))
);


--
-- Name: cumulative_alerts; Type: TABLE; Schema: suppression; Owner: -
--

CREATE TABLE suppression.cumulative_alerts (
    cumulative_id character varying(64) NOT NULL,
    deduplication_key character varying(128) NOT NULL,
    category character varying(32) DEFAULT 'SYSTEM_HEALTH'::character varying,
    rule_id integer NOT NULL,
    rule_description text,
    actor character varying(128),
    target character varying(128),
    agent_id character varying(32) NOT NULL,
    tenant_id character varying(64) DEFAULT 'DEFAULT'::character varying,
    total_event_count bigint DEFAULT 1 NOT NULL,
    total_burst_windows integer DEFAULT 1 NOT NULL,
    first_seen_at timestamp with time zone NOT NULL,
    last_seen_at timestamp with time zone NOT NULL,
    status character varying(32) DEFAULT 'ACTIVE'::character varying,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    ioa_summary text,
    peak_risk_score integer DEFAULT 0 NOT NULL,
    tlp_level character varying(12) DEFAULT 'TLP:AMBER'::character varying,
    sighting_count integer DEFAULT 0 NOT NULL,
    source_feed character varying(64) DEFAULT 'wazuh-pipeline'::character varying,
    stix_indicator_id character varying(128),
    mitre_technique_id character varying(32),
    os_platform character varying(16) DEFAULT 'unknown'::character varying NOT NULL,
    CONSTRAINT chk_cum_os_platform CHECK (((os_platform)::text = ANY ((ARRAY['linux'::character varying, 'windows'::character varying, 'macos'::character varying, 'unknown'::character varying])::text[]))),
    CONSTRAINT chk_cum_risk_score CHECK (((peak_risk_score >= 0) AND (peak_risk_score <= 100))),
    CONSTRAINT cumulative_alerts_status_check CHECK (((status)::text = ANY ((ARRAY['ACTIVE'::character varying, 'DORMANT'::character varying])::text[])))
);


--
-- Name: maintenance_windows; Type: TABLE; Schema: suppression; Owner: -
--

CREATE TABLE suppression.maintenance_windows (
    window_id character varying(64) NOT NULL,
    title character varying(128) NOT NULL,
    target_hostname character varying(128) NOT NULL,
    target_ip character varying(45),
    ticket_id character varying(64) NOT NULL,
    approved_by character varying(128) NOT NULL,
    window_start timestamp with time zone NOT NULL,
    window_end timestamp with time zone NOT NULL,
    status character varying(16) DEFAULT 'SCHEDULED'::character varying,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_maint_window_time CHECK ((window_end > window_start)),
    CONSTRAINT maintenance_windows_status_check CHECK (((status)::text = ANY ((ARRAY['SCHEDULED'::character varying, 'ACTIVE'::character varying, 'COMPLETED'::character varying, 'CANCELLED'::character varying])::text[])))
);


--
-- Name: shared_value_lists; Type: TABLE; Schema: suppression; Owner: -
--

CREATE TABLE suppression.shared_value_lists (
    list_id character varying(32) NOT NULL,
    list_name character varying(128) NOT NULL,
    list_type character varying(32) NOT NULL,
    "values" jsonb DEFAULT '[]'::jsonb NOT NULL,
    description text,
    referenced_by character varying(32)[] DEFAULT '{}'::character varying[],
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT shared_value_lists_list_type_check CHECK (((list_type)::text = ANY ((ARRAY['IP'::character varying, 'HOSTNAME'::character varying, 'USERNAME'::character varying, 'CIDR'::character varying, 'AGENT_GROUP'::character varying, 'RULE_SID'::character varying])::text[])))
);


--
-- Name: suppression_audit_log; Type: TABLE; Schema: suppression; Owner: -
--

CREATE TABLE suppression.suppression_audit_log (
    log_id bigint NOT NULL,
    suppression_id character varying(32) NOT NULL,
    action character varying(32) NOT NULL,
    performed_by character varying(128) NOT NULL,
    notes text,
    recorded_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT suppression_audit_log_action_check CHECK (((action)::text = ANY ((ARRAY['CREATED'::character varying, 'APPROVED'::character varying, 'REJECTED'::character varying, 'REVOKED'::character varying, 'MODIFIED'::character varying, 'REVIEWED'::character varying, 'EXTENDED'::character varying, 'EXPIRED'::character varying, 'DEPLOYED_TO_WAZUH'::character varying])::text[])))
);


--
-- Name: suppression_audit_log_log_id_seq; Type: SEQUENCE; Schema: suppression; Owner: -
--

CREATE SEQUENCE suppression.suppression_audit_log_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: suppression_audit_log_log_id_seq; Type: SEQUENCE OWNED BY; Schema: suppression; Owner: -
--

ALTER SEQUENCE suppression.suppression_audit_log_log_id_seq OWNED BY suppression.suppression_audit_log.log_id;


--
-- Name: suppression_groups; Type: TABLE; Schema: suppression; Owner: -
--

CREATE TABLE suppression.suppression_groups (
    group_id character varying(32) NOT NULL,
    group_name character varying(256) NOT NULL,
    group_type character varying(32) NOT NULL,
    tenant_id character varying(64) DEFAULT 'ALL'::character varying,
    description text,
    mitre_tactics text[],
    mitre_techniques text[],
    shared_scope jsonb DEFAULT '{}'::jsonb,
    auto_merge boolean DEFAULT false,
    priority character varying(4) DEFAULT 'P2'::character varying,
    owner character varying(128) NOT NULL,
    status character varying(16) DEFAULT 'ACTIVE'::character varying,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT suppression_groups_group_type_check CHECK (((group_type)::text = ANY ((ARRAY['TENANT'::character varying, 'USE_CASE'::character varying, 'ASSET_GROUP'::character varying, 'ACTOR'::character varying, 'MITRE_TACTIC'::character varying, 'MAINTENANCE'::character varying])::text[]))),
    CONSTRAINT suppression_groups_status_check CHECK (((status)::text = ANY ((ARRAY['ACTIVE'::character varying, 'DRAFT'::character varying, 'ARCHIVED'::character varying, 'UNDER_REVIEW'::character varying])::text[])))
);


--
-- Name: suppression_rules; Type: TABLE; Schema: suppression; Owner: -
--

CREATE TABLE suppression.suppression_rules (
    suppression_id character varying(32) NOT NULL,
    rule_name character varying(128) NOT NULL,
    suppression_class character varying(20) NOT NULL,
    target_rule_ids integer[] NOT NULL,
    author character varying(128) NOT NULL,
    approver character varying(128) NOT NULL,
    ticket_id character varying(64) NOT NULL,
    business_reason text NOT NULL,
    scope_definition jsonb NOT NULL,
    status character varying(32) DEFAULT 'ACTIVE'::character varying,
    created_date date DEFAULT CURRENT_DATE NOT NULL,
    expires_date date NOT NULL,
    review_cycle character varying(16) DEFAULT 'MONTHLY'::character varying,
    drift_baseline_count integer DEFAULT 0,
    current_drift_sigma numeric(8,2) DEFAULT 0.00,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    group_id character varying(32),
    enforcement_mode character varying(32) DEFAULT 'PIPELINE_MUTE'::character varying,
    CONSTRAINT chk_separation_of_duties CHECK (((author)::text <> (approver)::text)),
    CONSTRAINT chk_suppression_dates CHECK ((expires_date >= created_date)),
    CONSTRAINT suppression_rules_review_cycle_check CHECK (((review_cycle)::text = ANY ((ARRAY['WEEKLY'::character varying, 'MONTHLY'::character varying, 'QUARTERLY'::character varying])::text[]))),
    CONSTRAINT suppression_rules_status_check CHECK (((status)::text = ANY ((ARRAY['WAITING'::character varying, 'ACTIVE'::character varying, 'EXPIRED'::character varying, 'REVOKED'::character varying, 'PENDING_REVIEW'::character varying, 'PENDING_WAZUH_DEPLOY'::character varying, 'TUNED_IN_WAZUH_XML'::character varying, 'APPROVE'::character varying, 'DEPLOY'::character varying])::text[]))),
    CONSTRAINT suppression_rules_suppression_class_check CHECK (((suppression_class)::text = ANY ((ARRAY['S1_KNOWN_GOOD'::character varying, 'S2_FALSE_POSITIVE'::character varying, 'S3_MAINTENANCE'::character varying, 'S4_EXCEPTION'::character varying, 'S5_CONDITIONAL'::character varying])::text[])))
);


--
-- Name: v_actionable_aggregates; Type: VIEW; Schema: suppression; Owner: -
--

CREATE VIEW suppression.v_actionable_aggregates AS
 SELECT aa.aggregation_id,
    aa.rule_id,
    aa.deduplication_key,
    aa.tenant_id,
    aa.agent_id,
    aa.source_ip,
    aa.destination_ip,
    aa.username,
    aa.category,
    aa.actor,
    aa.target,
    aa.event_count,
    aa.window_start,
    aa.window_end,
    aa.window_duration_seconds,
    aa.max_inline_risk_score,
    aa.ocsf_severity_id,
    aa.log_source,
    aa.ioa_summary,
    aa.distinct_ioas,
    aa.distinct_iocs,
    aa.rule_description,
    aa.os_platform,
    aa.tlp_level,
    aa.mitre_technique_id,
    aa.mitre_tactics,
    aa.classification_groups,
    aa.created_at,
    ca.total_event_count AS cumulative_total_events,
    ca.total_burst_windows AS cumulative_burst_windows,
    ca.first_seen_at AS entity_first_seen,
    ca.last_seen_at AS entity_last_seen,
    ca.peak_risk_score AS entity_peak_risk,
    ca.status AS entity_status
   FROM (suppression.aggregated_alerts aa
     LEFT JOIN suppression.cumulative_alerts ca ON (((aa.deduplication_key)::text = (ca.deduplication_key)::text)))
  WHERE ((aa.status)::text = 'ACTIONABLE'::text);


--
-- Name: events; Type: TABLE; Schema: telemetry; Owner: -
--

CREATE TABLE telemetry.events (
    event_id character varying(64) NOT NULL,
    event_timestamp timestamp with time zone NOT NULL,
    agent_id character varying(32) DEFAULT '000'::character varying NOT NULL,
    tenant_id character varying(64) DEFAULT 'DEFAULT'::character varying NOT NULL,
    agent_name character varying(128),
    rule_id integer NOT NULL,
    rule_level integer DEFAULT 0 NOT NULL,
    rule_description text,
    source_ip inet,
    destination_ip inet,
    source_port integer,
    destination_port integer,
    protocol character varying(16),
    username character varying(128),
    classification_groups text[],
    mitre_attack_ids text[],
    mitre_tactics text[],
    mitre_techniques text[],
    compliance_frameworks jsonb DEFAULT '{}'::jsonb,
    asset_criticality_tier character varying(16) DEFAULT 'STANDARD'::character varying,
    is_asset_internet_exposed boolean DEFAULT false,
    is_privileged_user boolean DEFAULT false,
    is_service_account boolean DEFAULT false,
    threat_intel_match boolean DEFAULT false,
    threat_intel_confidence integer DEFAULT 0,
    raw_payload jsonb NOT NULL,
    ingested_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
)
PARTITION BY RANGE (event_timestamp);


--
-- Name: events_2026_07; Type: TABLE; Schema: telemetry; Owner: -
--

CREATE TABLE telemetry.events_2026_07 (
    event_id character varying(64) CONSTRAINT events_event_id_not_null NOT NULL,
    event_timestamp timestamp with time zone CONSTRAINT events_event_timestamp_not_null NOT NULL,
    agent_id character varying(32) DEFAULT '000'::character varying CONSTRAINT events_agent_id_not_null NOT NULL,
    tenant_id character varying(64) DEFAULT 'DEFAULT'::character varying CONSTRAINT events_tenant_id_not_null NOT NULL,
    agent_name character varying(128),
    rule_id integer CONSTRAINT events_rule_id_not_null NOT NULL,
    rule_level integer DEFAULT 0 CONSTRAINT events_rule_level_not_null NOT NULL,
    rule_description text,
    source_ip inet,
    destination_ip inet,
    source_port integer,
    destination_port integer,
    protocol character varying(16),
    username character varying(128),
    classification_groups text[],
    mitre_attack_ids text[],
    mitre_tactics text[],
    mitre_techniques text[],
    compliance_frameworks jsonb DEFAULT '{}'::jsonb,
    asset_criticality_tier character varying(16) DEFAULT 'STANDARD'::character varying,
    is_asset_internet_exposed boolean DEFAULT false,
    is_privileged_user boolean DEFAULT false,
    is_service_account boolean DEFAULT false,
    threat_intel_match boolean DEFAULT false,
    threat_intel_confidence integer DEFAULT 0,
    raw_payload jsonb CONSTRAINT events_raw_payload_not_null NOT NULL,
    ingested_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: events_2026_08; Type: TABLE; Schema: telemetry; Owner: -
--

CREATE TABLE telemetry.events_2026_08 (
    event_id character varying(64) CONSTRAINT events_event_id_not_null NOT NULL,
    event_timestamp timestamp with time zone CONSTRAINT events_event_timestamp_not_null NOT NULL,
    agent_id character varying(32) DEFAULT '000'::character varying CONSTRAINT events_agent_id_not_null NOT NULL,
    tenant_id character varying(64) DEFAULT 'DEFAULT'::character varying CONSTRAINT events_tenant_id_not_null NOT NULL,
    agent_name character varying(128),
    rule_id integer CONSTRAINT events_rule_id_not_null NOT NULL,
    rule_level integer DEFAULT 0 CONSTRAINT events_rule_level_not_null NOT NULL,
    rule_description text,
    source_ip inet,
    destination_ip inet,
    source_port integer,
    destination_port integer,
    protocol character varying(16),
    username character varying(128),
    classification_groups text[],
    mitre_attack_ids text[],
    mitre_tactics text[],
    mitre_techniques text[],
    compliance_frameworks jsonb DEFAULT '{}'::jsonb,
    asset_criticality_tier character varying(16) DEFAULT 'STANDARD'::character varying,
    is_asset_internet_exposed boolean DEFAULT false,
    is_privileged_user boolean DEFAULT false,
    is_service_account boolean DEFAULT false,
    threat_intel_match boolean DEFAULT false,
    threat_intel_confidence integer DEFAULT 0,
    raw_payload jsonb CONSTRAINT events_raw_payload_not_null NOT NULL,
    ingested_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: events_2026_09; Type: TABLE; Schema: telemetry; Owner: -
--

CREATE TABLE telemetry.events_2026_09 (
    event_id character varying(64) CONSTRAINT events_event_id_not_null NOT NULL,
    event_timestamp timestamp with time zone CONSTRAINT events_event_timestamp_not_null NOT NULL,
    agent_id character varying(32) DEFAULT '000'::character varying CONSTRAINT events_agent_id_not_null NOT NULL,
    tenant_id character varying(64) DEFAULT 'DEFAULT'::character varying CONSTRAINT events_tenant_id_not_null NOT NULL,
    agent_name character varying(128),
    rule_id integer CONSTRAINT events_rule_id_not_null NOT NULL,
    rule_level integer DEFAULT 0 CONSTRAINT events_rule_level_not_null NOT NULL,
    rule_description text,
    source_ip inet,
    destination_ip inet,
    source_port integer,
    destination_port integer,
    protocol character varying(16),
    username character varying(128),
    classification_groups text[],
    mitre_attack_ids text[],
    mitre_tactics text[],
    mitre_techniques text[],
    compliance_frameworks jsonb DEFAULT '{}'::jsonb,
    asset_criticality_tier character varying(16) DEFAULT 'STANDARD'::character varying,
    is_asset_internet_exposed boolean DEFAULT false,
    is_privileged_user boolean DEFAULT false,
    is_service_account boolean DEFAULT false,
    threat_intel_match boolean DEFAULT false,
    threat_intel_confidence integer DEFAULT 0,
    raw_payload jsonb CONSTRAINT events_raw_payload_not_null NOT NULL,
    ingested_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: events_2026_10; Type: TABLE; Schema: telemetry; Owner: -
--

CREATE TABLE telemetry.events_2026_10 (
    event_id character varying(64) CONSTRAINT events_event_id_not_null NOT NULL,
    event_timestamp timestamp with time zone CONSTRAINT events_event_timestamp_not_null NOT NULL,
    agent_id character varying(32) DEFAULT '000'::character varying CONSTRAINT events_agent_id_not_null NOT NULL,
    tenant_id character varying(64) DEFAULT 'DEFAULT'::character varying CONSTRAINT events_tenant_id_not_null NOT NULL,
    agent_name character varying(128),
    rule_id integer CONSTRAINT events_rule_id_not_null NOT NULL,
    rule_level integer DEFAULT 0 CONSTRAINT events_rule_level_not_null NOT NULL,
    rule_description text,
    source_ip inet,
    destination_ip inet,
    source_port integer,
    destination_port integer,
    protocol character varying(16),
    username character varying(128),
    classification_groups text[],
    mitre_attack_ids text[],
    mitre_tactics text[],
    mitre_techniques text[],
    compliance_frameworks jsonb DEFAULT '{}'::jsonb,
    asset_criticality_tier character varying(16) DEFAULT 'STANDARD'::character varying,
    is_asset_internet_exposed boolean DEFAULT false,
    is_privileged_user boolean DEFAULT false,
    is_service_account boolean DEFAULT false,
    threat_intel_match boolean DEFAULT false,
    threat_intel_confidence integer DEFAULT 0,
    raw_payload jsonb CONSTRAINT events_raw_payload_not_null NOT NULL,
    ingested_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: events_2026_11; Type: TABLE; Schema: telemetry; Owner: -
--

CREATE TABLE telemetry.events_2026_11 (
    event_id character varying(64) CONSTRAINT events_event_id_not_null NOT NULL,
    event_timestamp timestamp with time zone CONSTRAINT events_event_timestamp_not_null NOT NULL,
    agent_id character varying(32) DEFAULT '000'::character varying CONSTRAINT events_agent_id_not_null NOT NULL,
    tenant_id character varying(64) DEFAULT 'DEFAULT'::character varying CONSTRAINT events_tenant_id_not_null NOT NULL,
    agent_name character varying(128),
    rule_id integer CONSTRAINT events_rule_id_not_null NOT NULL,
    rule_level integer DEFAULT 0 CONSTRAINT events_rule_level_not_null NOT NULL,
    rule_description text,
    source_ip inet,
    destination_ip inet,
    source_port integer,
    destination_port integer,
    protocol character varying(16),
    username character varying(128),
    classification_groups text[],
    mitre_attack_ids text[],
    mitre_tactics text[],
    mitre_techniques text[],
    compliance_frameworks jsonb DEFAULT '{}'::jsonb,
    asset_criticality_tier character varying(16) DEFAULT 'STANDARD'::character varying,
    is_asset_internet_exposed boolean DEFAULT false,
    is_privileged_user boolean DEFAULT false,
    is_service_account boolean DEFAULT false,
    threat_intel_match boolean DEFAULT false,
    threat_intel_confidence integer DEFAULT 0,
    raw_payload jsonb CONSTRAINT events_raw_payload_not_null NOT NULL,
    ingested_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: events_2026_12; Type: TABLE; Schema: telemetry; Owner: -
--

CREATE TABLE telemetry.events_2026_12 (
    event_id character varying(64) CONSTRAINT events_event_id_not_null NOT NULL,
    event_timestamp timestamp with time zone CONSTRAINT events_event_timestamp_not_null NOT NULL,
    agent_id character varying(32) DEFAULT '000'::character varying CONSTRAINT events_agent_id_not_null NOT NULL,
    tenant_id character varying(64) DEFAULT 'DEFAULT'::character varying CONSTRAINT events_tenant_id_not_null NOT NULL,
    agent_name character varying(128),
    rule_id integer CONSTRAINT events_rule_id_not_null NOT NULL,
    rule_level integer DEFAULT 0 CONSTRAINT events_rule_level_not_null NOT NULL,
    rule_description text,
    source_ip inet,
    destination_ip inet,
    source_port integer,
    destination_port integer,
    protocol character varying(16),
    username character varying(128),
    classification_groups text[],
    mitre_attack_ids text[],
    mitre_tactics text[],
    mitre_techniques text[],
    compliance_frameworks jsonb DEFAULT '{}'::jsonb,
    asset_criticality_tier character varying(16) DEFAULT 'STANDARD'::character varying,
    is_asset_internet_exposed boolean DEFAULT false,
    is_privileged_user boolean DEFAULT false,
    is_service_account boolean DEFAULT false,
    threat_intel_match boolean DEFAULT false,
    threat_intel_confidence integer DEFAULT 0,
    raw_payload jsonb CONSTRAINT events_raw_payload_not_null NOT NULL,
    ingested_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: events_2027_01; Type: TABLE; Schema: telemetry; Owner: -
--

CREATE TABLE telemetry.events_2027_01 (
    event_id character varying(64) CONSTRAINT events_event_id_not_null NOT NULL,
    event_timestamp timestamp with time zone CONSTRAINT events_event_timestamp_not_null NOT NULL,
    agent_id character varying(32) DEFAULT '000'::character varying CONSTRAINT events_agent_id_not_null NOT NULL,
    tenant_id character varying(64) DEFAULT 'DEFAULT'::character varying CONSTRAINT events_tenant_id_not_null NOT NULL,
    agent_name character varying(128),
    rule_id integer CONSTRAINT events_rule_id_not_null NOT NULL,
    rule_level integer DEFAULT 0 CONSTRAINT events_rule_level_not_null NOT NULL,
    rule_description text,
    source_ip inet,
    destination_ip inet,
    source_port integer,
    destination_port integer,
    protocol character varying(16),
    username character varying(128),
    classification_groups text[],
    mitre_attack_ids text[],
    mitre_tactics text[],
    mitre_techniques text[],
    compliance_frameworks jsonb DEFAULT '{}'::jsonb,
    asset_criticality_tier character varying(16) DEFAULT 'STANDARD'::character varying,
    is_asset_internet_exposed boolean DEFAULT false,
    is_privileged_user boolean DEFAULT false,
    is_service_account boolean DEFAULT false,
    threat_intel_match boolean DEFAULT false,
    threat_intel_confidence integer DEFAULT 0,
    raw_payload jsonb CONSTRAINT events_raw_payload_not_null NOT NULL,
    ingested_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: events_default; Type: TABLE; Schema: telemetry; Owner: -
--

CREATE TABLE telemetry.events_default (
    event_id character varying(64) CONSTRAINT events_event_id_not_null NOT NULL,
    event_timestamp timestamp with time zone CONSTRAINT events_event_timestamp_not_null NOT NULL,
    agent_id character varying(32) DEFAULT '000'::character varying CONSTRAINT events_agent_id_not_null NOT NULL,
    tenant_id character varying(64) DEFAULT 'DEFAULT'::character varying CONSTRAINT events_tenant_id_not_null NOT NULL,
    agent_name character varying(128),
    rule_id integer CONSTRAINT events_rule_id_not_null NOT NULL,
    rule_level integer DEFAULT 0 CONSTRAINT events_rule_level_not_null NOT NULL,
    rule_description text,
    source_ip inet,
    destination_ip inet,
    source_port integer,
    destination_port integer,
    protocol character varying(16),
    username character varying(128),
    classification_groups text[],
    mitre_attack_ids text[],
    mitre_tactics text[],
    mitre_techniques text[],
    compliance_frameworks jsonb DEFAULT '{}'::jsonb,
    asset_criticality_tier character varying(16) DEFAULT 'STANDARD'::character varying,
    is_asset_internet_exposed boolean DEFAULT false,
    is_privileged_user boolean DEFAULT false,
    is_service_account boolean DEFAULT false,
    threat_intel_match boolean DEFAULT false,
    threat_intel_confidence integer DEFAULT 0,
    raw_payload jsonb CONSTRAINT events_raw_payload_not_null NOT NULL,
    ingested_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: ingest_checkpoints; Type: TABLE; Schema: telemetry; Owner: -
--

CREATE TABLE telemetry.ingest_checkpoints (
    tenant_id character varying(64) NOT NULL,
    last_event_id character varying(128),
    last_timestamp timestamp with time zone,
    cursor_offset bigint DEFAULT 0,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: normalized_events; Type: TABLE; Schema: telemetry; Owner: -
--

CREATE TABLE telemetry.normalized_events (
    normalized_event_id character varying(64) NOT NULL,
    raw_event_id character varying(64) NOT NULL,
    event_timestamp timestamp with time zone NOT NULL,
    rule_id integer NOT NULL,
    rule_level integer NOT NULL,
    rule_description text NOT NULL,
    classification_groups text[] DEFAULT '{}'::text[] NOT NULL,
    mitre_attack_ids character varying(16)[] DEFAULT '{}'::character varying[],
    mitre_tactics text[] DEFAULT '{}'::text[],
    mitre_techniques text[] DEFAULT '{}'::text[],
    compliance_frameworks jsonb DEFAULT '{}'::jsonb,
    asset_criticality_tier character varying(16) DEFAULT 'STANDARD'::character varying,
    is_asset_internet_exposed boolean DEFAULT false,
    is_privileged_user boolean DEFAULT false,
    is_service_account boolean DEFAULT false,
    threat_intel_match boolean DEFAULT false,
    threat_intel_confidence integer DEFAULT 0,
    processed_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT normalized_events_rule_level_check CHECK (((rule_level >= 0) AND (rule_level <= 16)))
)
PARTITION BY RANGE (processed_at);


--
-- Name: normalized_events_2026_07; Type: TABLE; Schema: telemetry; Owner: -
--

CREATE TABLE telemetry.normalized_events_2026_07 (
    normalized_event_id character varying(64) CONSTRAINT normalized_events_normalized_event_id_not_null NOT NULL,
    raw_event_id character varying(64) CONSTRAINT normalized_events_raw_event_id_not_null NOT NULL,
    event_timestamp timestamp with time zone CONSTRAINT normalized_events_event_timestamp_not_null NOT NULL,
    rule_id integer CONSTRAINT normalized_events_rule_id_not_null NOT NULL,
    rule_level integer CONSTRAINT normalized_events_rule_level_not_null NOT NULL,
    rule_description text CONSTRAINT normalized_events_rule_description_not_null NOT NULL,
    classification_groups text[] DEFAULT '{}'::text[] CONSTRAINT normalized_events_classification_groups_not_null NOT NULL,
    mitre_attack_ids character varying(16)[] DEFAULT '{}'::character varying[],
    mitre_tactics text[] DEFAULT '{}'::text[],
    mitre_techniques text[] DEFAULT '{}'::text[],
    compliance_frameworks jsonb DEFAULT '{}'::jsonb,
    asset_criticality_tier character varying(16) DEFAULT 'STANDARD'::character varying,
    is_asset_internet_exposed boolean DEFAULT false,
    is_privileged_user boolean DEFAULT false,
    is_service_account boolean DEFAULT false,
    threat_intel_match boolean DEFAULT false,
    threat_intel_confidence integer DEFAULT 0,
    processed_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP CONSTRAINT normalized_events_processed_at_not_null NOT NULL,
    CONSTRAINT normalized_events_rule_level_check CHECK (((rule_level >= 0) AND (rule_level <= 16)))
);


--
-- Name: normalized_events_2026_08; Type: TABLE; Schema: telemetry; Owner: -
--

CREATE TABLE telemetry.normalized_events_2026_08 (
    normalized_event_id character varying(64) CONSTRAINT normalized_events_normalized_event_id_not_null NOT NULL,
    raw_event_id character varying(64) CONSTRAINT normalized_events_raw_event_id_not_null NOT NULL,
    event_timestamp timestamp with time zone CONSTRAINT normalized_events_event_timestamp_not_null NOT NULL,
    rule_id integer CONSTRAINT normalized_events_rule_id_not_null NOT NULL,
    rule_level integer CONSTRAINT normalized_events_rule_level_not_null NOT NULL,
    rule_description text CONSTRAINT normalized_events_rule_description_not_null NOT NULL,
    classification_groups text[] DEFAULT '{}'::text[] CONSTRAINT normalized_events_classification_groups_not_null NOT NULL,
    mitre_attack_ids character varying(16)[] DEFAULT '{}'::character varying[],
    mitre_tactics text[] DEFAULT '{}'::text[],
    mitre_techniques text[] DEFAULT '{}'::text[],
    compliance_frameworks jsonb DEFAULT '{}'::jsonb,
    asset_criticality_tier character varying(16) DEFAULT 'STANDARD'::character varying,
    is_asset_internet_exposed boolean DEFAULT false,
    is_privileged_user boolean DEFAULT false,
    is_service_account boolean DEFAULT false,
    threat_intel_match boolean DEFAULT false,
    threat_intel_confidence integer DEFAULT 0,
    processed_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP CONSTRAINT normalized_events_processed_at_not_null NOT NULL,
    CONSTRAINT normalized_events_rule_level_check CHECK (((rule_level >= 0) AND (rule_level <= 16)))
);


--
-- Name: normalized_events_2026_09; Type: TABLE; Schema: telemetry; Owner: -
--

CREATE TABLE telemetry.normalized_events_2026_09 (
    normalized_event_id character varying(64) CONSTRAINT normalized_events_normalized_event_id_not_null NOT NULL,
    raw_event_id character varying(64) CONSTRAINT normalized_events_raw_event_id_not_null NOT NULL,
    event_timestamp timestamp with time zone CONSTRAINT normalized_events_event_timestamp_not_null NOT NULL,
    rule_id integer CONSTRAINT normalized_events_rule_id_not_null NOT NULL,
    rule_level integer CONSTRAINT normalized_events_rule_level_not_null NOT NULL,
    rule_description text CONSTRAINT normalized_events_rule_description_not_null NOT NULL,
    classification_groups text[] DEFAULT '{}'::text[] CONSTRAINT normalized_events_classification_groups_not_null NOT NULL,
    mitre_attack_ids character varying(16)[] DEFAULT '{}'::character varying[],
    mitre_tactics text[] DEFAULT '{}'::text[],
    mitre_techniques text[] DEFAULT '{}'::text[],
    compliance_frameworks jsonb DEFAULT '{}'::jsonb,
    asset_criticality_tier character varying(16) DEFAULT 'STANDARD'::character varying,
    is_asset_internet_exposed boolean DEFAULT false,
    is_privileged_user boolean DEFAULT false,
    is_service_account boolean DEFAULT false,
    threat_intel_match boolean DEFAULT false,
    threat_intel_confidence integer DEFAULT 0,
    processed_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP CONSTRAINT normalized_events_processed_at_not_null NOT NULL,
    CONSTRAINT normalized_events_rule_level_check CHECK (((rule_level >= 0) AND (rule_level <= 16)))
);


--
-- Name: normalized_events_2026_10; Type: TABLE; Schema: telemetry; Owner: -
--

CREATE TABLE telemetry.normalized_events_2026_10 (
    normalized_event_id character varying(64) CONSTRAINT normalized_events_normalized_event_id_not_null NOT NULL,
    raw_event_id character varying(64) CONSTRAINT normalized_events_raw_event_id_not_null NOT NULL,
    event_timestamp timestamp with time zone CONSTRAINT normalized_events_event_timestamp_not_null NOT NULL,
    rule_id integer CONSTRAINT normalized_events_rule_id_not_null NOT NULL,
    rule_level integer CONSTRAINT normalized_events_rule_level_not_null NOT NULL,
    rule_description text CONSTRAINT normalized_events_rule_description_not_null NOT NULL,
    classification_groups text[] DEFAULT '{}'::text[] CONSTRAINT normalized_events_classification_groups_not_null NOT NULL,
    mitre_attack_ids character varying(16)[] DEFAULT '{}'::character varying[],
    mitre_tactics text[] DEFAULT '{}'::text[],
    mitre_techniques text[] DEFAULT '{}'::text[],
    compliance_frameworks jsonb DEFAULT '{}'::jsonb,
    asset_criticality_tier character varying(16) DEFAULT 'STANDARD'::character varying,
    is_asset_internet_exposed boolean DEFAULT false,
    is_privileged_user boolean DEFAULT false,
    is_service_account boolean DEFAULT false,
    threat_intel_match boolean DEFAULT false,
    threat_intel_confidence integer DEFAULT 0,
    processed_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP CONSTRAINT normalized_events_processed_at_not_null NOT NULL,
    CONSTRAINT normalized_events_rule_level_check CHECK (((rule_level >= 0) AND (rule_level <= 16)))
);


--
-- Name: normalized_events_2026_12; Type: TABLE; Schema: telemetry; Owner: -
--

CREATE TABLE telemetry.normalized_events_2026_12 (
    normalized_event_id character varying(64) CONSTRAINT normalized_events_normalized_event_id_not_null NOT NULL,
    raw_event_id character varying(64) CONSTRAINT normalized_events_raw_event_id_not_null NOT NULL,
    event_timestamp timestamp with time zone CONSTRAINT normalized_events_event_timestamp_not_null NOT NULL,
    rule_id integer CONSTRAINT normalized_events_rule_id_not_null NOT NULL,
    rule_level integer CONSTRAINT normalized_events_rule_level_not_null NOT NULL,
    rule_description text CONSTRAINT normalized_events_rule_description_not_null NOT NULL,
    classification_groups text[] DEFAULT '{}'::text[] CONSTRAINT normalized_events_classification_groups_not_null NOT NULL,
    mitre_attack_ids character varying(16)[] DEFAULT '{}'::character varying[],
    mitre_tactics text[] DEFAULT '{}'::text[],
    mitre_techniques text[] DEFAULT '{}'::text[],
    compliance_frameworks jsonb DEFAULT '{}'::jsonb,
    asset_criticality_tier character varying(16) DEFAULT 'STANDARD'::character varying,
    is_asset_internet_exposed boolean DEFAULT false,
    is_privileged_user boolean DEFAULT false,
    is_service_account boolean DEFAULT false,
    threat_intel_match boolean DEFAULT false,
    threat_intel_confidence integer DEFAULT 0,
    processed_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP CONSTRAINT normalized_events_processed_at_not_null NOT NULL,
    CONSTRAINT normalized_events_rule_level_check CHECK (((rule_level >= 0) AND (rule_level <= 16)))
);


--
-- Name: normalized_events_2027_01; Type: TABLE; Schema: telemetry; Owner: -
--

CREATE TABLE telemetry.normalized_events_2027_01 (
    normalized_event_id character varying(64) CONSTRAINT normalized_events_normalized_event_id_not_null NOT NULL,
    raw_event_id character varying(64) CONSTRAINT normalized_events_raw_event_id_not_null NOT NULL,
    event_timestamp timestamp with time zone CONSTRAINT normalized_events_event_timestamp_not_null NOT NULL,
    rule_id integer CONSTRAINT normalized_events_rule_id_not_null NOT NULL,
    rule_level integer CONSTRAINT normalized_events_rule_level_not_null NOT NULL,
    rule_description text CONSTRAINT normalized_events_rule_description_not_null NOT NULL,
    classification_groups text[] DEFAULT '{}'::text[] CONSTRAINT normalized_events_classification_groups_not_null NOT NULL,
    mitre_attack_ids character varying(16)[] DEFAULT '{}'::character varying[],
    mitre_tactics text[] DEFAULT '{}'::text[],
    mitre_techniques text[] DEFAULT '{}'::text[],
    compliance_frameworks jsonb DEFAULT '{}'::jsonb,
    asset_criticality_tier character varying(16) DEFAULT 'STANDARD'::character varying,
    is_asset_internet_exposed boolean DEFAULT false,
    is_privileged_user boolean DEFAULT false,
    is_service_account boolean DEFAULT false,
    threat_intel_match boolean DEFAULT false,
    threat_intel_confidence integer DEFAULT 0,
    processed_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP CONSTRAINT normalized_events_processed_at_not_null NOT NULL,
    CONSTRAINT normalized_events_rule_level_check CHECK (((rule_level >= 0) AND (rule_level <= 16)))
);


--
-- Name: normalized_events_default; Type: TABLE; Schema: telemetry; Owner: -
--

CREATE TABLE telemetry.normalized_events_default (
    normalized_event_id character varying(64) CONSTRAINT normalized_events_normalized_event_id_not_null NOT NULL,
    raw_event_id character varying(64) CONSTRAINT normalized_events_raw_event_id_not_null NOT NULL,
    event_timestamp timestamp with time zone CONSTRAINT normalized_events_event_timestamp_not_null NOT NULL,
    rule_id integer CONSTRAINT normalized_events_rule_id_not_null NOT NULL,
    rule_level integer CONSTRAINT normalized_events_rule_level_not_null NOT NULL,
    rule_description text CONSTRAINT normalized_events_rule_description_not_null NOT NULL,
    classification_groups text[] DEFAULT '{}'::text[] CONSTRAINT normalized_events_classification_groups_not_null NOT NULL,
    mitre_attack_ids character varying(16)[] DEFAULT '{}'::character varying[],
    mitre_tactics text[] DEFAULT '{}'::text[],
    mitre_techniques text[] DEFAULT '{}'::text[],
    compliance_frameworks jsonb DEFAULT '{}'::jsonb,
    asset_criticality_tier character varying(16) DEFAULT 'STANDARD'::character varying,
    is_asset_internet_exposed boolean DEFAULT false,
    is_privileged_user boolean DEFAULT false,
    is_service_account boolean DEFAULT false,
    threat_intel_match boolean DEFAULT false,
    threat_intel_confidence integer DEFAULT 0,
    processed_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP CONSTRAINT normalized_events_processed_at_not_null NOT NULL,
    CONSTRAINT normalized_events_rule_level_check CHECK (((rule_level >= 0) AND (rule_level <= 16)))
);


--
-- Name: raw_events; Type: TABLE; Schema: telemetry; Owner: -
--

CREATE TABLE telemetry.raw_events (
    event_id character varying(64) NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    agent_id character varying(32) NOT NULL,
    tenant_id character varying(64) DEFAULT 'DEFAULT'::character varying,
    agent_name character varying(128),
    agent_ip character varying(45),
    source_ip character varying(45),
    destination_ip character varying(45),
    source_port integer,
    destination_port integer,
    protocol character varying(16),
    username character varying(128),
    location character varying(255),
    decoder_name character varying(64),
    raw_payload text NOT NULL,
    ingested_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
)
PARTITION BY RANGE ("timestamp");


--
-- Name: raw_events_2026_07; Type: TABLE; Schema: telemetry; Owner: -
--

CREATE TABLE telemetry.raw_events_2026_07 (
    event_id character varying(64) CONSTRAINT raw_events_event_id_not_null NOT NULL,
    "timestamp" timestamp with time zone CONSTRAINT raw_events_timestamp_not_null NOT NULL,
    agent_id character varying(32) CONSTRAINT raw_events_agent_id_not_null NOT NULL,
    tenant_id character varying(64) DEFAULT 'DEFAULT'::character varying,
    agent_name character varying(128),
    agent_ip character varying(45),
    source_ip character varying(45),
    destination_ip character varying(45),
    source_port integer,
    destination_port integer,
    protocol character varying(16),
    username character varying(128),
    location character varying(255),
    decoder_name character varying(64),
    raw_payload text CONSTRAINT raw_events_raw_payload_not_null NOT NULL,
    ingested_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: raw_events_2026_08; Type: TABLE; Schema: telemetry; Owner: -
--

CREATE TABLE telemetry.raw_events_2026_08 (
    event_id character varying(64) CONSTRAINT raw_events_event_id_not_null NOT NULL,
    "timestamp" timestamp with time zone CONSTRAINT raw_events_timestamp_not_null NOT NULL,
    agent_id character varying(32) CONSTRAINT raw_events_agent_id_not_null NOT NULL,
    tenant_id character varying(64) DEFAULT 'DEFAULT'::character varying,
    agent_name character varying(128),
    agent_ip character varying(45),
    source_ip character varying(45),
    destination_ip character varying(45),
    source_port integer,
    destination_port integer,
    protocol character varying(16),
    username character varying(128),
    location character varying(255),
    decoder_name character varying(64),
    raw_payload text CONSTRAINT raw_events_raw_payload_not_null NOT NULL,
    ingested_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: raw_events_2026_09; Type: TABLE; Schema: telemetry; Owner: -
--

CREATE TABLE telemetry.raw_events_2026_09 (
    event_id character varying(64) CONSTRAINT raw_events_event_id_not_null NOT NULL,
    "timestamp" timestamp with time zone CONSTRAINT raw_events_timestamp_not_null NOT NULL,
    agent_id character varying(32) CONSTRAINT raw_events_agent_id_not_null NOT NULL,
    tenant_id character varying(64) DEFAULT 'DEFAULT'::character varying,
    agent_name character varying(128),
    agent_ip character varying(45),
    source_ip character varying(45),
    destination_ip character varying(45),
    source_port integer,
    destination_port integer,
    protocol character varying(16),
    username character varying(128),
    location character varying(255),
    decoder_name character varying(64),
    raw_payload text CONSTRAINT raw_events_raw_payload_not_null NOT NULL,
    ingested_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: raw_events_2026_10; Type: TABLE; Schema: telemetry; Owner: -
--

CREATE TABLE telemetry.raw_events_2026_10 (
    event_id character varying(64) CONSTRAINT raw_events_event_id_not_null NOT NULL,
    "timestamp" timestamp with time zone CONSTRAINT raw_events_timestamp_not_null NOT NULL,
    agent_id character varying(32) CONSTRAINT raw_events_agent_id_not_null NOT NULL,
    tenant_id character varying(64) DEFAULT 'DEFAULT'::character varying,
    agent_name character varying(128),
    agent_ip character varying(45),
    source_ip character varying(45),
    destination_ip character varying(45),
    source_port integer,
    destination_port integer,
    protocol character varying(16),
    username character varying(128),
    location character varying(255),
    decoder_name character varying(64),
    raw_payload text CONSTRAINT raw_events_raw_payload_not_null NOT NULL,
    ingested_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: raw_events_2026_12; Type: TABLE; Schema: telemetry; Owner: -
--

CREATE TABLE telemetry.raw_events_2026_12 (
    event_id character varying(64) CONSTRAINT raw_events_event_id_not_null NOT NULL,
    "timestamp" timestamp with time zone CONSTRAINT raw_events_timestamp_not_null NOT NULL,
    agent_id character varying(32) CONSTRAINT raw_events_agent_id_not_null NOT NULL,
    tenant_id character varying(64) DEFAULT 'DEFAULT'::character varying,
    agent_name character varying(128),
    agent_ip character varying(45),
    source_ip character varying(45),
    destination_ip character varying(45),
    source_port integer,
    destination_port integer,
    protocol character varying(16),
    username character varying(128),
    location character varying(255),
    decoder_name character varying(64),
    raw_payload text CONSTRAINT raw_events_raw_payload_not_null NOT NULL,
    ingested_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: raw_events_2027_01; Type: TABLE; Schema: telemetry; Owner: -
--

CREATE TABLE telemetry.raw_events_2027_01 (
    event_id character varying(64) CONSTRAINT raw_events_event_id_not_null NOT NULL,
    "timestamp" timestamp with time zone CONSTRAINT raw_events_timestamp_not_null NOT NULL,
    agent_id character varying(32) CONSTRAINT raw_events_agent_id_not_null NOT NULL,
    tenant_id character varying(64) DEFAULT 'DEFAULT'::character varying,
    agent_name character varying(128),
    agent_ip character varying(45),
    source_ip character varying(45),
    destination_ip character varying(45),
    source_port integer,
    destination_port integer,
    protocol character varying(16),
    username character varying(128),
    location character varying(255),
    decoder_name character varying(64),
    raw_payload text CONSTRAINT raw_events_raw_payload_not_null NOT NULL,
    ingested_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: raw_events_default; Type: TABLE; Schema: telemetry; Owner: -
--

CREATE TABLE telemetry.raw_events_default (
    event_id character varying(64) CONSTRAINT raw_events_event_id_not_null NOT NULL,
    "timestamp" timestamp with time zone CONSTRAINT raw_events_timestamp_not_null NOT NULL,
    agent_id character varying(32) CONSTRAINT raw_events_agent_id_not_null NOT NULL,
    tenant_id character varying(64) DEFAULT 'DEFAULT'::character varying,
    agent_name character varying(128),
    agent_ip character varying(45),
    source_ip character varying(45),
    destination_ip character varying(45),
    source_port integer,
    destination_port integer,
    protocol character varying(16),
    username character varying(128),
    location character varying(255),
    decoder_name character varying(64),
    raw_payload text CONSTRAINT raw_events_raw_payload_not_null NOT NULL,
    ingested_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: events_2026_07; Type: TABLE ATTACH; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.events ATTACH PARTITION telemetry.events_2026_07 FOR VALUES FROM ('2026-07-01 00:00:00+07') TO ('2026-08-01 00:00:00+07');


--
-- Name: events_2026_08; Type: TABLE ATTACH; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.events ATTACH PARTITION telemetry.events_2026_08 FOR VALUES FROM ('2026-08-01 00:00:00+07') TO ('2026-09-01 00:00:00+07');


--
-- Name: events_2026_09; Type: TABLE ATTACH; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.events ATTACH PARTITION telemetry.events_2026_09 FOR VALUES FROM ('2026-09-01 00:00:00+07') TO ('2026-10-01 00:00:00+07');


--
-- Name: events_2026_10; Type: TABLE ATTACH; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.events ATTACH PARTITION telemetry.events_2026_10 FOR VALUES FROM ('2026-10-01 00:00:00+07') TO ('2026-11-01 00:00:00+07');


--
-- Name: events_2026_11; Type: TABLE ATTACH; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.events ATTACH PARTITION telemetry.events_2026_11 FOR VALUES FROM ('2026-11-01 00:00:00+07') TO ('2026-12-01 00:00:00+07');


--
-- Name: events_2026_12; Type: TABLE ATTACH; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.events ATTACH PARTITION telemetry.events_2026_12 FOR VALUES FROM ('2026-12-01 00:00:00+07') TO ('2027-01-01 00:00:00+07');


--
-- Name: events_2027_01; Type: TABLE ATTACH; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.events ATTACH PARTITION telemetry.events_2027_01 FOR VALUES FROM ('2027-01-01 00:00:00+07') TO ('2027-02-01 00:00:00+07');


--
-- Name: events_default; Type: TABLE ATTACH; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.events ATTACH PARTITION telemetry.events_default DEFAULT;


--
-- Name: normalized_events_2026_07; Type: TABLE ATTACH; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.normalized_events ATTACH PARTITION telemetry.normalized_events_2026_07 FOR VALUES FROM ('2026-07-01 07:00:00+07') TO ('2026-08-01 07:00:00+07');


--
-- Name: normalized_events_2026_08; Type: TABLE ATTACH; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.normalized_events ATTACH PARTITION telemetry.normalized_events_2026_08 FOR VALUES FROM ('2026-08-01 07:00:00+07') TO ('2026-09-01 07:00:00+07');


--
-- Name: normalized_events_2026_09; Type: TABLE ATTACH; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.normalized_events ATTACH PARTITION telemetry.normalized_events_2026_09 FOR VALUES FROM ('2026-09-01 07:00:00+07') TO ('2026-10-01 07:00:00+07');


--
-- Name: normalized_events_2026_10; Type: TABLE ATTACH; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.normalized_events ATTACH PARTITION telemetry.normalized_events_2026_10 FOR VALUES FROM ('2026-10-01 07:00:00+07') TO ('2026-11-01 07:00:00+07');


--
-- Name: normalized_events_2026_12; Type: TABLE ATTACH; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.normalized_events ATTACH PARTITION telemetry.normalized_events_2026_12 FOR VALUES FROM ('2026-12-01 00:00:00+07') TO ('2027-01-01 00:00:00+07');


--
-- Name: normalized_events_2027_01; Type: TABLE ATTACH; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.normalized_events ATTACH PARTITION telemetry.normalized_events_2027_01 FOR VALUES FROM ('2027-01-01 00:00:00+07') TO ('2027-02-01 00:00:00+07');


--
-- Name: normalized_events_default; Type: TABLE ATTACH; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.normalized_events ATTACH PARTITION telemetry.normalized_events_default DEFAULT;


--
-- Name: raw_events_2026_07; Type: TABLE ATTACH; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.raw_events ATTACH PARTITION telemetry.raw_events_2026_07 FOR VALUES FROM ('2026-07-01 07:00:00+07') TO ('2026-08-01 07:00:00+07');


--
-- Name: raw_events_2026_08; Type: TABLE ATTACH; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.raw_events ATTACH PARTITION telemetry.raw_events_2026_08 FOR VALUES FROM ('2026-08-01 07:00:00+07') TO ('2026-09-01 07:00:00+07');


--
-- Name: raw_events_2026_09; Type: TABLE ATTACH; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.raw_events ATTACH PARTITION telemetry.raw_events_2026_09 FOR VALUES FROM ('2026-09-01 07:00:00+07') TO ('2026-10-01 07:00:00+07');


--
-- Name: raw_events_2026_10; Type: TABLE ATTACH; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.raw_events ATTACH PARTITION telemetry.raw_events_2026_10 FOR VALUES FROM ('2026-10-01 07:00:00+07') TO ('2026-11-01 07:00:00+07');


--
-- Name: raw_events_2026_12; Type: TABLE ATTACH; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.raw_events ATTACH PARTITION telemetry.raw_events_2026_12 FOR VALUES FROM ('2026-12-01 00:00:00+07') TO ('2027-01-01 00:00:00+07');


--
-- Name: raw_events_2027_01; Type: TABLE ATTACH; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.raw_events ATTACH PARTITION telemetry.raw_events_2027_01 FOR VALUES FROM ('2027-01-01 00:00:00+07') TO ('2027-02-01 00:00:00+07');


--
-- Name: raw_events_default; Type: TABLE ATTACH; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.raw_events ATTACH PARTITION telemetry.raw_events_default DEFAULT;


--
-- Name: incident_stages stage_id; Type: DEFAULT; Schema: correlation; Owner: -
--

ALTER TABLE ONLY correlation.incident_stages ALTER COLUMN stage_id SET DEFAULT nextval('correlation.incident_stages_stage_id_seq'::regclass);


--
-- Name: threat_intelligence_iocs ioc_id; Type: DEFAULT; Schema: enrichment; Owner: -
--

ALTER TABLE ONLY enrichment.threat_intelligence_iocs ALTER COLUMN ioc_id SET DEFAULT nextval('enrichment.threat_intelligence_iocs_ioc_id_seq'::regclass);


--
-- Name: calculated_risk_scores score_id; Type: DEFAULT; Schema: risk_engine; Owner: -
--

ALTER TABLE ONLY risk_engine.calculated_risk_scores ALTER COLUMN score_id SET DEFAULT nextval('risk_engine.calculated_risk_scores_score_id_seq'::regclass);


--
-- Name: risk_scoring_factors factor_id; Type: DEFAULT; Schema: risk_engine; Owner: -
--

ALTER TABLE ONLY risk_engine.risk_scoring_factors ALTER COLUMN factor_id SET DEFAULT nextval('risk_engine.risk_scoring_factors_factor_id_seq'::regclass);


--
-- Name: ground_truth_dataset id; Type: DEFAULT; Schema: soc_ops; Owner: -
--

ALTER TABLE ONLY soc_ops.ground_truth_dataset ALTER COLUMN id SET DEFAULT nextval('soc_ops.ground_truth_dataset_id_seq'::regclass);


--
-- Name: incident_investigation_notes note_id; Type: DEFAULT; Schema: soc_ops; Owner: -
--

ALTER TABLE ONLY soc_ops.incident_investigation_notes ALTER COLUMN note_id SET DEFAULT nextval('soc_ops.incident_investigation_notes_note_id_seq'::regclass);


--
-- Name: incident_response_actions action_id; Type: DEFAULT; Schema: soc_ops; Owner: -
--

ALTER TABLE ONLY soc_ops.incident_response_actions ALTER COLUMN action_id SET DEFAULT nextval('soc_ops.incident_response_actions_action_id_seq'::regclass);


--
-- Name: soc_users user_id; Type: DEFAULT; Schema: soc_ops; Owner: -
--

ALTER TABLE ONLY soc_ops.soc_users ALTER COLUMN user_id SET DEFAULT nextval('soc_ops.soc_users_user_id_seq'::regclass);


--
-- Name: suppression_audit_log log_id; Type: DEFAULT; Schema: suppression; Owner: -
--

ALTER TABLE ONLY suppression.suppression_audit_log ALTER COLUMN log_id SET DEFAULT nextval('suppression.suppression_audit_log_log_id_seq'::regclass);


--
-- Name: correlated_incidents correlated_incidents_pkey; Type: CONSTRAINT; Schema: correlation; Owner: -
--

ALTER TABLE ONLY correlation.correlated_incidents
    ADD CONSTRAINT correlated_incidents_pkey PRIMARY KEY (incident_id);


--
-- Name: correlation_rules correlation_rules_pkey; Type: CONSTRAINT; Schema: correlation; Owner: -
--

ALTER TABLE ONLY correlation.correlation_rules
    ADD CONSTRAINT correlation_rules_pkey PRIMARY KEY (correlation_rule_id);


--
-- Name: correlation_rules correlation_rules_rule_code_key; Type: CONSTRAINT; Schema: correlation; Owner: -
--

ALTER TABLE ONLY correlation.correlation_rules
    ADD CONSTRAINT correlation_rules_rule_code_key UNIQUE (rule_code);


--
-- Name: incident_stages incident_stages_pkey; Type: CONSTRAINT; Schema: correlation; Owner: -
--

ALTER TABLE ONLY correlation.incident_stages
    ADD CONSTRAINT incident_stages_pkey PRIMARY KEY (stage_id);


--
-- Name: incident_stages uq_stage_order; Type: CONSTRAINT; Schema: correlation; Owner: -
--

ALTER TABLE ONLY correlation.incident_stages
    ADD CONSTRAINT uq_stage_order UNIQUE (incident_id, sequence_order);


--
-- Name: asset_inventory_context asset_inventory_context_hostname_key; Type: CONSTRAINT; Schema: enrichment; Owner: -
--

ALTER TABLE ONLY enrichment.asset_inventory_context
    ADD CONSTRAINT asset_inventory_context_hostname_key UNIQUE (hostname);


--
-- Name: asset_inventory_context asset_inventory_context_pkey; Type: CONSTRAINT; Schema: enrichment; Owner: -
--

ALTER TABLE ONLY enrichment.asset_inventory_context
    ADD CONSTRAINT asset_inventory_context_pkey PRIMARY KEY (asset_id);


--
-- Name: identity_context identity_context_pkey; Type: CONSTRAINT; Schema: enrichment; Owner: -
--

ALTER TABLE ONLY enrichment.identity_context
    ADD CONSTRAINT identity_context_pkey PRIMARY KEY (identity_id);


--
-- Name: identity_context identity_context_username_key; Type: CONSTRAINT; Schema: enrichment; Owner: -
--

ALTER TABLE ONLY enrichment.identity_context
    ADD CONSTRAINT identity_context_username_key UNIQUE (username);


--
-- Name: threat_intelligence_iocs threat_intelligence_iocs_pkey; Type: CONSTRAINT; Schema: enrichment; Owner: -
--

ALTER TABLE ONLY enrichment.threat_intelligence_iocs
    ADD CONSTRAINT threat_intelligence_iocs_pkey PRIMARY KEY (ioc_id);


--
-- Name: threat_intelligence_iocs uq_ioc_indicator; Type: CONSTRAINT; Schema: enrichment; Owner: -
--

ALTER TABLE ONLY enrichment.threat_intelligence_iocs
    ADD CONSTRAINT uq_ioc_indicator UNIQUE (indicator_value, indicator_type);


--
-- Name: hourly_overview_rollup hourly_overview_rollup_pkey; Type: CONSTRAINT; Schema: metrics; Owner: -
--

ALTER TABLE ONLY metrics.hourly_overview_rollup
    ADD CONSTRAINT hourly_overview_rollup_pkey PRIMARY KEY (bucket_hour);


--
-- Name: operational_metrics_daily operational_metrics_daily_pkey; Type: CONSTRAINT; Schema: metrics; Owner: -
--

ALTER TABLE ONLY metrics.operational_metrics_daily
    ADD CONSTRAINT operational_metrics_daily_pkey PRIMARY KEY (metric_date);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- Name: calculated_risk_scores calculated_risk_scores_incident_id_key; Type: CONSTRAINT; Schema: risk_engine; Owner: -
--

ALTER TABLE ONLY risk_engine.calculated_risk_scores
    ADD CONSTRAINT calculated_risk_scores_incident_id_key UNIQUE (incident_id);


--
-- Name: calculated_risk_scores calculated_risk_scores_pkey; Type: CONSTRAINT; Schema: risk_engine; Owner: -
--

ALTER TABLE ONLY risk_engine.calculated_risk_scores
    ADD CONSTRAINT calculated_risk_scores_pkey PRIMARY KEY (score_id);


--
-- Name: risk_scoring_factors risk_scoring_factors_pkey; Type: CONSTRAINT; Schema: risk_engine; Owner: -
--

ALTER TABLE ONLY risk_engine.risk_scoring_factors
    ADD CONSTRAINT risk_scoring_factors_pkey PRIMARY KEY (factor_id);


--
-- Name: ground_truth_dataset ground_truth_dataset_pkey; Type: CONSTRAINT; Schema: soc_ops; Owner: -
--

ALTER TABLE ONLY soc_ops.ground_truth_dataset
    ADD CONSTRAINT ground_truth_dataset_pkey PRIMARY KEY (id);


--
-- Name: incident_investigation_notes incident_investigation_notes_pkey; Type: CONSTRAINT; Schema: soc_ops; Owner: -
--

ALTER TABLE ONLY soc_ops.incident_investigation_notes
    ADD CONSTRAINT incident_investigation_notes_pkey PRIMARY KEY (note_id);


--
-- Name: incident_response_actions incident_response_actions_pkey; Type: CONSTRAINT; Schema: soc_ops; Owner: -
--

ALTER TABLE ONLY soc_ops.incident_response_actions
    ADD CONSTRAINT incident_response_actions_pkey PRIMARY KEY (action_id);


--
-- Name: soc_triage_queue soc_triage_queue_pkey; Type: CONSTRAINT; Schema: soc_ops; Owner: -
--

ALTER TABLE ONLY soc_ops.soc_triage_queue
    ADD CONSTRAINT soc_triage_queue_pkey PRIMARY KEY (triage_id);


--
-- Name: soc_users soc_users_email_key; Type: CONSTRAINT; Schema: soc_ops; Owner: -
--

ALTER TABLE ONLY soc_ops.soc_users
    ADD CONSTRAINT soc_users_email_key UNIQUE (email);


--
-- Name: soc_users soc_users_pkey; Type: CONSTRAINT; Schema: soc_ops; Owner: -
--

ALTER TABLE ONLY soc_ops.soc_users
    ADD CONSTRAINT soc_users_pkey PRIMARY KEY (user_id);


--
-- Name: soc_users soc_users_username_key; Type: CONSTRAINT; Schema: soc_ops; Owner: -
--

ALTER TABLE ONLY soc_ops.soc_users
    ADD CONSTRAINT soc_users_username_key UNIQUE (username);


--
-- Name: ground_truth_dataset uq_ground_truth_incident; Type: CONSTRAINT; Schema: soc_ops; Owner: -
--

ALTER TABLE ONLY soc_ops.ground_truth_dataset
    ADD CONSTRAINT uq_ground_truth_incident UNIQUE (incident_id);


--
-- Name: aggregated_alerts aggregated_alerts_category_check; Type: CHECK CONSTRAINT; Schema: suppression; Owner: -
--

ALTER TABLE suppression.aggregated_alerts
    ADD CONSTRAINT aggregated_alerts_category_check CHECK (((category)::text = ANY (ARRAY[('RANSOMWARE'::character varying)::text, ('MALWARE'::character varying)::text, ('COMMAND_AND_CONTROL'::character varying)::text, ('EXFILTRATION'::character varying)::text, ('LATERAL_MOVEMENT'::character varying)::text, ('PRIVILEGE_ESCALATION'::character varying)::text, ('CREDENTIAL_ACCESS'::character varying)::text, ('DEFENSE_EVASION'::character varying)::text, ('EXECUTION'::character varying)::text, ('PERSISTENCE'::character varying)::text, ('DISCOVERY'::character varying)::text, ('INITIAL_ACCESS'::character varying)::text, ('AUTH_FAILURE'::character varying)::text, ('AUTH_SUCCESS'::character varying)::text, ('WEB_ATTACK'::character varying)::text, ('WEB_OPERATIONAL'::character varying)::text, ('FILE_INTEGRITY'::character varying)::text, ('VULNERABILITY'::character varying)::text, ('CONFIGURATION_ASSESSMENT'::character varying)::text, ('CLOUD_CONTAINER'::character varying)::text, ('SYSTEM_HEALTH'::character varying)::text, ('OTHER'::character varying)::text, ('HOST'::character varying)::text, ('AUTH'::character varying)::text, ('NETWORK'::character varying)::text, ('TELEMETRY'::character varying)::text, ('COMPLIANCE'::character varying)::text]))) NOT VALID;


--
-- Name: aggregated_alerts aggregated_alerts_pkey; Type: CONSTRAINT; Schema: suppression; Owner: -
--

ALTER TABLE ONLY suppression.aggregated_alerts
    ADD CONSTRAINT aggregated_alerts_pkey PRIMARY KEY (aggregation_id);


--
-- Name: cumulative_alerts cumulative_alerts_category_check; Type: CHECK CONSTRAINT; Schema: suppression; Owner: -
--

ALTER TABLE suppression.cumulative_alerts
    ADD CONSTRAINT cumulative_alerts_category_check CHECK (((category)::text = ANY (ARRAY[('RANSOMWARE'::character varying)::text, ('MALWARE'::character varying)::text, ('COMMAND_AND_CONTROL'::character varying)::text, ('EXFILTRATION'::character varying)::text, ('LATERAL_MOVEMENT'::character varying)::text, ('PRIVILEGE_ESCALATION'::character varying)::text, ('CREDENTIAL_ACCESS'::character varying)::text, ('DEFENSE_EVASION'::character varying)::text, ('EXECUTION'::character varying)::text, ('PERSISTENCE'::character varying)::text, ('DISCOVERY'::character varying)::text, ('INITIAL_ACCESS'::character varying)::text, ('AUTH_FAILURE'::character varying)::text, ('AUTH_SUCCESS'::character varying)::text, ('WEB_ATTACK'::character varying)::text, ('WEB_OPERATIONAL'::character varying)::text, ('FILE_INTEGRITY'::character varying)::text, ('VULNERABILITY'::character varying)::text, ('CONFIGURATION_ASSESSMENT'::character varying)::text, ('CLOUD_CONTAINER'::character varying)::text, ('SYSTEM_HEALTH'::character varying)::text, ('OTHER'::character varying)::text, ('HOST'::character varying)::text, ('AUTH'::character varying)::text, ('NETWORK'::character varying)::text, ('TELEMETRY'::character varying)::text, ('COMPLIANCE'::character varying)::text]))) NOT VALID;


--
-- Name: cumulative_alerts cumulative_alerts_deduplication_key_key; Type: CONSTRAINT; Schema: suppression; Owner: -
--

ALTER TABLE ONLY suppression.cumulative_alerts
    ADD CONSTRAINT cumulative_alerts_deduplication_key_key UNIQUE (deduplication_key);


--
-- Name: cumulative_alerts cumulative_alerts_pkey; Type: CONSTRAINT; Schema: suppression; Owner: -
--

ALTER TABLE ONLY suppression.cumulative_alerts
    ADD CONSTRAINT cumulative_alerts_pkey PRIMARY KEY (cumulative_id);


--
-- Name: maintenance_windows maintenance_windows_pkey; Type: CONSTRAINT; Schema: suppression; Owner: -
--

ALTER TABLE ONLY suppression.maintenance_windows
    ADD CONSTRAINT maintenance_windows_pkey PRIMARY KEY (window_id);


--
-- Name: aggregate_evidence_mapping pk_aggregate_evidence; Type: CONSTRAINT; Schema: suppression; Owner: -
--

ALTER TABLE ONLY suppression.aggregate_evidence_mapping
    ADD CONSTRAINT pk_aggregate_evidence PRIMARY KEY (aggregation_id, raw_event_id);


--
-- Name: shared_value_lists shared_value_lists_pkey; Type: CONSTRAINT; Schema: suppression; Owner: -
--

ALTER TABLE ONLY suppression.shared_value_lists
    ADD CONSTRAINT shared_value_lists_pkey PRIMARY KEY (list_id);


--
-- Name: suppression_audit_log suppression_audit_log_pkey; Type: CONSTRAINT; Schema: suppression; Owner: -
--

ALTER TABLE ONLY suppression.suppression_audit_log
    ADD CONSTRAINT suppression_audit_log_pkey PRIMARY KEY (log_id);


--
-- Name: suppression_groups suppression_groups_pkey; Type: CONSTRAINT; Schema: suppression; Owner: -
--

ALTER TABLE ONLY suppression.suppression_groups
    ADD CONSTRAINT suppression_groups_pkey PRIMARY KEY (group_id);


--
-- Name: suppression_rules suppression_rules_pkey; Type: CONSTRAINT; Schema: suppression; Owner: -
--

ALTER TABLE ONLY suppression.suppression_rules
    ADD CONSTRAINT suppression_rules_pkey PRIMARY KEY (suppression_id);


--
-- Name: events pk_telemetry_events; Type: CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.events
    ADD CONSTRAINT pk_telemetry_events PRIMARY KEY (event_id, event_timestamp);


--
-- Name: events_2026_07 events_2026_07_pkey; Type: CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.events_2026_07
    ADD CONSTRAINT events_2026_07_pkey PRIMARY KEY (event_id, event_timestamp);


--
-- Name: events_2026_08 events_2026_08_pkey; Type: CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.events_2026_08
    ADD CONSTRAINT events_2026_08_pkey PRIMARY KEY (event_id, event_timestamp);


--
-- Name: events_2026_09 events_2026_09_pkey; Type: CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.events_2026_09
    ADD CONSTRAINT events_2026_09_pkey PRIMARY KEY (event_id, event_timestamp);


--
-- Name: events_2026_10 events_2026_10_pkey; Type: CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.events_2026_10
    ADD CONSTRAINT events_2026_10_pkey PRIMARY KEY (event_id, event_timestamp);


--
-- Name: events_2026_11 events_2026_11_pkey; Type: CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.events_2026_11
    ADD CONSTRAINT events_2026_11_pkey PRIMARY KEY (event_id, event_timestamp);


--
-- Name: events_2026_12 events_2026_12_pkey; Type: CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.events_2026_12
    ADD CONSTRAINT events_2026_12_pkey PRIMARY KEY (event_id, event_timestamp);


--
-- Name: events_2027_01 events_2027_01_pkey; Type: CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.events_2027_01
    ADD CONSTRAINT events_2027_01_pkey PRIMARY KEY (event_id, event_timestamp);


--
-- Name: events_default events_default_pkey; Type: CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.events_default
    ADD CONSTRAINT events_default_pkey PRIMARY KEY (event_id, event_timestamp);


--
-- Name: ingest_checkpoints ingest_checkpoints_pkey; Type: CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.ingest_checkpoints
    ADD CONSTRAINT ingest_checkpoints_pkey PRIMARY KEY (tenant_id);


--
-- Name: normalized_events pk_normalized_events; Type: CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.normalized_events
    ADD CONSTRAINT pk_normalized_events PRIMARY KEY (normalized_event_id, processed_at);


--
-- Name: normalized_events_2026_07 normalized_events_2026_07_pkey; Type: CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.normalized_events_2026_07
    ADD CONSTRAINT normalized_events_2026_07_pkey PRIMARY KEY (normalized_event_id, processed_at);


--
-- Name: normalized_events_2026_08 normalized_events_2026_08_pkey; Type: CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.normalized_events_2026_08
    ADD CONSTRAINT normalized_events_2026_08_pkey PRIMARY KEY (normalized_event_id, processed_at);


--
-- Name: normalized_events_2026_09 normalized_events_2026_09_pkey; Type: CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.normalized_events_2026_09
    ADD CONSTRAINT normalized_events_2026_09_pkey PRIMARY KEY (normalized_event_id, processed_at);


--
-- Name: normalized_events_2026_10 normalized_events_2026_10_pkey; Type: CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.normalized_events_2026_10
    ADD CONSTRAINT normalized_events_2026_10_pkey PRIMARY KEY (normalized_event_id, processed_at);


--
-- Name: normalized_events_2026_12 normalized_events_2026_12_pkey; Type: CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.normalized_events_2026_12
    ADD CONSTRAINT normalized_events_2026_12_pkey PRIMARY KEY (normalized_event_id, processed_at);


--
-- Name: normalized_events_2027_01 normalized_events_2027_01_pkey; Type: CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.normalized_events_2027_01
    ADD CONSTRAINT normalized_events_2027_01_pkey PRIMARY KEY (normalized_event_id, processed_at);


--
-- Name: normalized_events_default normalized_events_default_pkey; Type: CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.normalized_events_default
    ADD CONSTRAINT normalized_events_default_pkey PRIMARY KEY (normalized_event_id, processed_at);


--
-- Name: raw_events pk_raw_events; Type: CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.raw_events
    ADD CONSTRAINT pk_raw_events PRIMARY KEY (event_id, "timestamp");


--
-- Name: raw_events_2026_07 raw_events_2026_07_pkey; Type: CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.raw_events_2026_07
    ADD CONSTRAINT raw_events_2026_07_pkey PRIMARY KEY (event_id, "timestamp");


--
-- Name: raw_events_2026_08 raw_events_2026_08_pkey; Type: CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.raw_events_2026_08
    ADD CONSTRAINT raw_events_2026_08_pkey PRIMARY KEY (event_id, "timestamp");


--
-- Name: raw_events_2026_09 raw_events_2026_09_pkey; Type: CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.raw_events_2026_09
    ADD CONSTRAINT raw_events_2026_09_pkey PRIMARY KEY (event_id, "timestamp");


--
-- Name: raw_events_2026_10 raw_events_2026_10_pkey; Type: CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.raw_events_2026_10
    ADD CONSTRAINT raw_events_2026_10_pkey PRIMARY KEY (event_id, "timestamp");


--
-- Name: raw_events_2026_12 raw_events_2026_12_pkey; Type: CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.raw_events_2026_12
    ADD CONSTRAINT raw_events_2026_12_pkey PRIMARY KEY (event_id, "timestamp");


--
-- Name: raw_events_2027_01 raw_events_2027_01_pkey; Type: CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.raw_events_2027_01
    ADD CONSTRAINT raw_events_2027_01_pkey PRIMARY KEY (event_id, "timestamp");


--
-- Name: raw_events_default raw_events_default_pkey; Type: CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE ONLY telemetry.raw_events_default
    ADD CONSTRAINT raw_events_default_pkey PRIMARY KEY (event_id, "timestamp");


--
-- Name: idx_corr_incidents_first_seen_at; Type: INDEX; Schema: correlation; Owner: -
--

CREATE INDEX idx_corr_incidents_first_seen_at ON correlation.correlated_incidents USING btree (first_seen_at DESC);


--
-- Name: idx_correlated_incidents_last_seen; Type: INDEX; Schema: correlation; Owner: -
--

CREATE INDEX idx_correlated_incidents_last_seen ON correlation.correlated_incidents USING btree (last_seen_at);


--
-- Name: idx_incidents_actor_target; Type: INDEX; Schema: correlation; Owner: -
--

CREATE INDEX idx_incidents_actor_target ON correlation.correlated_incidents USING btree (attacker_source_ip, target_host, last_seen_at DESC);


--
-- Name: idx_asset_criticality; Type: INDEX; Schema: enrichment; Owner: -
--

CREATE INDEX idx_asset_criticality ON enrichment.asset_inventory_context USING btree (criticality_tier, ip_address);


--
-- Name: idx_identity_username; Type: INDEX; Schema: enrichment; Owner: -
--

CREATE INDEX idx_identity_username ON enrichment.identity_context USING btree (username, account_type);


--
-- Name: idx_threat_intel_lookup; Type: INDEX; Schema: enrichment; Owner: -
--

CREATE INDEX idx_threat_intel_lookup ON enrichment.threat_intelligence_iocs USING btree (indicator_value, indicator_type) WHERE (is_active = true);


--
-- Name: idx_hourly_overview_bucket; Type: INDEX; Schema: metrics; Owner: -
--

CREATE INDEX idx_hourly_overview_bucket ON metrics.hourly_overview_rollup USING btree (bucket_hour DESC);


--
-- Name: idx_gt_label; Type: INDEX; Schema: soc_ops; Owner: -
--

CREATE INDEX idx_gt_label ON soc_ops.ground_truth_dataset USING btree (ground_truth_label);


--
-- Name: idx_gt_tenant; Type: INDEX; Schema: soc_ops; Owner: -
--

CREATE INDEX idx_gt_tenant ON soc_ops.ground_truth_dataset USING btree (tenant_id);


--
-- Name: idx_gt_untrained; Type: INDEX; Schema: soc_ops; Owner: -
--

CREATE INDEX idx_gt_untrained ON soc_ops.ground_truth_dataset USING btree (is_used_in_training) WHERE (is_used_in_training = false);


--
-- Name: idx_investigation_notes_inc; Type: INDEX; Schema: soc_ops; Owner: -
--

CREATE INDEX idx_investigation_notes_inc ON soc_ops.incident_investigation_notes USING btree (incident_id, created_at);


--
-- Name: idx_response_actions_inc; Type: INDEX; Schema: soc_ops; Owner: -
--

CREATE INDEX idx_response_actions_inc ON soc_ops.incident_response_actions USING btree (incident_id, executed_at);


--
-- Name: idx_soc_queue_active_lookup; Type: INDEX; Schema: soc_ops; Owner: -
--

CREATE INDEX idx_soc_queue_active_lookup ON soc_ops.soc_triage_queue USING btree (priority, created_at DESC) WHERE (upper((triage_status)::text) <> ALL (ARRAY['CLOSED'::text, 'CLOSE'::text, 'RESOLVED'::text]));


--
-- Name: idx_soc_queue_analyst; Type: INDEX; Schema: soc_ops; Owner: -
--

CREATE INDEX idx_soc_queue_analyst ON soc_ops.soc_triage_queue USING btree (assigned_analyst) WHERE (assigned_analyst IS NOT NULL);


--
-- Name: idx_soc_queue_cooldown; Type: INDEX; Schema: soc_ops; Owner: -
--

CREATE INDEX idx_soc_queue_cooldown ON soc_ops.soc_triage_queue USING btree (priority, triage_status, cooldown_until);


--
-- Name: idx_soc_queue_status_prio; Type: INDEX; Schema: soc_ops; Owner: -
--

CREATE INDEX idx_soc_queue_status_prio ON soc_ops.soc_triage_queue USING btree (triage_status, priority, created_at);


--
-- Name: idx_soc_triage_queue_incident_id; Type: INDEX; Schema: soc_ops; Owner: -
--

CREATE INDEX idx_soc_triage_queue_incident_id ON soc_ops.soc_triage_queue USING btree (incident_id);


--
-- Name: idx_triage_cooldown; Type: INDEX; Schema: soc_ops; Owner: -
--

CREATE INDEX idx_triage_cooldown ON soc_ops.soc_triage_queue USING btree (incident_id, cooldown_until) WHERE (cooldown_until IS NOT NULL);


--
-- Name: idx_agg_alerts_actionable; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_agg_alerts_actionable ON suppression.aggregated_alerts USING btree (tenant_id, status, window_end) WHERE (((status)::text = 'ACTIONABLE'::text) AND (NOT is_suppressed));


--
-- Name: idx_agg_alerts_actor_trgm; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_agg_alerts_actor_trgm ON suppression.aggregated_alerts USING gin (actor public.gin_trgm_ops);


--
-- Name: idx_agg_alerts_actor_window; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_agg_alerts_actor_window ON suppression.aggregated_alerts USING btree (actor, window_end);


--
-- Name: idx_agg_alerts_cat_os; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_agg_alerts_cat_os ON suppression.aggregated_alerts USING btree (category, os_platform);


--
-- Name: idx_agg_alerts_category; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_agg_alerts_category ON suppression.aggregated_alerts USING btree (category);


--
-- Name: idx_agg_alerts_correlate_lookup; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_agg_alerts_correlate_lookup ON suppression.aggregated_alerts USING btree (tenant_id, window_end, actor, target);


--
-- Name: idx_agg_alerts_ioa_summary_trgm; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_agg_alerts_ioa_summary_trgm ON suppression.aggregated_alerts USING gin (ioa_summary public.gin_trgm_ops);


--
-- Name: idx_agg_alerts_os; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_agg_alerts_os ON suppression.aggregated_alerts USING btree (os_platform);


--
-- Name: idx_agg_alerts_risk_score; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_agg_alerts_risk_score ON suppression.aggregated_alerts USING btree (max_inline_risk_score DESC, ocsf_severity_id DESC NULLS LAST) WHERE ((status)::text = 'ACTIONABLE'::text);


--
-- Name: idx_agg_alerts_rule_desc_trgm; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_agg_alerts_rule_desc_trgm ON suppression.aggregated_alerts USING gin (rule_description public.gin_trgm_ops);


--
-- Name: idx_agg_alerts_suppression_rule; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_agg_alerts_suppression_rule ON suppression.aggregated_alerts USING btree (suppression_rule_id) WHERE (is_suppressed = true);


--
-- Name: idx_agg_alerts_target_trgm; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_agg_alerts_target_trgm ON suppression.aggregated_alerts USING gin (target public.gin_trgm_ops);


--
-- Name: idx_agg_alerts_target_window; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_agg_alerts_target_window ON suppression.aggregated_alerts USING btree (target, window_end);


--
-- Name: idx_agg_alerts_window_start; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_agg_alerts_window_start ON suppression.aggregated_alerts USING btree (window_start DESC);


--
-- Name: idx_aggregated_alerts_dedup; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_aggregated_alerts_dedup ON suppression.aggregated_alerts USING btree (deduplication_key, status, window_end);


--
-- Name: idx_aggregated_alerts_rule; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_aggregated_alerts_rule ON suppression.aggregated_alerts USING btree (rule_id, window_end DESC);


--
-- Name: idx_aggregated_alerts_time; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_aggregated_alerts_time ON suppression.aggregated_alerts USING btree (window_end DESC, status);


--
-- Name: idx_aggregated_alerts_window_end; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_aggregated_alerts_window_end ON suppression.aggregated_alerts USING btree (window_end);


--
-- Name: idx_cum_alerts_actor_trgm; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_cum_alerts_actor_trgm ON suppression.cumulative_alerts USING gin (actor public.gin_trgm_ops);


--
-- Name: idx_cum_alerts_cat_os; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_cum_alerts_cat_os ON suppression.cumulative_alerts USING btree (category, os_platform);


--
-- Name: idx_cum_alerts_category; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_cum_alerts_category ON suppression.cumulative_alerts USING btree (category);


--
-- Name: idx_cum_alerts_ioa_summary_trgm; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_cum_alerts_ioa_summary_trgm ON suppression.cumulative_alerts USING gin (ioa_summary public.gin_trgm_ops);


--
-- Name: idx_cum_alerts_os; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_cum_alerts_os ON suppression.cumulative_alerts USING btree (os_platform);


--
-- Name: idx_cum_alerts_rule_desc_trgm; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_cum_alerts_rule_desc_trgm ON suppression.cumulative_alerts USING gin (rule_description public.gin_trgm_ops);


--
-- Name: idx_cum_alerts_target_trgm; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_cum_alerts_target_trgm ON suppression.cumulative_alerts USING gin (target public.gin_trgm_ops);


--
-- Name: idx_cum_alerts_total_events; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_cum_alerts_total_events ON suppression.cumulative_alerts USING btree (total_event_count DESC);


--
-- Name: idx_cumulative_actor_category; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_cumulative_actor_category ON suppression.cumulative_alerts USING btree (actor, category, last_seen_at DESC);


--
-- Name: idx_cumulative_misp_export; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_cumulative_misp_export ON suppression.cumulative_alerts USING btree (source_feed, tlp_level, last_seen_at DESC) WHERE (sighting_count > 0);


--
-- Name: idx_cumulative_mitre_technique; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_cumulative_mitre_technique ON suppression.cumulative_alerts USING btree (mitre_technique_id) WHERE (mitre_technique_id IS NOT NULL);


--
-- Name: idx_cumulative_peak_risk; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_cumulative_peak_risk ON suppression.cumulative_alerts USING btree (peak_risk_score DESC) WHERE ((status)::text = 'ACTIVE'::text);


--
-- Name: idx_evidence_mapping_raw; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_evidence_mapping_raw ON suppression.aggregate_evidence_mapping USING btree (raw_event_id, event_timestamp);


--
-- Name: idx_maint_target_window; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_maint_target_window ON suppression.maintenance_windows USING btree (target_hostname, window_start, window_end) WHERE ((status)::text = 'ACTIVE'::text);


--
-- Name: idx_shared_lists_type; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_shared_lists_type ON suppression.shared_value_lists USING btree (list_type);


--
-- Name: idx_sup_groups_tenant; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_sup_groups_tenant ON suppression.suppression_groups USING btree (tenant_id, status);


--
-- Name: idx_sup_groups_type; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_sup_groups_type ON suppression.suppression_groups USING btree (group_type, status);


--
-- Name: idx_sup_rules_group; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_sup_rules_group ON suppression.suppression_rules USING btree (group_id) WHERE (group_id IS NOT NULL);


--
-- Name: idx_suppression_active; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_suppression_active ON suppression.suppression_rules USING btree (status, expires_date) WHERE ((status)::text = 'ACTIVE'::text);


--
-- Name: idx_suppression_rules_scope; Type: INDEX; Schema: suppression; Owner: -
--

CREATE INDEX idx_suppression_rules_scope ON suppression.suppression_rules USING gin (scope_definition);


--
-- Name: idx_telemetry_events_agent; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX idx_telemetry_events_agent ON ONLY telemetry.events USING btree (agent_id, tenant_id);


--
-- Name: events_2026_07_agent_id_tenant_id_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_07_agent_id_tenant_id_idx ON telemetry.events_2026_07 USING btree (agent_id, tenant_id);


--
-- Name: idx_telemetry_events_ts; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX idx_telemetry_events_ts ON ONLY telemetry.events USING btree (event_timestamp DESC);


--
-- Name: events_2026_07_event_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_07_event_timestamp_idx ON telemetry.events_2026_07 USING btree (event_timestamp DESC);


--
-- Name: idx_telemetry_events_payload_gin; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX idx_telemetry_events_payload_gin ON ONLY telemetry.events USING gin (raw_payload jsonb_path_ops);


--
-- Name: events_2026_07_raw_payload_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_07_raw_payload_idx ON telemetry.events_2026_07 USING gin (raw_payload jsonb_path_ops);


--
-- Name: idx_telemetry_events_rule; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX idx_telemetry_events_rule ON ONLY telemetry.events USING btree (rule_id, rule_level);


--
-- Name: events_2026_07_rule_id_rule_level_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_07_rule_id_rule_level_idx ON telemetry.events_2026_07 USING btree (rule_id, rule_level);


--
-- Name: idx_telemetry_events_src_ip; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX idx_telemetry_events_src_ip ON ONLY telemetry.events USING btree (source_ip) WHERE (source_ip IS NOT NULL);


--
-- Name: events_2026_07_source_ip_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_07_source_ip_idx ON telemetry.events_2026_07 USING btree (source_ip) WHERE (source_ip IS NOT NULL);


--
-- Name: idx_telemetry_events_username; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX idx_telemetry_events_username ON ONLY telemetry.events USING btree (username) WHERE (username IS NOT NULL);


--
-- Name: events_2026_07_username_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_07_username_idx ON telemetry.events_2026_07 USING btree (username) WHERE (username IS NOT NULL);


--
-- Name: events_2026_08_agent_id_tenant_id_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_08_agent_id_tenant_id_idx ON telemetry.events_2026_08 USING btree (agent_id, tenant_id);


--
-- Name: events_2026_08_event_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_08_event_timestamp_idx ON telemetry.events_2026_08 USING btree (event_timestamp DESC);


--
-- Name: events_2026_08_raw_payload_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_08_raw_payload_idx ON telemetry.events_2026_08 USING gin (raw_payload jsonb_path_ops);


--
-- Name: events_2026_08_rule_id_rule_level_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_08_rule_id_rule_level_idx ON telemetry.events_2026_08 USING btree (rule_id, rule_level);


--
-- Name: events_2026_08_source_ip_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_08_source_ip_idx ON telemetry.events_2026_08 USING btree (source_ip) WHERE (source_ip IS NOT NULL);


--
-- Name: events_2026_08_username_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_08_username_idx ON telemetry.events_2026_08 USING btree (username) WHERE (username IS NOT NULL);


--
-- Name: events_2026_09_agent_id_tenant_id_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_09_agent_id_tenant_id_idx ON telemetry.events_2026_09 USING btree (agent_id, tenant_id);


--
-- Name: events_2026_09_event_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_09_event_timestamp_idx ON telemetry.events_2026_09 USING btree (event_timestamp DESC);


--
-- Name: events_2026_09_raw_payload_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_09_raw_payload_idx ON telemetry.events_2026_09 USING gin (raw_payload jsonb_path_ops);


--
-- Name: events_2026_09_rule_id_rule_level_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_09_rule_id_rule_level_idx ON telemetry.events_2026_09 USING btree (rule_id, rule_level);


--
-- Name: events_2026_09_source_ip_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_09_source_ip_idx ON telemetry.events_2026_09 USING btree (source_ip) WHERE (source_ip IS NOT NULL);


--
-- Name: events_2026_09_username_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_09_username_idx ON telemetry.events_2026_09 USING btree (username) WHERE (username IS NOT NULL);


--
-- Name: events_2026_10_agent_id_tenant_id_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_10_agent_id_tenant_id_idx ON telemetry.events_2026_10 USING btree (agent_id, tenant_id);


--
-- Name: events_2026_10_event_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_10_event_timestamp_idx ON telemetry.events_2026_10 USING btree (event_timestamp DESC);


--
-- Name: events_2026_10_raw_payload_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_10_raw_payload_idx ON telemetry.events_2026_10 USING gin (raw_payload jsonb_path_ops);


--
-- Name: events_2026_10_rule_id_rule_level_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_10_rule_id_rule_level_idx ON telemetry.events_2026_10 USING btree (rule_id, rule_level);


--
-- Name: events_2026_10_source_ip_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_10_source_ip_idx ON telemetry.events_2026_10 USING btree (source_ip) WHERE (source_ip IS NOT NULL);


--
-- Name: events_2026_10_username_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_10_username_idx ON telemetry.events_2026_10 USING btree (username) WHERE (username IS NOT NULL);


--
-- Name: events_2026_11_agent_id_tenant_id_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_11_agent_id_tenant_id_idx ON telemetry.events_2026_11 USING btree (agent_id, tenant_id);


--
-- Name: events_2026_11_event_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_11_event_timestamp_idx ON telemetry.events_2026_11 USING btree (event_timestamp DESC);


--
-- Name: events_2026_11_raw_payload_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_11_raw_payload_idx ON telemetry.events_2026_11 USING gin (raw_payload jsonb_path_ops);


--
-- Name: events_2026_11_rule_id_rule_level_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_11_rule_id_rule_level_idx ON telemetry.events_2026_11 USING btree (rule_id, rule_level);


--
-- Name: events_2026_11_source_ip_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_11_source_ip_idx ON telemetry.events_2026_11 USING btree (source_ip) WHERE (source_ip IS NOT NULL);


--
-- Name: events_2026_11_username_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_11_username_idx ON telemetry.events_2026_11 USING btree (username) WHERE (username IS NOT NULL);


--
-- Name: events_2026_12_agent_id_tenant_id_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_12_agent_id_tenant_id_idx ON telemetry.events_2026_12 USING btree (agent_id, tenant_id);


--
-- Name: events_2026_12_event_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_12_event_timestamp_idx ON telemetry.events_2026_12 USING btree (event_timestamp DESC);


--
-- Name: events_2026_12_raw_payload_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_12_raw_payload_idx ON telemetry.events_2026_12 USING gin (raw_payload jsonb_path_ops);


--
-- Name: events_2026_12_rule_id_rule_level_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_12_rule_id_rule_level_idx ON telemetry.events_2026_12 USING btree (rule_id, rule_level);


--
-- Name: events_2026_12_source_ip_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_12_source_ip_idx ON telemetry.events_2026_12 USING btree (source_ip) WHERE (source_ip IS NOT NULL);


--
-- Name: events_2026_12_username_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2026_12_username_idx ON telemetry.events_2026_12 USING btree (username) WHERE (username IS NOT NULL);


--
-- Name: events_2027_01_agent_id_tenant_id_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2027_01_agent_id_tenant_id_idx ON telemetry.events_2027_01 USING btree (agent_id, tenant_id);


--
-- Name: events_2027_01_event_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2027_01_event_timestamp_idx ON telemetry.events_2027_01 USING btree (event_timestamp DESC);


--
-- Name: events_2027_01_raw_payload_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2027_01_raw_payload_idx ON telemetry.events_2027_01 USING gin (raw_payload jsonb_path_ops);


--
-- Name: events_2027_01_rule_id_rule_level_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2027_01_rule_id_rule_level_idx ON telemetry.events_2027_01 USING btree (rule_id, rule_level);


--
-- Name: events_2027_01_source_ip_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2027_01_source_ip_idx ON telemetry.events_2027_01 USING btree (source_ip) WHERE (source_ip IS NOT NULL);


--
-- Name: events_2027_01_username_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_2027_01_username_idx ON telemetry.events_2027_01 USING btree (username) WHERE (username IS NOT NULL);


--
-- Name: events_default_agent_id_tenant_id_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_default_agent_id_tenant_id_idx ON telemetry.events_default USING btree (agent_id, tenant_id);


--
-- Name: events_default_event_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_default_event_timestamp_idx ON telemetry.events_default USING btree (event_timestamp DESC);


--
-- Name: events_default_raw_payload_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_default_raw_payload_idx ON telemetry.events_default USING gin (raw_payload jsonb_path_ops);


--
-- Name: events_default_rule_id_rule_level_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_default_rule_id_rule_level_idx ON telemetry.events_default USING btree (rule_id, rule_level);


--
-- Name: events_default_source_ip_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_default_source_ip_idx ON telemetry.events_default USING btree (source_ip) WHERE (source_ip IS NOT NULL);


--
-- Name: events_default_username_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX events_default_username_idx ON telemetry.events_default USING btree (username) WHERE (username IS NOT NULL);


--
-- Name: idx_ingest_checkpoints_ts; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX idx_ingest_checkpoints_ts ON telemetry.ingest_checkpoints USING btree (last_timestamp);


--
-- Name: idx_norm_events_2026_07_raw_event_id; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX idx_norm_events_2026_07_raw_event_id ON telemetry.normalized_events_2026_07 USING btree (raw_event_id);


--
-- Name: idx_norm_events_raw_event_id; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX idx_norm_events_raw_event_id ON ONLY telemetry.normalized_events USING btree (raw_event_id);


--
-- Name: idx_norm_events_2026_08_raw_event_id; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX idx_norm_events_2026_08_raw_event_id ON telemetry.normalized_events_2026_08 USING btree (raw_event_id);


--
-- Name: idx_norm_events_2026_09_raw_event_id; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX idx_norm_events_2026_09_raw_event_id ON telemetry.normalized_events_2026_09 USING btree (raw_event_id);


--
-- Name: idx_norm_events_2026_10_raw_event_id; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX idx_norm_events_2026_10_raw_event_id ON telemetry.normalized_events_2026_10 USING btree (raw_event_id);


--
-- Name: idx_norm_events_default_raw_event_id; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX idx_norm_events_default_raw_event_id ON telemetry.normalized_events_default USING btree (raw_event_id);


--
-- Name: idx_norm_events_groups; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX idx_norm_events_groups ON ONLY telemetry.normalized_events USING gin (classification_groups);


--
-- Name: idx_norm_events_mitre; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX idx_norm_events_mitre ON ONLY telemetry.normalized_events USING gin (mitre_attack_ids);


--
-- Name: idx_norm_events_rule_level; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX idx_norm_events_rule_level ON ONLY telemetry.normalized_events USING btree (rule_level, rule_id);


--
-- Name: idx_norm_events_tactics; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX idx_norm_events_tactics ON ONLY telemetry.normalized_events USING gin (mitre_tactics);


--
-- Name: idx_normalized_events_timestamp; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX idx_normalized_events_timestamp ON ONLY telemetry.normalized_events USING btree (event_timestamp);


--
-- Name: idx_raw_events_2026_07_agent_id; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX idx_raw_events_2026_07_agent_id ON telemetry.raw_events_2026_07 USING btree (agent_id);


--
-- Name: idx_raw_events_2026_08_agent_id; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX idx_raw_events_2026_08_agent_id ON telemetry.raw_events_2026_08 USING btree (agent_id);


--
-- Name: idx_raw_events_ingested_at; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX idx_raw_events_ingested_at ON ONLY telemetry.raw_events USING btree (ingested_at DESC);


--
-- Name: idx_raw_events_src_ip; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX idx_raw_events_src_ip ON ONLY telemetry.raw_events USING btree (source_ip) WHERE (source_ip IS NOT NULL);


--
-- Name: idx_raw_events_tenant_time; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX idx_raw_events_tenant_time ON ONLY telemetry.raw_events USING btree (tenant_id, "timestamp" DESC);


--
-- Name: idx_raw_events_timestamp; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX idx_raw_events_timestamp ON ONLY telemetry.raw_events USING btree ("timestamp");


--
-- Name: idx_raw_events_timestamp_desc; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX idx_raw_events_timestamp_desc ON ONLY telemetry.raw_events USING btree ("timestamp" DESC);


--
-- Name: normalized_events_2026_07_classification_groups_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_07_classification_groups_idx ON telemetry.normalized_events_2026_07 USING gin (classification_groups);


--
-- Name: normalized_events_2026_07_event_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_07_event_timestamp_idx ON telemetry.normalized_events_2026_07 USING btree (event_timestamp);


--
-- Name: normalized_events_2026_07_mitre_attack_ids_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_07_mitre_attack_ids_idx ON telemetry.normalized_events_2026_07 USING gin (mitre_attack_ids);


--
-- Name: normalized_events_2026_07_mitre_tactics_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_07_mitre_tactics_idx ON telemetry.normalized_events_2026_07 USING gin (mitre_tactics);


--
-- Name: normalized_events_2026_07_raw_event_id_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_07_raw_event_id_idx ON telemetry.normalized_events_2026_07 USING btree (raw_event_id);


--
-- Name: normalized_events_2026_07_rule_level_rule_id_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_07_rule_level_rule_id_idx ON telemetry.normalized_events_2026_07 USING btree (rule_level, rule_id);


--
-- Name: normalized_events_2026_08_classification_groups_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_08_classification_groups_idx ON telemetry.normalized_events_2026_08 USING gin (classification_groups);


--
-- Name: normalized_events_2026_08_event_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_08_event_timestamp_idx ON telemetry.normalized_events_2026_08 USING btree (event_timestamp);


--
-- Name: normalized_events_2026_08_mitre_attack_ids_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_08_mitre_attack_ids_idx ON telemetry.normalized_events_2026_08 USING gin (mitre_attack_ids);


--
-- Name: normalized_events_2026_08_mitre_tactics_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_08_mitre_tactics_idx ON telemetry.normalized_events_2026_08 USING gin (mitre_tactics);


--
-- Name: normalized_events_2026_08_rule_level_rule_id_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_08_rule_level_rule_id_idx ON telemetry.normalized_events_2026_08 USING btree (rule_level, rule_id);


--
-- Name: normalized_events_2026_09_classification_groups_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_09_classification_groups_idx ON telemetry.normalized_events_2026_09 USING gin (classification_groups);


--
-- Name: normalized_events_2026_09_event_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_09_event_timestamp_idx ON telemetry.normalized_events_2026_09 USING btree (event_timestamp);


--
-- Name: normalized_events_2026_09_mitre_attack_ids_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_09_mitre_attack_ids_idx ON telemetry.normalized_events_2026_09 USING gin (mitre_attack_ids);


--
-- Name: normalized_events_2026_09_mitre_tactics_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_09_mitre_tactics_idx ON telemetry.normalized_events_2026_09 USING gin (mitre_tactics);


--
-- Name: normalized_events_2026_09_rule_level_rule_id_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_09_rule_level_rule_id_idx ON telemetry.normalized_events_2026_09 USING btree (rule_level, rule_id);


--
-- Name: normalized_events_2026_10_classification_groups_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_10_classification_groups_idx ON telemetry.normalized_events_2026_10 USING gin (classification_groups);


--
-- Name: normalized_events_2026_10_event_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_10_event_timestamp_idx ON telemetry.normalized_events_2026_10 USING btree (event_timestamp);


--
-- Name: normalized_events_2026_10_mitre_attack_ids_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_10_mitre_attack_ids_idx ON telemetry.normalized_events_2026_10 USING gin (mitre_attack_ids);


--
-- Name: normalized_events_2026_10_mitre_tactics_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_10_mitre_tactics_idx ON telemetry.normalized_events_2026_10 USING gin (mitre_tactics);


--
-- Name: normalized_events_2026_10_rule_level_rule_id_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_10_rule_level_rule_id_idx ON telemetry.normalized_events_2026_10 USING btree (rule_level, rule_id);


--
-- Name: normalized_events_2026_12_classification_groups_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_12_classification_groups_idx ON telemetry.normalized_events_2026_12 USING gin (classification_groups);


--
-- Name: normalized_events_2026_12_event_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_12_event_timestamp_idx ON telemetry.normalized_events_2026_12 USING btree (event_timestamp);


--
-- Name: normalized_events_2026_12_mitre_attack_ids_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_12_mitre_attack_ids_idx ON telemetry.normalized_events_2026_12 USING gin (mitre_attack_ids);


--
-- Name: normalized_events_2026_12_mitre_tactics_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_12_mitre_tactics_idx ON telemetry.normalized_events_2026_12 USING gin (mitre_tactics);


--
-- Name: normalized_events_2026_12_raw_event_id_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_12_raw_event_id_idx ON telemetry.normalized_events_2026_12 USING btree (raw_event_id);


--
-- Name: normalized_events_2026_12_rule_level_rule_id_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2026_12_rule_level_rule_id_idx ON telemetry.normalized_events_2026_12 USING btree (rule_level, rule_id);


--
-- Name: normalized_events_2027_01_classification_groups_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2027_01_classification_groups_idx ON telemetry.normalized_events_2027_01 USING gin (classification_groups);


--
-- Name: normalized_events_2027_01_event_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2027_01_event_timestamp_idx ON telemetry.normalized_events_2027_01 USING btree (event_timestamp);


--
-- Name: normalized_events_2027_01_mitre_attack_ids_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2027_01_mitre_attack_ids_idx ON telemetry.normalized_events_2027_01 USING gin (mitre_attack_ids);


--
-- Name: normalized_events_2027_01_mitre_tactics_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2027_01_mitre_tactics_idx ON telemetry.normalized_events_2027_01 USING gin (mitre_tactics);


--
-- Name: normalized_events_2027_01_raw_event_id_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2027_01_raw_event_id_idx ON telemetry.normalized_events_2027_01 USING btree (raw_event_id);


--
-- Name: normalized_events_2027_01_rule_level_rule_id_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_2027_01_rule_level_rule_id_idx ON telemetry.normalized_events_2027_01 USING btree (rule_level, rule_id);


--
-- Name: normalized_events_default_classification_groups_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_default_classification_groups_idx ON telemetry.normalized_events_default USING gin (classification_groups);


--
-- Name: normalized_events_default_event_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_default_event_timestamp_idx ON telemetry.normalized_events_default USING btree (event_timestamp);


--
-- Name: normalized_events_default_mitre_attack_ids_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_default_mitre_attack_ids_idx ON telemetry.normalized_events_default USING gin (mitre_attack_ids);


--
-- Name: normalized_events_default_mitre_tactics_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_default_mitre_tactics_idx ON telemetry.normalized_events_default USING gin (mitre_tactics);


--
-- Name: normalized_events_default_rule_level_rule_id_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX normalized_events_default_rule_level_rule_id_idx ON telemetry.normalized_events_default USING btree (rule_level, rule_id);


--
-- Name: raw_events_2026_07_ingested_at_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2026_07_ingested_at_idx ON telemetry.raw_events_2026_07 USING btree (ingested_at DESC);


--
-- Name: raw_events_2026_07_source_ip_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2026_07_source_ip_idx ON telemetry.raw_events_2026_07 USING btree (source_ip) WHERE (source_ip IS NOT NULL);


--
-- Name: raw_events_2026_07_tenant_id_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2026_07_tenant_id_timestamp_idx ON telemetry.raw_events_2026_07 USING btree (tenant_id, "timestamp" DESC);


--
-- Name: raw_events_2026_07_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2026_07_timestamp_idx ON telemetry.raw_events_2026_07 USING btree ("timestamp" DESC);


--
-- Name: raw_events_2026_07_timestamp_idx1; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2026_07_timestamp_idx1 ON telemetry.raw_events_2026_07 USING btree ("timestamp");


--
-- Name: raw_events_2026_08_ingested_at_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2026_08_ingested_at_idx ON telemetry.raw_events_2026_08 USING btree (ingested_at DESC);


--
-- Name: raw_events_2026_08_source_ip_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2026_08_source_ip_idx ON telemetry.raw_events_2026_08 USING btree (source_ip) WHERE (source_ip IS NOT NULL);


--
-- Name: raw_events_2026_08_tenant_id_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2026_08_tenant_id_timestamp_idx ON telemetry.raw_events_2026_08 USING btree (tenant_id, "timestamp" DESC);


--
-- Name: raw_events_2026_08_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2026_08_timestamp_idx ON telemetry.raw_events_2026_08 USING btree ("timestamp" DESC);


--
-- Name: raw_events_2026_08_timestamp_idx1; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2026_08_timestamp_idx1 ON telemetry.raw_events_2026_08 USING btree ("timestamp");


--
-- Name: raw_events_2026_09_ingested_at_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2026_09_ingested_at_idx ON telemetry.raw_events_2026_09 USING btree (ingested_at DESC);


--
-- Name: raw_events_2026_09_source_ip_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2026_09_source_ip_idx ON telemetry.raw_events_2026_09 USING btree (source_ip) WHERE (source_ip IS NOT NULL);


--
-- Name: raw_events_2026_09_tenant_id_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2026_09_tenant_id_timestamp_idx ON telemetry.raw_events_2026_09 USING btree (tenant_id, "timestamp" DESC);


--
-- Name: raw_events_2026_09_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2026_09_timestamp_idx ON telemetry.raw_events_2026_09 USING btree ("timestamp" DESC);


--
-- Name: raw_events_2026_09_timestamp_idx1; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2026_09_timestamp_idx1 ON telemetry.raw_events_2026_09 USING btree ("timestamp");


--
-- Name: raw_events_2026_10_ingested_at_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2026_10_ingested_at_idx ON telemetry.raw_events_2026_10 USING btree (ingested_at DESC);


--
-- Name: raw_events_2026_10_source_ip_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2026_10_source_ip_idx ON telemetry.raw_events_2026_10 USING btree (source_ip) WHERE (source_ip IS NOT NULL);


--
-- Name: raw_events_2026_10_tenant_id_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2026_10_tenant_id_timestamp_idx ON telemetry.raw_events_2026_10 USING btree (tenant_id, "timestamp" DESC);


--
-- Name: raw_events_2026_10_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2026_10_timestamp_idx ON telemetry.raw_events_2026_10 USING btree ("timestamp" DESC);


--
-- Name: raw_events_2026_10_timestamp_idx1; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2026_10_timestamp_idx1 ON telemetry.raw_events_2026_10 USING btree ("timestamp");


--
-- Name: raw_events_2026_12_ingested_at_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2026_12_ingested_at_idx ON telemetry.raw_events_2026_12 USING btree (ingested_at DESC);


--
-- Name: raw_events_2026_12_source_ip_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2026_12_source_ip_idx ON telemetry.raw_events_2026_12 USING btree (source_ip) WHERE (source_ip IS NOT NULL);


--
-- Name: raw_events_2026_12_tenant_id_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2026_12_tenant_id_timestamp_idx ON telemetry.raw_events_2026_12 USING btree (tenant_id, "timestamp" DESC);


--
-- Name: raw_events_2026_12_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2026_12_timestamp_idx ON telemetry.raw_events_2026_12 USING btree ("timestamp" DESC);


--
-- Name: raw_events_2026_12_timestamp_idx1; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2026_12_timestamp_idx1 ON telemetry.raw_events_2026_12 USING btree ("timestamp");


--
-- Name: raw_events_2027_01_ingested_at_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2027_01_ingested_at_idx ON telemetry.raw_events_2027_01 USING btree (ingested_at DESC);


--
-- Name: raw_events_2027_01_source_ip_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2027_01_source_ip_idx ON telemetry.raw_events_2027_01 USING btree (source_ip) WHERE (source_ip IS NOT NULL);


--
-- Name: raw_events_2027_01_tenant_id_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2027_01_tenant_id_timestamp_idx ON telemetry.raw_events_2027_01 USING btree (tenant_id, "timestamp" DESC);


--
-- Name: raw_events_2027_01_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2027_01_timestamp_idx ON telemetry.raw_events_2027_01 USING btree ("timestamp" DESC);


--
-- Name: raw_events_2027_01_timestamp_idx1; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_2027_01_timestamp_idx1 ON telemetry.raw_events_2027_01 USING btree ("timestamp");


--
-- Name: raw_events_default_ingested_at_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_default_ingested_at_idx ON telemetry.raw_events_default USING btree (ingested_at DESC);


--
-- Name: raw_events_default_source_ip_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_default_source_ip_idx ON telemetry.raw_events_default USING btree (source_ip) WHERE (source_ip IS NOT NULL);


--
-- Name: raw_events_default_tenant_id_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_default_tenant_id_timestamp_idx ON telemetry.raw_events_default USING btree (tenant_id, "timestamp" DESC);


--
-- Name: raw_events_default_timestamp_idx; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_default_timestamp_idx ON telemetry.raw_events_default USING btree ("timestamp" DESC);


--
-- Name: raw_events_default_timestamp_idx1; Type: INDEX; Schema: telemetry; Owner: -
--

CREATE INDEX raw_events_default_timestamp_idx1 ON telemetry.raw_events_default USING btree ("timestamp");


--
-- Name: events_2026_07_agent_id_tenant_id_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_agent ATTACH PARTITION telemetry.events_2026_07_agent_id_tenant_id_idx;


--
-- Name: events_2026_07_event_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_ts ATTACH PARTITION telemetry.events_2026_07_event_timestamp_idx;


--
-- Name: events_2026_07_pkey; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.pk_telemetry_events ATTACH PARTITION telemetry.events_2026_07_pkey;


--
-- Name: events_2026_07_raw_payload_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_payload_gin ATTACH PARTITION telemetry.events_2026_07_raw_payload_idx;


--
-- Name: events_2026_07_rule_id_rule_level_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_rule ATTACH PARTITION telemetry.events_2026_07_rule_id_rule_level_idx;


--
-- Name: events_2026_07_source_ip_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_src_ip ATTACH PARTITION telemetry.events_2026_07_source_ip_idx;


--
-- Name: events_2026_07_username_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_username ATTACH PARTITION telemetry.events_2026_07_username_idx;


--
-- Name: events_2026_08_agent_id_tenant_id_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_agent ATTACH PARTITION telemetry.events_2026_08_agent_id_tenant_id_idx;


--
-- Name: events_2026_08_event_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_ts ATTACH PARTITION telemetry.events_2026_08_event_timestamp_idx;


--
-- Name: events_2026_08_pkey; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.pk_telemetry_events ATTACH PARTITION telemetry.events_2026_08_pkey;


--
-- Name: events_2026_08_raw_payload_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_payload_gin ATTACH PARTITION telemetry.events_2026_08_raw_payload_idx;


--
-- Name: events_2026_08_rule_id_rule_level_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_rule ATTACH PARTITION telemetry.events_2026_08_rule_id_rule_level_idx;


--
-- Name: events_2026_08_source_ip_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_src_ip ATTACH PARTITION telemetry.events_2026_08_source_ip_idx;


--
-- Name: events_2026_08_username_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_username ATTACH PARTITION telemetry.events_2026_08_username_idx;


--
-- Name: events_2026_09_agent_id_tenant_id_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_agent ATTACH PARTITION telemetry.events_2026_09_agent_id_tenant_id_idx;


--
-- Name: events_2026_09_event_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_ts ATTACH PARTITION telemetry.events_2026_09_event_timestamp_idx;


--
-- Name: events_2026_09_pkey; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.pk_telemetry_events ATTACH PARTITION telemetry.events_2026_09_pkey;


--
-- Name: events_2026_09_raw_payload_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_payload_gin ATTACH PARTITION telemetry.events_2026_09_raw_payload_idx;


--
-- Name: events_2026_09_rule_id_rule_level_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_rule ATTACH PARTITION telemetry.events_2026_09_rule_id_rule_level_idx;


--
-- Name: events_2026_09_source_ip_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_src_ip ATTACH PARTITION telemetry.events_2026_09_source_ip_idx;


--
-- Name: events_2026_09_username_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_username ATTACH PARTITION telemetry.events_2026_09_username_idx;


--
-- Name: events_2026_10_agent_id_tenant_id_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_agent ATTACH PARTITION telemetry.events_2026_10_agent_id_tenant_id_idx;


--
-- Name: events_2026_10_event_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_ts ATTACH PARTITION telemetry.events_2026_10_event_timestamp_idx;


--
-- Name: events_2026_10_pkey; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.pk_telemetry_events ATTACH PARTITION telemetry.events_2026_10_pkey;


--
-- Name: events_2026_10_raw_payload_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_payload_gin ATTACH PARTITION telemetry.events_2026_10_raw_payload_idx;


--
-- Name: events_2026_10_rule_id_rule_level_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_rule ATTACH PARTITION telemetry.events_2026_10_rule_id_rule_level_idx;


--
-- Name: events_2026_10_source_ip_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_src_ip ATTACH PARTITION telemetry.events_2026_10_source_ip_idx;


--
-- Name: events_2026_10_username_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_username ATTACH PARTITION telemetry.events_2026_10_username_idx;


--
-- Name: events_2026_11_agent_id_tenant_id_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_agent ATTACH PARTITION telemetry.events_2026_11_agent_id_tenant_id_idx;


--
-- Name: events_2026_11_event_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_ts ATTACH PARTITION telemetry.events_2026_11_event_timestamp_idx;


--
-- Name: events_2026_11_pkey; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.pk_telemetry_events ATTACH PARTITION telemetry.events_2026_11_pkey;


--
-- Name: events_2026_11_raw_payload_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_payload_gin ATTACH PARTITION telemetry.events_2026_11_raw_payload_idx;


--
-- Name: events_2026_11_rule_id_rule_level_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_rule ATTACH PARTITION telemetry.events_2026_11_rule_id_rule_level_idx;


--
-- Name: events_2026_11_source_ip_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_src_ip ATTACH PARTITION telemetry.events_2026_11_source_ip_idx;


--
-- Name: events_2026_11_username_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_username ATTACH PARTITION telemetry.events_2026_11_username_idx;


--
-- Name: events_2026_12_agent_id_tenant_id_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_agent ATTACH PARTITION telemetry.events_2026_12_agent_id_tenant_id_idx;


--
-- Name: events_2026_12_event_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_ts ATTACH PARTITION telemetry.events_2026_12_event_timestamp_idx;


--
-- Name: events_2026_12_pkey; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.pk_telemetry_events ATTACH PARTITION telemetry.events_2026_12_pkey;


--
-- Name: events_2026_12_raw_payload_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_payload_gin ATTACH PARTITION telemetry.events_2026_12_raw_payload_idx;


--
-- Name: events_2026_12_rule_id_rule_level_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_rule ATTACH PARTITION telemetry.events_2026_12_rule_id_rule_level_idx;


--
-- Name: events_2026_12_source_ip_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_src_ip ATTACH PARTITION telemetry.events_2026_12_source_ip_idx;


--
-- Name: events_2026_12_username_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_username ATTACH PARTITION telemetry.events_2026_12_username_idx;


--
-- Name: events_2027_01_agent_id_tenant_id_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_agent ATTACH PARTITION telemetry.events_2027_01_agent_id_tenant_id_idx;


--
-- Name: events_2027_01_event_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_ts ATTACH PARTITION telemetry.events_2027_01_event_timestamp_idx;


--
-- Name: events_2027_01_pkey; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.pk_telemetry_events ATTACH PARTITION telemetry.events_2027_01_pkey;


--
-- Name: events_2027_01_raw_payload_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_payload_gin ATTACH PARTITION telemetry.events_2027_01_raw_payload_idx;


--
-- Name: events_2027_01_rule_id_rule_level_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_rule ATTACH PARTITION telemetry.events_2027_01_rule_id_rule_level_idx;


--
-- Name: events_2027_01_source_ip_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_src_ip ATTACH PARTITION telemetry.events_2027_01_source_ip_idx;


--
-- Name: events_2027_01_username_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_username ATTACH PARTITION telemetry.events_2027_01_username_idx;


--
-- Name: events_default_agent_id_tenant_id_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_agent ATTACH PARTITION telemetry.events_default_agent_id_tenant_id_idx;


--
-- Name: events_default_event_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_ts ATTACH PARTITION telemetry.events_default_event_timestamp_idx;


--
-- Name: events_default_pkey; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.pk_telemetry_events ATTACH PARTITION telemetry.events_default_pkey;


--
-- Name: events_default_raw_payload_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_payload_gin ATTACH PARTITION telemetry.events_default_raw_payload_idx;


--
-- Name: events_default_rule_id_rule_level_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_rule ATTACH PARTITION telemetry.events_default_rule_id_rule_level_idx;


--
-- Name: events_default_source_ip_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_src_ip ATTACH PARTITION telemetry.events_default_source_ip_idx;


--
-- Name: events_default_username_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_telemetry_events_username ATTACH PARTITION telemetry.events_default_username_idx;


--
-- Name: idx_norm_events_2026_08_raw_event_id; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_raw_event_id ATTACH PARTITION telemetry.idx_norm_events_2026_08_raw_event_id;


--
-- Name: idx_norm_events_2026_09_raw_event_id; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_raw_event_id ATTACH PARTITION telemetry.idx_norm_events_2026_09_raw_event_id;


--
-- Name: idx_norm_events_2026_10_raw_event_id; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_raw_event_id ATTACH PARTITION telemetry.idx_norm_events_2026_10_raw_event_id;


--
-- Name: idx_norm_events_default_raw_event_id; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_raw_event_id ATTACH PARTITION telemetry.idx_norm_events_default_raw_event_id;


--
-- Name: normalized_events_2026_07_classification_groups_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_groups ATTACH PARTITION telemetry.normalized_events_2026_07_classification_groups_idx;


--
-- Name: normalized_events_2026_07_event_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_normalized_events_timestamp ATTACH PARTITION telemetry.normalized_events_2026_07_event_timestamp_idx;


--
-- Name: normalized_events_2026_07_mitre_attack_ids_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_mitre ATTACH PARTITION telemetry.normalized_events_2026_07_mitre_attack_ids_idx;


--
-- Name: normalized_events_2026_07_mitre_tactics_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_tactics ATTACH PARTITION telemetry.normalized_events_2026_07_mitre_tactics_idx;


--
-- Name: normalized_events_2026_07_pkey; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.pk_normalized_events ATTACH PARTITION telemetry.normalized_events_2026_07_pkey;


--
-- Name: normalized_events_2026_07_raw_event_id_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_raw_event_id ATTACH PARTITION telemetry.normalized_events_2026_07_raw_event_id_idx;


--
-- Name: normalized_events_2026_07_rule_level_rule_id_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_rule_level ATTACH PARTITION telemetry.normalized_events_2026_07_rule_level_rule_id_idx;


--
-- Name: normalized_events_2026_08_classification_groups_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_groups ATTACH PARTITION telemetry.normalized_events_2026_08_classification_groups_idx;


--
-- Name: normalized_events_2026_08_event_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_normalized_events_timestamp ATTACH PARTITION telemetry.normalized_events_2026_08_event_timestamp_idx;


--
-- Name: normalized_events_2026_08_mitre_attack_ids_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_mitre ATTACH PARTITION telemetry.normalized_events_2026_08_mitre_attack_ids_idx;


--
-- Name: normalized_events_2026_08_mitre_tactics_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_tactics ATTACH PARTITION telemetry.normalized_events_2026_08_mitre_tactics_idx;


--
-- Name: normalized_events_2026_08_pkey; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.pk_normalized_events ATTACH PARTITION telemetry.normalized_events_2026_08_pkey;


--
-- Name: normalized_events_2026_08_rule_level_rule_id_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_rule_level ATTACH PARTITION telemetry.normalized_events_2026_08_rule_level_rule_id_idx;


--
-- Name: normalized_events_2026_09_classification_groups_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_groups ATTACH PARTITION telemetry.normalized_events_2026_09_classification_groups_idx;


--
-- Name: normalized_events_2026_09_event_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_normalized_events_timestamp ATTACH PARTITION telemetry.normalized_events_2026_09_event_timestamp_idx;


--
-- Name: normalized_events_2026_09_mitre_attack_ids_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_mitre ATTACH PARTITION telemetry.normalized_events_2026_09_mitre_attack_ids_idx;


--
-- Name: normalized_events_2026_09_mitre_tactics_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_tactics ATTACH PARTITION telemetry.normalized_events_2026_09_mitre_tactics_idx;


--
-- Name: normalized_events_2026_09_pkey; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.pk_normalized_events ATTACH PARTITION telemetry.normalized_events_2026_09_pkey;


--
-- Name: normalized_events_2026_09_rule_level_rule_id_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_rule_level ATTACH PARTITION telemetry.normalized_events_2026_09_rule_level_rule_id_idx;


--
-- Name: normalized_events_2026_10_classification_groups_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_groups ATTACH PARTITION telemetry.normalized_events_2026_10_classification_groups_idx;


--
-- Name: normalized_events_2026_10_event_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_normalized_events_timestamp ATTACH PARTITION telemetry.normalized_events_2026_10_event_timestamp_idx;


--
-- Name: normalized_events_2026_10_mitre_attack_ids_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_mitre ATTACH PARTITION telemetry.normalized_events_2026_10_mitre_attack_ids_idx;


--
-- Name: normalized_events_2026_10_mitre_tactics_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_tactics ATTACH PARTITION telemetry.normalized_events_2026_10_mitre_tactics_idx;


--
-- Name: normalized_events_2026_10_pkey; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.pk_normalized_events ATTACH PARTITION telemetry.normalized_events_2026_10_pkey;


--
-- Name: normalized_events_2026_10_rule_level_rule_id_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_rule_level ATTACH PARTITION telemetry.normalized_events_2026_10_rule_level_rule_id_idx;


--
-- Name: normalized_events_2026_12_classification_groups_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_groups ATTACH PARTITION telemetry.normalized_events_2026_12_classification_groups_idx;


--
-- Name: normalized_events_2026_12_event_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_normalized_events_timestamp ATTACH PARTITION telemetry.normalized_events_2026_12_event_timestamp_idx;


--
-- Name: normalized_events_2026_12_mitre_attack_ids_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_mitre ATTACH PARTITION telemetry.normalized_events_2026_12_mitre_attack_ids_idx;


--
-- Name: normalized_events_2026_12_mitre_tactics_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_tactics ATTACH PARTITION telemetry.normalized_events_2026_12_mitre_tactics_idx;


--
-- Name: normalized_events_2026_12_pkey; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.pk_normalized_events ATTACH PARTITION telemetry.normalized_events_2026_12_pkey;


--
-- Name: normalized_events_2026_12_raw_event_id_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_raw_event_id ATTACH PARTITION telemetry.normalized_events_2026_12_raw_event_id_idx;


--
-- Name: normalized_events_2026_12_rule_level_rule_id_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_rule_level ATTACH PARTITION telemetry.normalized_events_2026_12_rule_level_rule_id_idx;


--
-- Name: normalized_events_2027_01_classification_groups_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_groups ATTACH PARTITION telemetry.normalized_events_2027_01_classification_groups_idx;


--
-- Name: normalized_events_2027_01_event_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_normalized_events_timestamp ATTACH PARTITION telemetry.normalized_events_2027_01_event_timestamp_idx;


--
-- Name: normalized_events_2027_01_mitre_attack_ids_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_mitre ATTACH PARTITION telemetry.normalized_events_2027_01_mitre_attack_ids_idx;


--
-- Name: normalized_events_2027_01_mitre_tactics_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_tactics ATTACH PARTITION telemetry.normalized_events_2027_01_mitre_tactics_idx;


--
-- Name: normalized_events_2027_01_pkey; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.pk_normalized_events ATTACH PARTITION telemetry.normalized_events_2027_01_pkey;


--
-- Name: normalized_events_2027_01_raw_event_id_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_raw_event_id ATTACH PARTITION telemetry.normalized_events_2027_01_raw_event_id_idx;


--
-- Name: normalized_events_2027_01_rule_level_rule_id_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_rule_level ATTACH PARTITION telemetry.normalized_events_2027_01_rule_level_rule_id_idx;


--
-- Name: normalized_events_default_classification_groups_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_groups ATTACH PARTITION telemetry.normalized_events_default_classification_groups_idx;


--
-- Name: normalized_events_default_event_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_normalized_events_timestamp ATTACH PARTITION telemetry.normalized_events_default_event_timestamp_idx;


--
-- Name: normalized_events_default_mitre_attack_ids_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_mitre ATTACH PARTITION telemetry.normalized_events_default_mitre_attack_ids_idx;


--
-- Name: normalized_events_default_mitre_tactics_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_tactics ATTACH PARTITION telemetry.normalized_events_default_mitre_tactics_idx;


--
-- Name: normalized_events_default_pkey; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.pk_normalized_events ATTACH PARTITION telemetry.normalized_events_default_pkey;


--
-- Name: normalized_events_default_rule_level_rule_id_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_norm_events_rule_level ATTACH PARTITION telemetry.normalized_events_default_rule_level_rule_id_idx;


--
-- Name: raw_events_2026_07_ingested_at_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_ingested_at ATTACH PARTITION telemetry.raw_events_2026_07_ingested_at_idx;


--
-- Name: raw_events_2026_07_pkey; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.pk_raw_events ATTACH PARTITION telemetry.raw_events_2026_07_pkey;


--
-- Name: raw_events_2026_07_source_ip_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_src_ip ATTACH PARTITION telemetry.raw_events_2026_07_source_ip_idx;


--
-- Name: raw_events_2026_07_tenant_id_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_tenant_time ATTACH PARTITION telemetry.raw_events_2026_07_tenant_id_timestamp_idx;


--
-- Name: raw_events_2026_07_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_timestamp_desc ATTACH PARTITION telemetry.raw_events_2026_07_timestamp_idx;


--
-- Name: raw_events_2026_07_timestamp_idx1; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_timestamp ATTACH PARTITION telemetry.raw_events_2026_07_timestamp_idx1;


--
-- Name: raw_events_2026_08_ingested_at_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_ingested_at ATTACH PARTITION telemetry.raw_events_2026_08_ingested_at_idx;


--
-- Name: raw_events_2026_08_pkey; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.pk_raw_events ATTACH PARTITION telemetry.raw_events_2026_08_pkey;


--
-- Name: raw_events_2026_08_source_ip_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_src_ip ATTACH PARTITION telemetry.raw_events_2026_08_source_ip_idx;


--
-- Name: raw_events_2026_08_tenant_id_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_tenant_time ATTACH PARTITION telemetry.raw_events_2026_08_tenant_id_timestamp_idx;


--
-- Name: raw_events_2026_08_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_timestamp_desc ATTACH PARTITION telemetry.raw_events_2026_08_timestamp_idx;


--
-- Name: raw_events_2026_08_timestamp_idx1; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_timestamp ATTACH PARTITION telemetry.raw_events_2026_08_timestamp_idx1;


--
-- Name: raw_events_2026_09_ingested_at_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_ingested_at ATTACH PARTITION telemetry.raw_events_2026_09_ingested_at_idx;


--
-- Name: raw_events_2026_09_pkey; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.pk_raw_events ATTACH PARTITION telemetry.raw_events_2026_09_pkey;


--
-- Name: raw_events_2026_09_source_ip_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_src_ip ATTACH PARTITION telemetry.raw_events_2026_09_source_ip_idx;


--
-- Name: raw_events_2026_09_tenant_id_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_tenant_time ATTACH PARTITION telemetry.raw_events_2026_09_tenant_id_timestamp_idx;


--
-- Name: raw_events_2026_09_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_timestamp_desc ATTACH PARTITION telemetry.raw_events_2026_09_timestamp_idx;


--
-- Name: raw_events_2026_09_timestamp_idx1; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_timestamp ATTACH PARTITION telemetry.raw_events_2026_09_timestamp_idx1;


--
-- Name: raw_events_2026_10_ingested_at_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_ingested_at ATTACH PARTITION telemetry.raw_events_2026_10_ingested_at_idx;


--
-- Name: raw_events_2026_10_pkey; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.pk_raw_events ATTACH PARTITION telemetry.raw_events_2026_10_pkey;


--
-- Name: raw_events_2026_10_source_ip_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_src_ip ATTACH PARTITION telemetry.raw_events_2026_10_source_ip_idx;


--
-- Name: raw_events_2026_10_tenant_id_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_tenant_time ATTACH PARTITION telemetry.raw_events_2026_10_tenant_id_timestamp_idx;


--
-- Name: raw_events_2026_10_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_timestamp_desc ATTACH PARTITION telemetry.raw_events_2026_10_timestamp_idx;


--
-- Name: raw_events_2026_10_timestamp_idx1; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_timestamp ATTACH PARTITION telemetry.raw_events_2026_10_timestamp_idx1;


--
-- Name: raw_events_2026_12_ingested_at_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_ingested_at ATTACH PARTITION telemetry.raw_events_2026_12_ingested_at_idx;


--
-- Name: raw_events_2026_12_pkey; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.pk_raw_events ATTACH PARTITION telemetry.raw_events_2026_12_pkey;


--
-- Name: raw_events_2026_12_source_ip_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_src_ip ATTACH PARTITION telemetry.raw_events_2026_12_source_ip_idx;


--
-- Name: raw_events_2026_12_tenant_id_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_tenant_time ATTACH PARTITION telemetry.raw_events_2026_12_tenant_id_timestamp_idx;


--
-- Name: raw_events_2026_12_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_timestamp_desc ATTACH PARTITION telemetry.raw_events_2026_12_timestamp_idx;


--
-- Name: raw_events_2026_12_timestamp_idx1; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_timestamp ATTACH PARTITION telemetry.raw_events_2026_12_timestamp_idx1;


--
-- Name: raw_events_2027_01_ingested_at_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_ingested_at ATTACH PARTITION telemetry.raw_events_2027_01_ingested_at_idx;


--
-- Name: raw_events_2027_01_pkey; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.pk_raw_events ATTACH PARTITION telemetry.raw_events_2027_01_pkey;


--
-- Name: raw_events_2027_01_source_ip_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_src_ip ATTACH PARTITION telemetry.raw_events_2027_01_source_ip_idx;


--
-- Name: raw_events_2027_01_tenant_id_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_tenant_time ATTACH PARTITION telemetry.raw_events_2027_01_tenant_id_timestamp_idx;


--
-- Name: raw_events_2027_01_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_timestamp_desc ATTACH PARTITION telemetry.raw_events_2027_01_timestamp_idx;


--
-- Name: raw_events_2027_01_timestamp_idx1; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_timestamp ATTACH PARTITION telemetry.raw_events_2027_01_timestamp_idx1;


--
-- Name: raw_events_default_ingested_at_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_ingested_at ATTACH PARTITION telemetry.raw_events_default_ingested_at_idx;


--
-- Name: raw_events_default_pkey; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.pk_raw_events ATTACH PARTITION telemetry.raw_events_default_pkey;


--
-- Name: raw_events_default_source_ip_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_src_ip ATTACH PARTITION telemetry.raw_events_default_source_ip_idx;


--
-- Name: raw_events_default_tenant_id_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_tenant_time ATTACH PARTITION telemetry.raw_events_default_tenant_id_timestamp_idx;


--
-- Name: raw_events_default_timestamp_idx; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_timestamp_desc ATTACH PARTITION telemetry.raw_events_default_timestamp_idx;


--
-- Name: raw_events_default_timestamp_idx1; Type: INDEX ATTACH; Schema: telemetry; Owner: -
--

ALTER INDEX telemetry.idx_raw_events_timestamp ATTACH PARTITION telemetry.raw_events_default_timestamp_idx1;


--
-- Name: asset_inventory_context trg_asset_updated_at; Type: TRIGGER; Schema: enrichment; Owner: -
--

CREATE TRIGGER trg_asset_updated_at BEFORE UPDATE ON enrichment.asset_inventory_context FOR EACH ROW EXECUTE FUNCTION public.trigger_set_timestamp();


--
-- Name: identity_context trg_identity_updated_at; Type: TRIGGER; Schema: enrichment; Owner: -
--

CREATE TRIGGER trg_identity_updated_at BEFORE UPDATE ON enrichment.identity_context FOR EACH ROW EXECUTE FUNCTION public.trigger_set_timestamp();


--
-- Name: soc_triage_queue trg_capture_ground_truth; Type: TRIGGER; Schema: soc_ops; Owner: -
--

CREATE TRIGGER trg_capture_ground_truth AFTER UPDATE ON soc_ops.soc_triage_queue FOR EACH ROW EXECUTE FUNCTION soc_ops.capture_ground_truth_on_triage();


--
-- Name: soc_triage_queue trg_soc_triage_cooldown; Type: TRIGGER; Schema: soc_ops; Owner: -
--

CREATE TRIGGER trg_soc_triage_cooldown BEFORE UPDATE ON soc_ops.soc_triage_queue FOR EACH ROW EXECUTE FUNCTION soc_ops.trigger_set_cooldown_on_resolve();


--
-- Name: soc_triage_queue trg_soc_triage_resolved; Type: TRIGGER; Schema: soc_ops; Owner: -
--

CREATE TRIGGER trg_soc_triage_resolved BEFORE UPDATE ON soc_ops.soc_triage_queue FOR EACH ROW EXECUTE FUNCTION soc_ops.trigger_triage_resolved();


--
-- Name: soc_triage_queue trg_soc_triage_updated_at; Type: TRIGGER; Schema: soc_ops; Owner: -
--

CREATE TRIGGER trg_soc_triage_updated_at BEFORE UPDATE ON soc_ops.soc_triage_queue FOR EACH ROW EXECUTE FUNCTION public.trigger_set_timestamp();


--
-- Name: shared_value_lists trg_shared_value_lists_updated_at; Type: TRIGGER; Schema: suppression; Owner: -
--

CREATE TRIGGER trg_shared_value_lists_updated_at BEFORE UPDATE ON suppression.shared_value_lists FOR EACH ROW EXECUTE FUNCTION public.trigger_set_timestamp();


--
-- Name: suppression_groups trg_suppression_groups_updated_at; Type: TRIGGER; Schema: suppression; Owner: -
--

CREATE TRIGGER trg_suppression_groups_updated_at BEFORE UPDATE ON suppression.suppression_groups FOR EACH ROW EXECUTE FUNCTION public.trigger_set_timestamp();


--
-- Name: suppression_rules trg_suppression_updated_at; Type: TRIGGER; Schema: suppression; Owner: -
--

CREATE TRIGGER trg_suppression_updated_at BEFORE UPDATE ON suppression.suppression_rules FOR EACH ROW EXECUTE FUNCTION public.trigger_set_timestamp();


--
-- Name: correlated_incidents correlated_incidents_correlation_rule_id_fkey; Type: FK CONSTRAINT; Schema: correlation; Owner: -
--

ALTER TABLE ONLY correlation.correlated_incidents
    ADD CONSTRAINT correlated_incidents_correlation_rule_id_fkey FOREIGN KEY (correlation_rule_id) REFERENCES correlation.correlation_rules(correlation_rule_id);


--
-- Name: incident_stages incident_stages_incident_id_fkey; Type: FK CONSTRAINT; Schema: correlation; Owner: -
--

ALTER TABLE ONLY correlation.incident_stages
    ADD CONSTRAINT incident_stages_incident_id_fkey FOREIGN KEY (incident_id) REFERENCES correlation.correlated_incidents(incident_id) ON DELETE CASCADE;


--
-- Name: calculated_risk_scores calculated_risk_scores_incident_id_fkey; Type: FK CONSTRAINT; Schema: risk_engine; Owner: -
--

ALTER TABLE ONLY risk_engine.calculated_risk_scores
    ADD CONSTRAINT calculated_risk_scores_incident_id_fkey FOREIGN KEY (incident_id) REFERENCES correlation.correlated_incidents(incident_id) ON DELETE CASCADE;


--
-- Name: risk_scoring_factors risk_scoring_factors_incident_id_fkey; Type: FK CONSTRAINT; Schema: risk_engine; Owner: -
--

ALTER TABLE ONLY risk_engine.risk_scoring_factors
    ADD CONSTRAINT risk_scoring_factors_incident_id_fkey FOREIGN KEY (incident_id) REFERENCES correlation.correlated_incidents(incident_id) ON DELETE CASCADE;


--
-- Name: incident_investigation_notes incident_investigation_notes_incident_id_fkey; Type: FK CONSTRAINT; Schema: soc_ops; Owner: -
--

ALTER TABLE ONLY soc_ops.incident_investigation_notes
    ADD CONSTRAINT incident_investigation_notes_incident_id_fkey FOREIGN KEY (incident_id) REFERENCES correlation.correlated_incidents(incident_id) ON DELETE CASCADE;


--
-- Name: incident_response_actions incident_response_actions_incident_id_fkey; Type: FK CONSTRAINT; Schema: soc_ops; Owner: -
--

ALTER TABLE ONLY soc_ops.incident_response_actions
    ADD CONSTRAINT incident_response_actions_incident_id_fkey FOREIGN KEY (incident_id) REFERENCES correlation.correlated_incidents(incident_id) ON DELETE CASCADE;


--
-- Name: soc_triage_queue soc_triage_queue_incident_id_fkey; Type: FK CONSTRAINT; Schema: soc_ops; Owner: -
--

ALTER TABLE ONLY soc_ops.soc_triage_queue
    ADD CONSTRAINT soc_triage_queue_incident_id_fkey FOREIGN KEY (incident_id) REFERENCES correlation.correlated_incidents(incident_id) ON DELETE CASCADE;


--
-- Name: aggregate_evidence_mapping aggregate_evidence_mapping_aggregation_id_fkey; Type: FK CONSTRAINT; Schema: suppression; Owner: -
--

ALTER TABLE ONLY suppression.aggregate_evidence_mapping
    ADD CONSTRAINT aggregate_evidence_mapping_aggregation_id_fkey FOREIGN KEY (aggregation_id) REFERENCES suppression.aggregated_alerts(aggregation_id) ON DELETE CASCADE;


--
-- Name: aggregate_evidence_mapping fk_evidence_to_raw; Type: FK CONSTRAINT; Schema: suppression; Owner: -
--

ALTER TABLE ONLY suppression.aggregate_evidence_mapping
    ADD CONSTRAINT fk_evidence_to_raw FOREIGN KEY (raw_event_id, event_timestamp) REFERENCES telemetry.raw_events(event_id, "timestamp") ON DELETE CASCADE;


--
-- Name: suppression_rules suppression_rules_group_id_fkey; Type: FK CONSTRAINT; Schema: suppression; Owner: -
--

ALTER TABLE ONLY suppression.suppression_rules
    ADD CONSTRAINT suppression_rules_group_id_fkey FOREIGN KEY (group_id) REFERENCES suppression.suppression_groups(group_id) ON DELETE SET NULL;


--
-- Name: normalized_events fk_norm_to_raw; Type: FK CONSTRAINT; Schema: telemetry; Owner: -
--

ALTER TABLE telemetry.normalized_events
    ADD CONSTRAINT fk_norm_to_raw FOREIGN KEY (raw_event_id, event_timestamp) REFERENCES telemetry.raw_events(event_id, "timestamp") ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict VRbYBHMRXuuuce86N3IC0DdIiLrdEWEVzXIxsZ1d01jhHDen2fSHWea5SgQAyba

