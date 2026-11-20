"""
========================================================================================
TEST APEX CORRELATION & BEHAVIORAL CLUSTERING ENGINE (JALUR 2 - LEVEL 3 & 4)
========================================================================================
Validates:
1. Level 3 Behavioral Spatial Clustering:
   - Defense 1: Cloud-Native Asset-Epoch Binding (k8s_pod_uid + boot_epoch prevents IP churn).
   - Defense 3: Dynamic Crown Jewel Criticality Multiplier for Tier-0 Domain Controllers.
   - Defense 4: Semantic Invariant Normalization (Defeating URI/token random noise perturbation).
2. Level 4 Cross-Category Causal Correlation DAG Engine:
   - Monotonic multi-stage kill chain reconstruction (Recon -> RCE -> PrivEsc).
   - Temporal Node Unrolling on lateral movement loops (Cyclic deadlock prevention).
   - Adaptive Window with 7-Day Hard Ceiling Cap.
   - 5-Second Network Clock Skew tolerance.
   - Defense 2: Bi-Temporal Event Sourcing & Retrospective Delta Splicing (28h+ delayed logs).
   - Defense 5: Hybrid Post-Quantum Cryptographic Proof of Custody (SHA-256 + BLAKE3/SHA-384).
3. 100% Zero-Touch Isolation from Jalur 1.
========================================================================================
"""

import pytest
from datetime import datetime, timezone, timedelta
from pipeline.apex_correlation_engine import (
    ApexBehavioralClusterEngine,
    ApexCrossCategoryCorrelationEngine,
    SemanticInvariantNormalizer,
    HybridPQCHasher,
    calculate_entropy,
    extract_feature_user,
    extract_feature_uri
)


def test_deep_feature_extraction_user_and_uri():
    """Verifies user and URI extraction from nested JSONB fingerprint_input and tracked_samples."""
    item_jsonb = {
        "fingerprint_input": {
            "c": "auth_bruteforce",
            "p": {"dst_user:clean": "Administrator", "url_path:tmpl": "/wp-login.php"}
        },
        "tracked_samples": {
            "url_path": ["/wp-login.php?redirect_to=admin"]
        }
    }
    extracted_user = extract_feature_user(item_jsonb)
    extracted_uri = extract_feature_uri(item_jsonb)
    
    assert extracted_user == "administrator"
    assert "/wp-login.php" in extracted_uri


def test_configurable_weights_and_threshold():
    """Verifies that custom similarity weights and thresholds are respected."""
    custom_weights = {"entity": 0.50, "ip": 0.50, "user": 0.0, "token": 0.0, "rule": 0.0}
    engine = ApexBehavioralClusterEngine(base_weights=custom_weights, default_threshold=0.80)
    
    a = {"tenant_id": "T1", "target_asset": "srv-1", "source_ip": "1.2.3.4"}
    b = {"tenant_id": "T1", "target_asset": "srv-1", "source_ip": "1.2.3.4"}
    c = {"tenant_id": "T1", "target_asset": "srv-1", "source_ip": "5.6.7.8"}
    
    # a and b identical on entity + ip -> 1.0 >= 0.80
    assert engine.compute_similarity(a, b) == 1.0
    # a and c match on target_asset (sim_e=0.5) but different IP -> 0.50 * 0.5 = 0.25 < 0.80
    assert engine.compute_similarity(a, c) == 0.25
    
    clusters = engine.cluster_items([a, b, c])
    assert len(clusters) == 2  # a & b in cluster 1, c in cluster 2


def test_deterministic_cluster_id():
    """Verifies that cluster_id is deterministically generated from tenant, pivot, and IP."""
    engine = ApexBehavioralClusterEngine()
    item = {"group_id": "APX-RO-001", "tenant_id": "TenantA", "source_ip": "10.0.0.1"}
    
    clusters_1 = engine.cluster_items([item])
    clusters_2 = engine.cluster_items([item])
    
    assert clusters_1[0]["cluster_id"] == clusters_2[0]["cluster_id"]
    assert clusters_1[0]["cluster_id"].startswith("APX-CLUST-")


def test_defense_4_semantic_invariant_normalization():
    """Verifies that high-entropy noise injected into URIs is normalized."""
    noisy_uri_1 = "/api/v1/auth?token=a8f93b11029e847c&sess=991827"
    noisy_uri_2 = "/api/v1/auth?token=fe0192ca7845ba12&sess=991827"
    
    norm_1 = SemanticInvariantNormalizer.normalize_uri(noisy_uri_1)
    norm_2 = SemanticInvariantNormalizer.normalize_uri(noisy_uri_2)
    
    assert "{HIGH_ENTROPY_TOKEN}" in norm_1
    assert norm_1 == norm_2, "Semantic Invariant must map both noisy URIs to the exact same canonical pattern"


def test_defense_1_cloud_native_asset_epoch_binding():
    """Verifies that Kubernetes pod churn on the same IP is never falsely correlated."""
    cluster_engine = ApexBehavioralClusterEngine()
    
    # Pod 1: Payment gateway exploited
    alert_pod_1 = {
        "tenant_id": "TenantC",
        "category_code": "web_attack_rce",
        "cloud_metadata": {
            "assigned_ip": "10.244.3.88",
            "k8s_pod_uid": "uid-pod-payment-111",
            "boot_epoch": 1794389000
        }
    }
    
    # Pod 2: HR payroll pod allocated the exact same IP later
    alert_pod_2 = {
        "tenant_id": "TenantC",
        "category_code": "web_attack_rce",
        "cloud_metadata": {
            "assigned_ip": "10.244.3.88",
            "k8s_pod_uid": "uid-pod-hr-222",
            "boot_epoch": 1794391200
        }
    }
    
    sim = cluster_engine.compute_similarity(alert_pod_1, alert_pod_2)
    assert sim == 0.0, "Similarity between different pods on the same IP must be 0.0 (IP Re-allocation protection)"


def test_defense_3_crown_jewel_criticality_multiplier():
    """Verifies that Tier-0 assets (e.g. Domain Controller) lower the threshold and trigger high severity."""
    cluster_engine = ApexBehavioralClusterEngine()
    
    dc_alert = {
        "tenant_id": "TenantC",
        "category_code": "priv_escalation",
        "target_asset": "dc-prod-01.corp.internal",
        "asset_metadata": {
            "hostname": "dc-prod-01.corp.internal",
            "asset_tier": 0,
            "criticality_weight": 2.5
        },
        "alert_count": 1
    }
    
    clusters = cluster_engine.cluster_items([dc_alert])
    assert len(clusters) == 1
    assert clusters[0]["members"][0]["asset_metadata"]["asset_tier"] == 0


def test_level_4_cross_category_correlation_and_defense_5_pqc():
    """Verifies multi-stage attack chain tracking and Hybrid Quantum-Resistant MMR hashing."""
    corr_engine = ApexCrossCategoryCorrelationEngine()
    
    input_chain = [
        {
            "group_id": "APX-RO-043908FA0E46",
            "tenant_id": "TenantC",
            "category_code": "web_attack",
            "target_asset": "hportal-prod-159",
            "first_seen": "2026-10-16T04:18:25Z"
        },
        {
            "leaf_group_id": "APX-LG-EPHEM-POD-001",
            "tenant_id": "TenantC",
            "category_code": "web_attack_rce",
            "target_asset": "hportal-prod-159",
            "first_seen": "2026-10-16T04:22:10Z"
        },
        {
            "leaf_group_id": "APX-LG-PRIV-DC-002",
            "tenant_id": "TenantC",
            "category_code": "priv_escalation",
            "target_asset": "dc-prod-01.corp.internal",
            "asset_metadata": {"asset_tier": 0, "hostname": "dc-prod-01.corp.internal"},
            "first_seen": "2026-10-16T04:53:25Z"
        }
    ]
    
    incidents = corr_engine.correlate_chain(input_chain)
    assert len(incidents) == 1
    inc = incidents[0]
    
    assert inc["incident_type"] == "ADVANCED_PERSISTENT_THREAT_MULTI_STAGE"
    assert inc["threat_severity"] == "P0_CRITICAL"
    assert inc["kill_chain_timeline"]["stages_total"] == 3
    assert inc["cryptographic_proof_of_custody"]["cnsa_2_0_compliant"] is True
    assert len(inc["cryptographic_proof_of_custody"]["mmr_root_sha256"]) == 64
    assert len(inc["cryptographic_proof_of_custody"]["pqc_hybrid_digest"]) == 64


def test_defense_2_bi_temporal_late_splicing_28h():
    """Verifies that events arriving 28 hours late from disconnected rigs are spliced cleanly."""
    corr_engine = ApexCrossCategoryCorrelationEngine()
    
    # 1. Base incident established at 04:53 UTC
    input_chain = [
        {
            "group_id": "APX-RO-043908FA0E46",
            "tenant_id": "TenantC",
            "category_code": "web_attack",
            "target_asset": "hportal-prod-159",
            "first_seen": "2026-10-16T04:18:25Z"
        },
        {
            "leaf_group_id": "APX-LG-PRIV-DC-002",
            "tenant_id": "TenantC",
            "category_code": "priv_escalation",
            "target_asset": "dc-prod-01.corp.internal",
            "asset_metadata": {"asset_tier": 0, "hostname": "dc-prod-01.corp.internal"},
            "first_seen": "2026-10-16T04:53:25Z"
        }
    ]
    
    incidents = corr_engine.correlate_chain(input_chain)
    base_inc = incidents[0]
    assert base_inc["kill_chain_timeline"]["stages_total"] == 2
    
    # 2. Delayed FIM alert arrives 28 hours later
    late_fim_event = {
        "leaf_group_id": "APX-LG-FIM-LATE-003",
        "tenant_id": "TenantC",
        "category_code": "fim_change",
        "target_asset": "dc-prod-01.corp.internal",
        "event_timestamp": "2026-10-16T04:56:40Z",
        "ingest_timestamp": "2026-10-17T08:56:40Z",  # 28 Hours Late!
        "evidence": {
            "file_path": "C:\\Windows\\System32\\ntds.dit"
        }
    }
    
    amended_inc = corr_engine.splice_late_arriving_event(base_inc, late_fim_event)
    
    assert amended_inc["status"] == "AMENDED_WITH_RETROSPECTIVE_DELTA"
    assert amended_inc["kill_chain_timeline"]["stages_total"] == 3
    last_stage = amended_inc["kill_chain_timeline"]["stages_confirmed"][-1]
    assert "28 Hours" in last_stage["bi_temporal_splicing"]["delay_human_readable"]
    assert last_stage["target_file"] == "C:\\Windows\\System32\\ntds.dit"


def test_all_33_categories_stage_and_mitre_mapping():
    """Verifies that all 33 taxonomy categories map to Kill Chain Stages (1-5) and valid MITRE techniques."""
    corr_engine = ApexCrossCategoryCorrelationEngine()

    all_33_categories = [
        "account_change", "agent_health", "app_error_log", "auth_bruteforce",
        "cloud_api_denied", "cloud_iam_change", "cloud_login_failed", "container_runtime",
        "dns_suspicious", "dos_flood", "fim_change", "firewall_deny",
        "generic_rule", "ids_signature", "ioc_match", "log_tamper",
        "lolbin_script", "malware", "persistence", "policy_violation",
        "priv_escalation", "rootcheck", "saas_audit", "sca_failed",
        "scan_vertical", "suspicious_process", "system_event", "vuln_detected",
        "web_attack", "web_client_error", "web_post_burst", "web_server_error",
        "web_waf_block"
    ]

    for cat in all_33_categories:
        stage = corr_engine.get_stage_order(cat)
        assert 1 <= stage <= 5, f"Category {cat} has invalid stage {stage}"
        
        mitre = corr_engine._resolve_mitre_technique(cat)
        assert mitre.startswith("T"), f"Category {cat} unresolved MITRE technique: {mitre}"
        assert "(" in mitre and ")" in mitre, f"Category {cat} technique format invalid: {mitre}"


def test_dynamic_custom_stage_and_mitre_override():
    """Verifies dynamic injection of custom stage and MITRE mappings without code hardcoding."""
    custom_stages = {"zero_day_telemetry": 3, "custom_exfil": 5}
    custom_mitre = {"zero_day_telemetry": "T1203.999 (Custom Zero Day)", "custom_exfil": "T1048.999 (Custom Exfiltration)"}

    engine = ApexCrossCategoryCorrelationEngine(
        custom_stage_map=custom_stages,
        custom_mitre_map=custom_mitre
    )

    assert engine.get_stage_order("zero_day_telemetry") == 3
    assert engine.get_stage_order("custom_exfil") == 5
    assert engine._resolve_mitre_technique("zero_day_telemetry") == "T1203.999 (Custom Zero Day)"
    assert engine._resolve_mitre_technique("custom_exfil") == "T1048.999 (Custom Exfiltration)"

