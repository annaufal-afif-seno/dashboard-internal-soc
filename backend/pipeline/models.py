"""
Pydantic Data Models for Wazuh 19-Table Enterprise Database Schema & Pipeline
Scope-Locked • Evidence-Based • High-Throughput • Production-Grade
"""
from typing import Optional, List, Dict, Any, Union
from datetime import datetime, date
from decimal import Decimal
from pydantic import BaseModel, Field, ConfigDict, field_validator


# ============================================================================
# 1. INGESTION & TELEMETRY MODELS (STAGE 1 & COMMON EVENT MODEL)
# ============================================================================

class RuleModel(BaseModel):
    id: str
    level: int = 0
    description: str = ""
    firedtimes: Optional[int] = None
    groups: List[str] = Field(default_factory=list)
    pci_dss: Optional[List[str]] = None
    gdpr: Optional[List[str]] = None
    nist_800_53: Optional[List[str]] = None
    tsc: Optional[List[str]] = None
    mitre: Optional[Dict[str, Any]] = None


class AgentModel(BaseModel):
    id: str = "000"
    name: str = "unknown"
    ip: Optional[str] = None
    labels: Optional[Dict[str, Any]] = None


class DecoderModel(BaseModel):
    name: str = "unknown"
    parent: Optional[str] = None


class WazuhRawAlert(BaseModel):
    """Raw Wazuh Alert schema parsed from JSON Lines"""
    id: Optional[str] = Field(default=None, alias="_id")
    event_id: Optional[str] = Field(default=None, alias="id")
    timestamp: str
    at_timestamp: Optional[str] = Field(default=None, alias="@timestamp")
    rule: RuleModel
    agent: AgentModel = Field(default_factory=AgentModel)
    manager: Optional[Dict[str, Any]] = None
    full_log: Optional[str] = None
    predecoder: Optional[Dict[str, Any]] = None
    decoder: Optional[DecoderModel] = None
    data: Optional[Dict[str, Any]] = None
    location: Optional[str] = None
    short_message: Optional[str] = None
    host: Optional[str] = None

    model_config = ConfigDict(populate_by_name=True)


class RawEventDB(BaseModel):
    """Database model for table: raw_events"""
    event_id: str
    timestamp: datetime
    agent_id: str
    tenant_id: str = "DEFAULT"
    agent_name: Optional[str] = None
    agent_ip: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    username: Optional[str] = None
    location: Optional[str] = None
    decoder_name: Optional[str] = None
    raw_payload: str
    ingested_at: Optional[datetime] = None


class NormalizedEventDB(BaseModel):
    """Database model for table: normalized_events"""
    normalized_event_id: str
    raw_event_id: str
    event_timestamp: datetime
    rule_id: int
    rule_level: int
    rule_description: str
    classification_groups: List[str] = Field(default_factory=list)
    mitre_attack_ids: List[str] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    compliance_frameworks: Dict[str, Any] = Field(default_factory=dict)
    asset_criticality_tier: str = "STANDARD"
    is_asset_internet_exposed: bool = False
    is_privileged_user: bool = False
    is_service_account: bool = False
    threat_intel_match: bool = False
    threat_intel_confidence: int = 0
    processed_at: Optional[datetime] = None
    needs_classification_review: bool = False


class CommonEventModel(BaseModel):
    """Standardized Common Event Model (CEM) for in-flight processing"""
    event_id: str
    timestamp: str
    source_ip: Optional[str] = None
    source_host: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_host: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    username: Optional[str] = None
    agent_id: str
    agent_name: str
    tenant_id: str = "DEFAULT"
    host_criticality: str = "STANDARD"
    is_internet_exposed: bool = False
    is_privileged_user: bool = False
    is_service_account: bool = False
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    command_line: Optional[str] = None
    parent_process: Optional[str] = None
    rule_id: str
    rule_level: int
    rule_description: str
    classification_groups: List[str] = Field(default_factory=list)
    mitre_attack_ids: List[str] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    raw_payload: Optional[str] = None
    location: Optional[str] = None
    decoder_name: Optional[str] = None

    # Semantic Normalization & Archetype Fields (22 Sweet Spot Categories)
    event_category: str = "SYSTEM_HEALTH"  # RANSOMWARE, MALWARE, COMMAND_AND_CONTROL, EXFILTRATION, LATERAL_MOVEMENT, PRIVILEGE_ESCALATION, CREDENTIAL_ACCESS, DEFENSE_EVASION, EXECUTION, PERSISTENCE, DISCOVERY, INITIAL_ACCESS, AUTH_FAILURE, AUTH_SUCCESS, WEB_ATTACK, WEB_OPERATIONAL, FILE_INTEGRITY, VULNERABILITY, CONFIGURATION_ASSESSMENT, CLOUD_CONTAINER, SYSTEM_HEALTH, OTHER
    dedup_actor: Optional[str] = None
    dedup_target: Optional[str] = None
    window_class: str = "STANDARD"  # FAST (300s/600s), STANDARD (900s), SLOW (1800s/3600s)
    window_duration_seconds: int = 900

    # OS Platform Dimension (extracted from agent.labels.os / data.win / decoder heuristics)
    os_platform: str = "unknown"  # linux, windows, macos, unknown

    # Threat Intelligence Enrichment & Context
    threat_intel_match: bool = False

    # Compliance mappings extracted from Wazuh rule metadata
    compliance_frameworks: Dict[str, Any] = Field(default_factory=dict)

    # Indicator of Attack (IOA) In-Aggregate Context Summary
    ioa_summary: Optional[str] = None

    # Autonomous Self-Healing / Zero-Day Audit Flag
    needs_classification_review: bool = False

    # ── OCSF v1.3 Mandatory Fields (set by OCSFFieldMapperPlugin) ────────────
    # Reference: https://schema.ocsf.io/1.3.0/classes/base_event
    ocsf_class_uid: Optional[int] = None     # e.g., 3002=Auth, 4001=NetworkActivity, 1007=Process
    ocsf_category_uid: Optional[int] = None  # e.g., 1=System, 2=Findings, 3=IAM, 4=Network
    ocsf_activity_id: Optional[int] = None   # e.g., 1=Logon, 3=Modify, 6=Traffic
    ocsf_severity_id: Optional[int] = None   # 0=Unknown, 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical, 6=Fatal

    # ── Inline Risk Score (set by InlineRiskScorerPlugin) ────────────────────
    # Pre-computed at normalization time. Eliminates JOIN to risk_scoring_factors for triage.
    # Reference: Splunk CIM 5.3 risk_score + Microsoft Sentinel entity risk scoring.
    inline_risk_score: Optional[int] = None  # 0-100

    # ── Generic IOC Extraction (set by GenericIOCExtractorPlugin) ──────────
    # Regex-extracted IOCs from full_log/raw_payload for unknown alert types.
    # Keys: ipv4, md5, sha256, sha1, domains, cves, urls
    extracted_iocs: Optional[Dict[str, Any]] = None

    # ── HTTP & Web Forensics (set by Ingest / HTTPTrafficAnalyzerPlugin) ────
    http_status: Optional[int] = None
    user_agent: Optional[str] = None
    is_scanner_ua: bool = False





# ============================================================================
# 2. CONTEXT ENRICHMENT MASTER MODELS (STAGE 3)
# ============================================================================

class AssetInventoryContextDB(BaseModel):
    """Database model for table: asset_inventory_context"""
    asset_id: str
    hostname: str
    ip_address: Optional[str] = None
    asset_type: str  # DOMAIN_CONTROLLER, DB_SERVER, WEB_SERVER, WORKSTATION
    criticality_tier: str  # CROWN_JEWEL, CRITICAL, HIGH, STANDARD, LAB
    criticality_score: int  # 0, 5, 15, 20, 25
    environment: str = "PRODUCTION"
    is_internet_exposed: bool = False
    owner_department: Optional[str] = None
    last_synced_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class IdentityContextDB(BaseModel):
    """Database model for table: identity_context"""
    identity_id: str
    username: str
    account_type: str  # STANDARD_USER, PRIVILEGED_ADMIN, SERVICE_ACCOUNT, SYSTEM, EXTERNAL_VENDOR
    is_privileged: bool = False
    department: Optional[str] = None
    expected_hosts: List[str] = Field(default_factory=list)
    risk_baseline_score: int = 0
    last_synced_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class ThreatIntelligenceIoCDB(BaseModel):
    """Database model for table: threat_intelligence_iocs"""
    ioc_id: Optional[int] = None
    indicator_value: str
    indicator_type: str  # IPV4, IPV6, DOMAIN, MD5, SHA256, URL
    threat_actor: Optional[str] = None
    malware_family: Optional[str] = None
    confidence_score: int  # 0..100
    source_feed: str
    description: Optional[str] = None
    is_active: bool = True
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    expires_at: Optional[datetime] = None


class MaintenanceWindowDB(BaseModel):
    """Database model for table: maintenance_windows"""
    window_id: str
    title: str
    target_hostname: str
    target_ip: Optional[str] = None
    ticket_id: str
    approved_by: str
    window_start: datetime
    window_end: datetime
    status: str = "SCHEDULED"  # SCHEDULED, ACTIVE, COMPLETED, CANCELLED
    created_at: Optional[datetime] = None


# ============================================================================
# 3. NOISE CONTROL & DEDUPLICATION MODELS (STAGE 2)
# ============================================================================

# --- IOC / IOA Structured Sub-Models (Enriched Scope Definition) ---
# Ref: MISP Attribute Types, Elastic Exception Items, SIGMA Modifiers, OCSF

class IocIndicator(BaseModel):
    """Single Indicator of Compromise entry within a suppression scope.
    Covers IP, domain, hash, email, URL — each with direction & action.
    Ref: MISP attribute types (https://github.com/MISP/MISP)
    """
    type: str  # IPV4, IPV6, DOMAIN, URL, MD5, SHA256, SHA1, EMAIL, CIDR, C2_DOMAIN
    value: str
    direction: str = "any"       # source, destination, any
    action: str = "suppress"     # suppress | never_suppress (IOC blacklist override)

    @field_validator("type")
    @classmethod
    def validate_ioc_type(cls, v):
        allowed = {"IPV4", "IPV6", "DOMAIN", "URL", "MD5", "SHA256", "SHA1",
                   "EMAIL", "CIDR", "C2_DOMAIN"}
        if v.upper() not in allowed:
            raise ValueError(f"IOC type must be one of {allowed}")
        return v.upper()

    @field_validator("action")
    @classmethod
    def validate_ioc_action(cls, v):
        if v.lower() not in ("suppress", "never_suppress"):
            raise ValueError("IOC action must be 'suppress' or 'never_suppress'")
        return v.lower()


class IoaPattern(BaseModel):
    """Single Indicator of Attack pattern for behavioral matching.
    Maps 1:1 to Wazuh rule primitives (<field>, <match>, <regex>).
    Ref: Elastic Detection Rules conditions, SIGMA field modifiers
    """
    field: str       # url_path, command_line, process_path, data.dns.question.name, etc.
    operator: str    # equals, contains, regex, startswith, endswith, not_contains, not_equals
    value: str

    @field_validator("operator")
    @classmethod
    def validate_operator(cls, v):
        allowed = {"equals", "contains", "regex", "startswith", "endswith",
                   "not_contains", "not_equals", "not_regex"}
        if v.lower() not in allowed:
            raise ValueError(f"Operator must be one of {allowed}")
        return v.lower()

    def to_wazuh_element(self) -> str:
        """Convert this IoaPattern to a Wazuh XML element string."""
        fld = self.field
        val = self.value
        op = self.operator
        if op in ("regex", "not_regex"):
            prefix = "^" if not val.startswith("^") else ""
            if fld in ("url_path", "url"):
                return f'    <field name="url">{prefix}{val}</field>'
            elif fld == "command_line":
                return f'    <regex>{val}</regex>'
            return f'    <field name="{fld}">{prefix}{val}</field>'
        elif op == "startswith":
            return f'    <field name="{fld}">^{val}</field>'
        elif op == "endswith":
            return f'    <field name="{fld}">{val}$</field>'
        elif op in ("contains", "not_contains"):
            if fld == "command_line":
                return f'    <match>{val}</match>'
            return f'    <field name="{fld}">{val}</field>'
        elif op in ("equals", "not_equals"):
            if fld == "command_line":
                return f'    <match>^{val}$</match>'
            return f'    <field name="{fld}">^{val}$</field>'
        return f'    <field name="{fld}">{val}</field>'


class NeverSuppressGuard(BaseModel):
    """Safety guardrails that OVERRIDE suppression even when rule matches.
    Ref: Palantir ADS 'Detection Coverage Gap' principle
    """
    threat_intel_match: bool = True
    min_risk_score_override: int = 80
    ioc_blacklist_types: List[str] = Field(
        default_factory=lambda: ["MD5", "SHA256", "C2_DOMAIN"]
    )

    @field_validator("min_risk_score_override")
    @classmethod
    def validate_risk_override(cls, v):
        if not (0 <= v <= 100):
            raise ValueError("min_risk_score_override must be between 0 and 100")
        return v


class SuppressionRuleDB(BaseModel):
    """Database model for table: suppression_rules (with Separation of Duties)"""
    suppression_id: str
    rule_name: str
    suppression_class: str  # S1_KNOWN_GOOD, S2_FALSE_POSITIVE, S3_MAINTENANCE, S4_EXCEPTION, S5_CONDITIONAL
    target_rule_ids: List[int]
    author: str
    approver: str  # Separation of duties: author <> approver
    ticket_id: str
    business_reason: str
    scope_definition: Dict[str, Any]
    status: str = "ACTIVE"  # ACTIVE, EXPIRED, REVOKED, PENDING_REVIEW, PENDING_WAZUH_DEPLOY, TUNED_IN_WAZUH_XML
    enforcement_mode: str = "PIPELINE_MUTE"  # PIPELINE_MUTE, WAZUH_XML, WAZUH_CDB, HYBRID
    created_date: date
    expires_date: date
    review_cycle: str = "MONTHLY"
    drift_baseline_count: int = 0
    current_drift_sigma: Decimal = Decimal("0.00")
    group_id: Optional[str] = None  # FK to suppression_groups.group_id (hierarchical bundling)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def to_wazuh_xml(self, rule_id_num: int = 100500) -> str:
        """Convert this suppression rule to a standalone Wazuh native XML level 0 rule."""
        sids_str = ",".join(str(s) for s in sorted(self.target_rule_ids)) if self.target_rule_ids else "0"
        lines = [f'<rule id="{rule_id_num}" level="0">']
        lines.append(f'  <if_sid>{sids_str}</if_sid>')
        
        scope = self.scope_definition or {}
        hostname = scope.get("target_host") or scope.get("hostname")
        if hostname and hostname not in ("-", "All / Internal", "All"):
            lines.append(f'  <hostname>{hostname}</hostname>')
        
        srcip = scope.get("source_ip") or scope.get("actor")
        if srcip and srcip not in ("-", "All / Internal", "All") and not str(srcip).startswith("user:"):
            lines.append(f'  <srcip>{srcip}</srcip>')
            
        username = scope.get("username")
        if username and username not in ("-", "All / Internal", "All"):
            lines.append(f'  <user>{username}</user>')
            
        url_path = scope.get("url_path") or scope.get("url")
        if url_path:
            lines.append(f'  <field name="url">{url_path}</field>')
            
        program = scope.get("program_name")
        if program:
            lines.append(f'  <program_name>{program}</program_name>')
            
        for ioa in self.get_ioa_patterns():
            elem = ioa.to_wazuh_element()
            if elem:
                lines.append(f'  {elem.strip()}')
                
        lines.append(f'  <description>ASOC Tuned Suppression: {self.rule_name} [{self.suppression_id}]</description>')
        lines.append('</rule>')
        return "\n".join(lines)

    # --- Enriched IOC/IOA Accessors (parsed from scope_definition) ---

    def get_ioc_indicators(self) -> List['IocIndicator']:
        """Parse structured IOC indicators from scope_definition."""
        raw = self.scope_definition.get("ioc_indicators", [])
        return [IocIndicator(**item) for item in raw if isinstance(item, dict)]

    def get_ioa_patterns(self) -> List['IoaPattern']:
        """Parse structured IOA patterns from scope_definition."""
        raw = self.scope_definition.get("ioa_patterns", [])
        return [IoaPattern(**item) for item in raw if isinstance(item, dict)]

    def get_never_suppress_guard(self) -> Optional['NeverSuppressGuard']:
        """Parse never-suppress guardrails from scope_definition."""
        raw = self.scope_definition.get("never_suppress_if")
        if raw and isinstance(raw, dict):
            return NeverSuppressGuard(**raw)
        return None

    def has_ioc_blacklist_override(self, ioc_type: str) -> bool:
        """Check if a given IOC type is on the never-suppress blacklist."""
        guard = self.get_never_suppress_guard()
        if guard and ioc_type.upper() in [t.upper() for t in guard.ioc_blacklist_types]:
            return True
        return False


class SuppressionAuditLogDB(BaseModel):
    """Database model for table: suppression_audit_log"""
    log_id: Optional[int] = None
    suppression_id: str
    action: str  # CREATED, APPROVED, REJECTED, REVOKED, MODIFIED, REVIEWED, EXTENDED, EXPIRED
    performed_by: str
    notes: Optional[str] = None
    recorded_at: Optional[datetime] = None


class SuppressionGroupDB(BaseModel):
    """Database model for table: suppression_groups (Policy Bundle)
    Groups multiple suppression rules into hierarchical bundles.
    Ref: Elastic Shared Exception Containers, Palantir ADS Framework.
    """
    group_id: str  # GRP-2026-001
    group_name: str
    group_type: str  # TENANT, USE_CASE, ASSET_GROUP, ACTOR, MITRE_TACTIC, MAINTENANCE
    tenant_id: str = "ALL"
    description: Optional[str] = None
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    shared_scope: Dict[str, Any] = Field(default_factory=dict)
    auto_merge: bool = False
    priority: str = "P2"
    owner: str
    status: str = "ACTIVE"  # ACTIVE, DRAFT, ARCHIVED, UNDER_REVIEW
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class SharedValueListDB(BaseModel):
    """Database model for table: shared_value_lists (CDB-style shared lookup lists)
    Centralized IP/hostname/username lists referenced by multiple groups.
    Ref: Wazuh CDB Lists, Elastic Value Lists.
    """
    list_id: str  # LST-2026-001
    list_name: str
    list_type: str  # IP, HOSTNAME, USERNAME, CIDR, AGENT_GROUP, RULE_SID
    values: List[Any] = Field(default_factory=list)
    description: Optional[str] = None
    referenced_by: List[str] = Field(default_factory=list)  # group_ids
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class AggregatedAlertDB(BaseModel):
    """Database model for table: aggregated_alerts"""
    aggregation_id: str
    rule_id: int
    deduplication_key: str
    tenant_id: str = "DEFAULT"
    agent_id: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    event_count: int = 1
    window_start: datetime
    window_end: datetime
    status: str = "OPEN"  # PRD Section 3: Hanya OPEN dan CLOSED
    category: str = "SYSTEM_HEALTH"  # 22 Sweet Spot Categories
    rule_description: Optional[str] = None
    actor: Optional[str] = None
    target: Optional[str] = None
    os_platform: str = "unknown"  # linux, windows, macos, unknown
    window_duration_seconds: int = 900
    created_at: Optional[datetime] = None
    ioa_summary: Optional[str] = None
    # Pre-computed risk fields from normalization — eliminates JOIN to normalized_events for scoring engine
    max_inline_risk_score: int = 0          # Highest inline_risk_score across all events in window (0-100)
    ocsf_severity_id: Optional[int] = None  # Highest OCSF severity_id in window (1=Info, 2=Low, 3=Med, 4=High, 5=Critical, 6=Fatal)
    is_suppressed: bool = False
    suppression_rule_id: Optional[str] = None
    suppression_reason: Optional[str] = None
    # MISP-readiness fields (Migration 004)
    tlp_level: str = "TLP:AMBER"                       # TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:AMBER+STRICT, TLP:RED
    mitre_technique_id: Optional[str] = None            # ATT&CK technique ID (e.g., T1078, T1190)
    # Metadata fields (Migration 007 & 008)
    mitre_tactics: List[str] = Field(default_factory=list)
    classification_groups: List[str] = Field(default_factory=list)
    log_source: Optional[str] = None
    distinct_ioas: List[str] = Field(default_factory=list)
    distinct_iocs: List[str] = Field(default_factory=list)
    dominant_http_status: Optional[int] = None
    is_scanner_ua: bool = False


class CumulativeAlertDB(BaseModel):
    """Database model for table: cumulative_alerts (lifetime entity tracking without window cutoff)"""
    cumulative_id: str
    deduplication_key: str
    category: str = "SYSTEM_HEALTH"
    rule_id: int
    rule_description: Optional[str] = None
    actor: Optional[str] = None
    target: Optional[str] = None
    os_platform: str = "unknown"  # linux, windows, macos, unknown
    agent_id: str
    tenant_id: str = "DEFAULT"
    total_event_count: int = 1
    total_burst_windows: int = 1
    first_seen_at: datetime
    last_seen_at: datetime
    status: str = "ACTIVE"  # ACTIVE, DORMANT
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    ioa_summary: Optional[str] = None
    peak_risk_score: int = 0  # All-time highest inline_risk_score ever seen for this entity pattern
    # MISP-readiness fields (Migration 004)
    tlp_level: str = "TLP:AMBER"  # TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:AMBER+STRICT, TLP:RED
    sighting_count: int = 0       # MISP sighting counter for threat intelligence sharing
    source_feed: str = "wazuh-pipeline"  # Origin feed identifier for MISP event attribution
    stix_indicator_id: Optional[str] = None   # STIX 2.1 Indicator ID for cross-platform correlation
    mitre_technique_id: Optional[str] = None  # ATT&CK technique ID (e.g., T1078, T1190)


class AggregateEvidenceMappingDB(BaseModel):
    """Database model for table: aggregate_evidence_mapping"""
    aggregation_id: str
    raw_event_id: str
    event_timestamp: datetime
    mapped_at: Optional[datetime] = None


# ============================================================================
# 4. BEHAVIORAL CORRELATION & INCIDENT MODELS (STAGE 4)
# ============================================================================

class CorrelationRuleDB(BaseModel):
    """Database model for table: correlation_rules"""
    correlation_rule_id: str
    rule_code: str
    rule_name: str
    description: str
    timeframe_seconds: int
    target_severity: str  # P0, P1, P2, P3
    is_active: bool = True
    created_at: Optional[datetime] = None


class CorrelatedIncidentDB(BaseModel):
    """Database model for table: correlated_incidents"""
    incident_id: str
    correlation_rule_id: str
    tenant_id: str = "DEFAULT"
    title: str
    narrative: str
    initial_access_vector: Optional[str] = None
    attacker_source_ip: Optional[str] = None
    compromised_account: Optional[str] = None
    target_host: Optional[str] = None
    incident_status: str = "DETECTED"  # DETECTED, IN_TRIAGE, ESCALATED, CONTAINED, RESOLVED, CLOSED_FP
    first_seen_at: datetime
    last_seen_at: datetime
    related_incident_ids: List[str] = Field(default_factory=list)
    detected_at: Optional[datetime] = None


class IncidentStageDB(BaseModel):
    """Database model for table: incident_stages"""
    stage_id: Optional[int] = None
    incident_id: str
    sequence_order: int
    stage_name: str
    reference_id: str
    evidence_type: str  # AGGREGATED_ALERT, NORMALIZED_EVENT, CUMULATIVE_PROFILE
    stage_description: Optional[str] = None
    recorded_at: Optional[datetime] = None


# ============================================================================
# 5. DYNAMIC RISK SCORING MODELS (STAGE 5)
# ============================================================================

class RiskScoringFactorDB(BaseModel):
    """Database model for table: risk_scoring_factors"""
    factor_id: Optional[int] = None
    incident_id: str
    factor_type: str  # DETECTION_SEVERITY, ASSET_CRITICALITY, IDENTITY_RISK, THREAT_INTELLIGENCE, BEHAVIORAL_ANOMALY, CORRELATION_CHAIN, KNOWN_GOOD_OFFSET, CONFIDENCE_DEPTH
    weight_added: int  # -100..100
    justification: Optional[str] = None
    evaluated_at: Optional[datetime] = None


class CalculatedRiskScoreDB(BaseModel):
    """Database model for table: calculated_risk_scores (with P0-P4 Invariant)"""
    score_id: Optional[int] = None
    incident_id: str
    total_score: int  # 0..100
    soc_priority: str  # P0, P1, P2, P3, P4
    scoring_version: str = "v1.0"
    calculated_at: Optional[datetime] = None

    # PRD Section 8 #9: Mapping P0-P4 berbasis skor sudah dihapus.
    # Priority ditentukan oleh kategori aggregate, bukan oleh score.


# ============================================================================
# 6. SOC TRIAGE, RESPONSE & NOTES MODELS (STAGE 6)
# ============================================================================

class SocTriageQueueDB(BaseModel):
    """Database model for table: soc_triage_queue (100% aligned with User Flow)"""
    triage_id: str
    incident_id: str
    actor: Optional[str] = None
    target: Optional[str] = None
    tenant_id: str = "DEFAULT"
    os_platform: str = "unknown"
    induk_aggregation_id: Optional[str] = None
    sla_deadline: Optional[datetime] = None
    window_buffer_until: Optional[datetime] = None
    iris_case_id: Optional[int] = None
    iris_case_url: Optional[str] = None
    misp_event_id: Optional[int] = None
    misp_sync_status: str = "NOT_SYNCED"
    assigned_analyst: Optional[str] = None
    priority: str = "P3"  # Standard incident priority
    triage_status: str = "OPEN"  # OPEN, INVESTIGATE, CLOSE, WAITING, APPROVE, REJECT, FP Reject, AUTO_CLOSED, ESCALATED_IRIS, WAITING_SLA
    resolution_outcome: Optional[str] = None
    false_positive_reason: Optional[str] = None
    mean_time_to_triage_seconds: Optional[int] = None
    is_verified_true_positive: bool = False
    ground_truth_verdict: Optional[str] = None  # BENIGN, THREAT
    analyst_notes: Optional[str] = None
    manager_review_notes: Optional[str] = None
    manager_reviewer: Optional[str] = None
    manager_reviewed_at: Optional[datetime] = None
    reject_count: int = 0
    parent_triage_id: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    cooldown_until: Optional[datetime] = None


class TicketAggregateDB(BaseModel):
    """Database model for table: ticket_aggregates (1 Induk + Correlated Aggregates)"""
    ticket_id: str
    aggregation_id: str
    is_induk: bool = False
    is_escalation_trigger: bool = False
    added_at: Optional[datetime] = None


class PolicyBundleDB(BaseModel):
    """Database model for table: policy_bundles (Per-tenant benign clusters for SOC Dev audit)"""
    bundle_id: str
    tenant_id: str
    ticket_id: Optional[str] = None
    actor: str
    target: str
    wazuh_rule_ids: List[int] = Field(default_factory=list)
    bundle_status: str = "PENDING_DEV_AUDIT"
    developer_notes: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class WazuhRuleProposalDB(BaseModel):
    """Database model for table: wazuh_rule_proposals (Separation of duties: Dev creates/tests, Manager approves)"""
    proposal_id: str
    bundle_id: str
    tenant_id: str
    proposal_type: str  # CDB_LIST, XML_RULE
    rule_content: str
    business_reason: str
    logtest_status: str = "NOT_TESTED"  # PASSED, FAILED, NOT_TESTED
    logtest_output: Optional[str] = None
    developer_author: str
    manager_approver: Optional[str] = None
    manager_rejection_reason: Optional[str] = None
    approval_status: str = "PENDING_APPROVAL"  # PENDING_APPROVAL, APPROVED, REJECTED
    expires_date: date
    is_deployed_to_wazuh: bool = False
    deployed_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class IncidentInvestigationNoteDB(BaseModel):
    """Database model for table: incident_investigation_notes"""
    note_id: Optional[int] = None
    incident_id: str
    analyst_name: str
    note_text: str
    created_at: Optional[datetime] = None


class IncidentResponseActionDB(BaseModel):
    """Database model for table: incident_response_actions"""
    action_id: Optional[int] = None
    incident_id: str
    action_type: str  # HOST_ISOLATION, IP_BLOCK_FIREWALL, USER_ACCOUNT_DISABLE, PROCESS_TERMINATION, ENABLE_AUDIT_MODE, CUSTOM_SCRIPT
    target_entity: str
    initiated_by: str
    execution_status: str = "PENDING"  # PENDING, SUCCESS, FAILED, ROLLED_BACK
    execution_output: Optional[str] = None
    executed_at: Optional[datetime] = None


# ============================================================================
# 7. OPERATIONAL METRICS & KPI MODEL (STAGE 7)
# ============================================================================

class OperationalMetricsDailyDB(BaseModel):
    """Database model for table: operational_metrics_daily"""
    metric_date: date
    raw_events_count: int = 0
    wazuh_alerts_count: int = 0
    suppressed_events_count: int = 0
    aggregated_alerts_count: int = 0
    correlated_incidents_count: int = 0
    analyst_reviewed_count: int = 0
    true_positives_count: int = 0
    actionable_incidents_count: int = 0
    suppression_escapes_count: int = 0
    avg_mean_time_to_triage_sec: float = 0.0
    alert_reduction_percentage: Optional[Decimal] = None
    created_at: Optional[datetime] = None
