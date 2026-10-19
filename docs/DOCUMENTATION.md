# Wazuh Enterprise Multi-Stage Alert Grouping & Fatigue Reduction Pipeline
## Exhaustive Technical Documentation
### Version 2.1.0 — Generated September 2026

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Overview](#2-architecture-overview)
3. [Repository Structure](#3-repository-structure)
4. [Dependencies & Environment](#4-dependencies--environment)
5. [Configuration Layer](#5-configuration-layer)
6. [Data Models — pipeline/models.py](#6-data-models--pipelinemodelspy)
7. [Stage 1: Ingestion & Normalization — pipeline/ingest.py](#7-stage-1-ingestion--normalization--pipelineingestpy)
8. [Normalization Plugins — pipeline/normalization_plugins.py](#8-normalization-plugins--pipelinenormalization_pluginspy)
9. [Stage 2: Deduplication — pipeline/deduplicate.py](#9-stage-2-deduplication--pipelinededuplicatepy)
10. [Suppression Governance — pipeline/governance.py](#10-suppression-governance--pipelinegovernancepy)
11. [Stage 3: Behavioral Correlation — pipeline/correlate.py](#11-stage-3-behavioral-correlation--pipelinecorrelatepy)
12. [Stage 4: Dynamic Risk Scoring — pipeline/score.py](#12-stage-4-dynamic-risk-scoring--pipelinescorepy)
13. [Data Layer — pipeline/database.py](#13-data-layer--pipelinedaborabasepy)
14. [Supplementary Modules](#14-supplementary-modules)
15. [Pipeline Orchestrator — run_master_pipeline.py](#15-pipeline-orchestrator--run_master_pipelinepy)
16. [Package Init — pipeline/__init__.py](#16-package-init--pipeline__init__py)
17. [Database Schema Reference](#17-database-schema-reference)
18. [Suppression Taxonomy (S1–S5)](#18-suppression-taxonomy-s1s5)
19. [MISP & Threat Intelligence Integration](#19-misp--threat-intelligence-integration)
20. [Operational Runbook](#20-operational-runbook)

---


## 1. Executive Summary

This repository implements a **production-grade, multi-stage alert grouping, noise reduction, and incident triage pipeline** for Wazuh SIEM deployments. It eliminates SOC Alert Fatigue by reducing raw alert noise volume by **97.75%** while preserving **100% of raw forensic evidence**.

### Benchmark Performance (July 2026 — 840,402 Alerts / 1.14 GB)

| Metric | Value |
|--------|-------|
| Raw Ingestion Volume | 840,402 alerts across 5 weekly batches |
| Aggregated Output | 18,939 alert objects |
| Noise Reduction | **97.75%** |
| Compression Ratio | 44.4 : 1 |
| Correlated Attacks | 2 confirmed P1 Intrusion Incidents |
| Forensic Evidence Links | 840,402 links in `aggregate_evidence_mapping` |
| Throughput | ~7,000–11,000 alerts/second |

### Core Design Principles

1. **Zero Data Loss** — Every raw alert preserved in `telemetry.raw_events`, linked via `aggregate_evidence_mapping`
2. **Policy-Driven Suppression** — All decisions auditable, governed by S1–S5 taxonomy, enforced by PostgreSQL CHECK constraints
3. **Never-Suppress Guard** — P0/P1 critical alerts have absolute immunity from suppression
4. **Config-Driven** — All behavioral rules, scoring weights, OCSF mappings, MITRE enrichments externalized to JSON
5. **Graceful Degradation** — Database unavailability never crashes the pipeline
6. **Crash Recovery** — In-flight dedup windows persisted to disk snapshots and restored on restart




## 2. Architecture Overview

```
[Wazuh Logs] → [Stage 1: Ingest/Normalize] → [Stage 2: Sliding-Window Dedup]
  → [Stage 3: Attack Correlation] → [Stage 4: Risk Scoring]
  → [PostgreSQL 19 Tables] → [SOC Triage Dashboard]
```

### Pipeline Stages

| Stage | Module | Input | Output |
|-------|--------|-------|--------|
| 1 | `ingest.py` + `normalization_plugins.py` | Raw JSON alerts | `CommonEventModel` |
| 2 | `deduplicate.py` + `governance.py` | CEMs | Aggregated windows (ACTIONABLE/SUPPRESSED) |
| 3 | `correlate.py` | ACTIONABLE aggregates | Correlated Incidents |
| 4 | `score.py` | Incidents | Scored & prioritized incidents (P0–P4) |
| Post | TI sync, EDF view, retention, burst consolidation | DB state | Updated enrichments |

### Data Flow Per Event

1. Raw JSON alert read by `AlertStreamReader` (10,000-record chunks)
2. Parsed into `WazuhRawAlert`, normalized to `CommonEventModel`
3. `CanonicalAssetResolver` resolves host criticality tier
4. `classify_event_archetype` assigns 1 of 20 event categories + actor/target/track speed
5. Plugin chain: OCSF → MITRE → inline risk score → IOC extraction
6. `generate_ioa_summary` creates human-readable IOA summary
7. CEM enters `SlidingWindowAggregator` — dedup key computed, window opened/merged
8. On window close: governance check (S1–S5) → ACTIONABLE or SUPPRESSED
9. ACTIONABLE aggregates enter `CorrelationEngine` (8 behavioral rules)
10. Incidents scored by `RiskScorer` (0–100 → P0–P4)
11. All data persisted via `DatabaseManager` bulk operations

## 3. Repository Structure

```
wazuh alert grouping -/
├── config/
│   ├── settings.py                      # Central config (DB creds, paths, constants)
│   ├── aggregation_rules.json           # 20-category event routing taxonomy
│   ├── suppression_rules_registry.json  # S1–S5 suppression policy registry
│   ├── correlation_rules.json           # 8 behavioral correlation rules
│   ├── ocsf_mapping.json               # OCSF v1.3 field mapping
│   ├── mitre_community_supplement.json  # MITRE ATT&CK gap-fill data
│   ├── inline_risk_weights.json         # Inline risk scorer weights
│   └── retention_policy.json            # 30-day rolling retention config
├── pipeline/
│   ├── __init__.py                      # Package exports & version (2.1.0)
│   ├── models.py                        # Pydantic v2 data models
│   ├── ingest.py                        # Stage 1: Streaming ingestion
│   ├── normalization_plugins.py         # Plugin chain (4 built-in plugins)
│   ├── deduplicate.py                   # Stage 2: Sliding-window dedup
│   ├── governance.py                    # Stage 2/7: Suppression governance
│   ├── correlate.py                     # Stage 3: Behavioral correlation
│   ├── score.py                         # Stage 4: Risk scoring
│   ├── database.py                      # Data layer: PostgreSQL driver
│   ├── threat_intel_sync.py             # TI harvester & enrichment
│   ├── sync_live_ti_to_scores.py        # Live TI → score recalculation
│   ├── update_edf_view.py               # EDF priority queue view
│   ├── retention_manager.py             # 30-day retention manager
│   └── consolidate_standalone_bursts.py # Burst consolidation
├── run_master_pipeline.py               # Top-level orchestrator
├── requirements.txt                     # Python dependencies
└── README.md                            # Project overview
```

## 4. Dependencies & Environment

### requirements.txt

| Package | Version | Purpose |
|---------|---------|---------|
| `pydantic` | ≥ 2.5.0 | Data model validation (CEM, DB schemas) |
| `psycopg2-binary` | ≥ 2.9.9 | PostgreSQL driver |
| `polars` | ≥ 0.20.0 | High-performance DataFrame operations |
| `pytest` | ≥ 8.0.0 | Test framework (152+ tests) |
| `pytest-cov` | ≥ 4.1.0 | Coverage reporting |
| `rich` | ≥ 13.7.0 | Terminal formatting |
| `python-dotenv` | ≥ 1.0.0 | `.env` file loading |

**Runtime**: Python 3.10+, PostgreSQL 14+, Windows or Linux.




## 5. Configuration Layer

The pipeline is heavily config-driven, allowing SOC engineers and analysts to modify routing rules, suppression behavior, risk scoring weights, and correlation policies without altering Python code.

### 5.1 config/settings.py

Centralized settings management supporting environment variables and `.env` fallback.

```python
# Database Settings
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "postgres")
DB_NAME = os.getenv("DB_NAME", "wazuh_soc_db")

# Connection Pool Defaults
DB_POOL_MIN_CONN = int(os.getenv("DB_POOL_MIN_CONN", "4"))
DB_POOL_MAX_CONN = int(os.getenv("DB_POOL_MAX_CONN", "30"))

# File / Directory Paths (using pathlib.Path for cross-platform support)
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("DATA_DIR", BASE_DIR / "data"))
CONFIG_DIR = BASE_DIR / "config"
PERSISTENCE_DIR = BASE_DIR / "persistence"  # Stores dedup & correlation state snapshots

# Aggregation & Ingestion Defaults
DEFAULT_CHUNK_SIZE = int(os.getenv("CHUNK_SIZE", "10000"))
DEFAULT_WINDOW_MINUTES = int(os.getenv("WINDOW_MINUTES", "15"))
BURST_THRESHOLD = int(os.getenv("BURST_THRESHOLD", "10"))

# Pipeline Global Flags
ENABLE_THREAT_INTEL = os.getenv("ENABLE_THREAT_INTEL", "true").lower() in ("true", "1", "yes")
ENABLE_OCSF_EXPORT = os.getenv("ENABLE_OCSF_EXPORT", "true").lower() in ("true", "1", "yes")
```

- **Persistence Directory**: `persistence/` holds `dedup_state_snapshot.json` and `correlation_state_snapshot.json` for crash recovery and stateful pipeline restarts.
- **Connection Pooling**: Uses `psycopg2.pool.ThreadedConnectionPool` configured with minimum 4 and maximum 30 connections.

---

### 5.2 config/aggregation_rules.json

Defines the 20-category taxonomy, track speed assignments, window durations, dedup key components, and routing priorities.

- **Window Profiles**:
  - `STANDARD`: 15-minute sliding window (900 seconds). Applied to network, web, auth, and fast-moving attacks.
  - `SLOW`: 30-minute sliding window (1800 seconds). Applied to FIM, vulnerability scans, system health, and scheduled audits.
- **Dedup Key Formula**: Canonical dedup keys are formed deterministically per category:
  - Auth: `hash(tenant_id + category + source_ip + target_user + target_host)`
  - Web: `hash(tenant_id + category + source_ip + uri_path + http_status)`
  - Endpoint/Process: `hash(tenant_id + category + agent_id + process_path + command_line_hash)`
  - FIM/Integrity: `hash(tenant_id + category + agent_id + file_path + change_type)`

---

### 5.3 config/suppression_rules_registry.json

Structured repository of active suppression rules aligned with the S1–S5 policy taxonomy.

- **Structure**: Each rule defines `suppression_id`, `rule_name`, `suppression_class` (`S1_KNOWN_GOOD`, `S2_FALSE_POSITIVE`, `S3_MAINTENANCE`, `S4_EXCEPTION`, `S5_CONDITIONAL`), `target_rule_ids`, `match_criteria` (field exact/regex matches), `scope` (`GLOBAL` vs `TENANT`), and `sla_expiry_timestamp`.
- **Enforcement**: Validated at ingestion against the database's `suppression.suppression_rules` table and evaluated during window finalization in `governance.py`.
- **Never-Suppress Safeguard**: Checked before any rule in this registry can execute.

---

### 5.4 config/correlation_rules.json

Externalized definitions of 8 behavioral correlation rules (CORR-001 through CORR-008):

| Rule ID | Name | Trigger Condition | Multi-Stage Chain | Target Severity |
|---------|------|-------------------|-------------------|-----------------|
| `CORR-001` | Multi-Stage Web Intrusion & Remote Shell | Web exploit (SQLi/RFI/LFI) followed by process execution | WEB_OPERATIONAL → EXECUTION | P1 / P0 |
| `CORR-002` | Lateral Movement via Privileged Account | Credential dumping/spray followed by remote SMB/SSH login | AUTH_ANOMALY → NETWORK_TRAFFIC | P1 |
| `CORR-003` | Ransomware Precursor Activity | Mass file modifications + shadow copy deletion command | FILE_INTEGRITY → COMMAND_CONTROL | P0 |
| `CORR-004` | High Burst Anomaly & Sustained Sweep | Standalone burst exceeding 100 events or 3+ repeat windows | RECONNAISSANCE_PROBE | P2 / P3 |
| `CORR-005` | Defense Evasion via Log Clearing | Wazuh agent service stop or EventLog clear commands | DEFENSE_EVASION → EXECUTION | P1 |
| `CORR-006` | Data Exfiltration Over Non-Standard Port | High outbound network transfer to unknown external IP | NETWORK_TRAFFIC → EXFILTRATION | P2 |
| `CORR-007` | Privilege Escalation to Root/SYSTEM | Standard user session spawning UID 0 / SYSTEM shell | AUTH_ANOMALY → PRIVILEGE_ESCALATION | P1 |
| `CORR-008` | Cloud / Container Escape & API Abuse | Container breakout indicator or IAM token enumeration | CLOUD_CONTAINER → PERSISTENCE | P1 |

---

### 5.5 Additional Configuration Files

- **`config/ocsf_mapping.json`**: Maps internal event categories to OCSF v1.3 classes (`class_uid`, `category_uid`, `activity_id`) and establishes severity offset biases.
- **`config/mitre_community_supplement.json`**: Fallback dictionary of Wazuh rule IDs mapped to MITRE ATT&CK tactics, techniques, and sub-techniques.
- **`config/inline_risk_weights.json`**: Weight parameters, multipliers, and asset criticality scores for the Stage 1 inline risk calculator.
- **`config/retention_policy.json`**: 30-day retention parameters, target tables, batch chunk sizes, and vacuum settings.



## 6. Data Models — pipeline/models.py

The data layer uses **Pydantic v2** models to enforce strict schema validation, type safety, and JSON serialization.

### 6.1 CommonEventModel (CEM)

The central unified data representation for every security event passing through the pipeline. Every raw Wazuh alert is normalized into a CEM before downstream processing.

| Field Name | Type | Description |
|------------|------|-------------|
| `event_id` | `str` | Unique UUID or Wazuh alert ID (`id` or generated) |
| `timestamp` | `datetime` | UTC timestamp of event occurrence |
| `tenant_id` | `str` | Multi-tenant identifier (defaults to `"DEFAULT"`) |
| `agent_id` | `Optional[str]` | Wazuh agent ID (e.g., `"001"`, `"000"` for manager) |
| `agent_name` | `str` | Hostname / agent name |
| `agent_ip` | `Optional[str]` | IP address of reporting Wazuh agent |
| `host_criticality` | `str` | Asset tier: `CROWN_JEWEL`, `CRITICAL`, `STANDARD`, `DEV_TEST` |
| `source_ip` | `Optional[str]` | Source / attacker IPv4/IPv6 address |
| `source_port` | `Optional[int]` | Source TCP/UDP port |
| `destination_ip` | `Optional[str]` | Target / server IPv4/IPv6 address |
| `destination_port` | `Optional[int]` | Target TCP/UDP port |
| `protocol` | `Optional[str]` | Transport protocol (`tcp`, `udp`, `icmp`) |
| `username` | `Optional[str]` | User account associated with event |
| `process_name` | `Optional[str]` | Executable file name |
| `process_path` | `Optional[str]` | Absolute path of executable |
| `process_id` | `Optional[int]` | OS PID |
| `parent_process_name` | `Optional[str]` | Spawning parent executable |
| `command_line` | `Optional[str]` | Process command line invocation |
| `rule_id` | `str` | Native Wazuh rule ID (e.g., `"5710"`, `"100002"`) |
| `rule_level` | `int` | Wazuh rule severity level (0–16) |
| `rule_description` | `str` | Human-readable rule title |
| `rule_groups` | `List[str]` | Rule group tags (`web`, `authentication`, `syscheck`, etc.) |
| `event_category` | `str` | Pipeline 20-category classification |
| `track_speed` | `str` | `STANDARD` (15m window) or `SLOW` (30m window) |
| `window_duration_seconds` | `int` | 900 or 1800 seconds |
| `actor` | `str` | Resolved primary threat actor identifier |
| `target` | `str` | Resolved primary attack target identifier |
| `canonical_dedup_key` | `str` | MD5 hash defining unique aggregation bucket |
| `mitre_tactics` | `List[str]` | MITRE ATT&CK tactics (e.g., `["Initial Access"]`) |
| `mitre_attack_ids` | `List[str]` | MITRE ATT&CK technique IDs (e.g., `["T1190"]`) |
| `ocsf_class_uid` | `Optional[int]` | OCSF v1.3 class identifier |
| `ocsf_category_uid` | `Optional[int]` | OCSF v1.3 category identifier |
| `ocsf_activity_id` | `Optional[int]` | OCSF v1.3 activity identifier |
| `ocsf_severity_id` | `Optional[int]` | OCSF v1.3 normalized severity (1–6) |
| `inline_risk_score` | `int` | Real-time score computed during Stage 1 (0–100) |
| `threat_intel_match` | `bool` | True if source IP matches active malicious feed |
| `threat_intel_confidence` | `int` | AbuseIPDB / feed confidence percentage (0–100) |
| `extracted_iocs` | `Optional[Dict[str, List[str]]]` | Regex-extracted IPs, hashes, domains, CVEs |
| `ioa_summary` | `str` | Indicator of Attack context summary |
| `raw_payload` | `str` | Original raw JSON string for full forensic audit |

---

### 6.2 Database Persistence Models

- **`AggregatedAlertDB`**: Represents one closed window in `suppression.aggregated_alerts`. Contains window start/end, total event count, suppression state (`ACTIONABLE` vs `SUPPRESSED`), suppression class (`S1`–`S5`), maximum inline risk score, and MITRE attribution.
- **`CumulativeAlertDB`**: Represents long-term entity tracking in `suppression.cumulative_alerts`. Maintains persistent counters for total lifetime events and total burst windows observed for an actor/target pair, along with dormancy status (`ACTIVE` vs `DORMANT`).
- **`AggregateEvidenceMappingDB`**: Stores 1-to-many forensic links in `suppression.aggregate_evidence_mapping`, linking each `raw_event_id` to its enclosing `aggregate_id` to ensure 100% evidentiary traceability without data loss.



## 7. Stage 1: Ingestion & Normalization — pipeline/ingest.py

The ingestion layer transforms heterogeneous, high-volume raw JSON alert streams into strongly-typed `CommonEventModel` instances with asset context and classification.

### 7.1 AlertStreamReader

A generator-based streaming parser engineered for memory efficiency when processing multi-gigabyte log archives:

```python
class AlertStreamReader:
    def __init__(self, filepath: str, chunk_size: int = 10000):
        self.filepath = filepath
        self.chunk_size = chunk_size

    def stream_chunks(self) -> Generator[List[Dict[str, Any]], None, None]:
        """Yields chunks of parsed raw dictionaries."""
        ...

    def stream_normalized_events(self) -> Generator[CommonEventModel, None, None]:
        """Yields fully normalized and plugin-enriched CommonEventModel instances."""
        ...
```

- **Dual-Mode Streaming**: Automatically detects whether the input file is a standard JSON array (`[...]`) or Newline-Delimited JSON (NDJSON).
- **Bounded Memory**: Memory footprint remains under **100 MB RAM** regardless of input file size by streaming records in bounded chunks (default: 10,000 records).
- **Throughput**: Processes between **7,000 and 11,000 events/second** on standard hardware.

---

### 7.2 CanonicalAssetResolver

Enriches hostnames and agent IPs with an asset criticality tier:

- **Tiers**:
  - `CROWN_JEWEL`: Active Directory Domain Controllers, production database servers, secret vaults (multipliers applied in risk scoring).
  - `CRITICAL`: Public-facing web servers, API gateways, payment endpoints.
  - `STANDARD`: General corporate workstations, internal file shares, utility servers.
  - `DEV_TEST`: Ephemeral development, staging, or CI/CD runner environments.
- **Resolution Priority**: Evaluates static asset mappings, falls back to hostname regex patterns (e.g., `dc-.*`, `prod-.*`, `test-.*`), and defaults to `STANDARD`.

---

### 7.3 classify_event_archetype()

A robust, 3-tier heuristic classification engine mapping raw Wazuh alerts into one of **20 security categories**:

1. **Tier 1 (Authoritative Match)**: Inspects `rule.groups`, `decoder.name`, and rule description keywords:
   - `AUTH_ANOMALY`: Authentication failures, brute-force attempts, SSH invalid users.
   - `PRIVILEGE_ESCALATION`: `sudo` usage, UAC bypass, token impersonation, setuid execution.
   - `DEFENSE_EVASION`: Disabling logging, stopping agent services, audit log clears.
   - `PERSISTENCE`: Scheduled tasks, cron jobs, registry run keys, systemd service installation.
   - `COMMAND_CONTROL`: Cobalt Strike beacons, reverse shells, dynamic DNS lookups.
   - `CREDENTIAL_ACCESS`: Mimikatz, `/etc/shadow` reads, LSASS dumps, SAM registry extraction.
   - `LATERAL_MOVEMENT`: PsExec, WMI remote execution, SMB share enumeration, WinRM calls.
   - `EXFILTRATION`: Unusual outbound data volumes, cloud sync uploads, DNS tunneling.
   - `EXECUTION`: Suspicious powershell/bash flags, LOLBins (`certutil`, `bitsadmin`, `mshta`).
   - `DISCOVERY`: Port scanning, network sweeps, `net user`, `whoami /priv`.
   - `INITIAL_ACCESS`: Phishing attachments, external vulnerability exploitation.
   - `IMPACT`: Ransomware extensions, disk wiping, defacement, service disruption.
   - `NETWORK_TRAFFIC`: Firewall drops, IDS/IPS alerts, Suricata/Snort signatures.
   - `MALWARE`: ClamAV hits, EDR malware detections, suspicious binary execution.
   - `ROOTCHECK`: Wazuh rootcheck engine, hidden ports, altered system binaries.
   - `WEB_OPERATIONAL`: Nginx/Apache 4xx/5xx errors, directory traversal, standard 404 scans.
   - `FILE_INTEGRITY`: Syscheck FIM changes, modified binaries, checksum mismatches.
   - `VULNERABILITY`: Wazuh vulnerability detector hits, CVE identifications.
   - `CONFIGURATION_ASSESSMENT`: SCA scans, CIS benchmark failures, policy compliance checks.
   - `CLOUD_CONTAINER`: Docker, Kubernetes, AWS CloudTrail, Azure Activity Log events.
2. **Tier 2 (Dynamic Entity Signals)**: Routes alerts with IP pairs to `WEB_OPERATIONAL`, process names to `EXECUTION`, and high rule levels (≥6) to `EXECUTION`.
3. **Tier 3 (Universal Fallback)**: Safe fallback to `SYSTEM_HEALTH` (`service:systemd`, `SLOW` track).

---

### 7.4 generate_ioa_summary()

100% data-driven Indicator of Attack context generator that creates concise, human-readable summaries without dynamic parameter explosion:

- Extracts HTTP status codes from `data.status` or regex matching.
- Appends primary MITRE technique tag when available.
- Formats category-specific narratives (e.g., `web: 404_not_found | uri: /admin/login.php | mitre: T1190`).



## 8. Normalization Plugins — pipeline/normalization_plugins.py

An extensible, open-closed plugin architecture allowing SOC engineers to inject custom enrichment and transformation logic into Stage 1 without touching core ingest code.

### 8.1 Plugin Interface

All plugins inherit from the abstract base class `NormalizationPlugin`:

```python
class NormalizationPlugin(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique human-readable identifier for logging."""
        ...

    @abstractmethod
    def enrich(self, cem: Any, raw: Any) -> Any:
        """Enriches and returns the CommonEventModel."""
        ...
```

- **Performance Contract**: Must complete in **< 500 microseconds** per event.
- **Zero I/O Rule**: Plugins must never perform database, network, or disk I/O inside `enrich()`. All configurations and lookups are pre-loaded in memory.
- **Fail-Safe Execution**: Handled via `run_plugin_chain(cem, raw)` — any unhandled exception inside a plugin is trapped, logged, and isolated without aborting the event.

---

### 8.2 Built-In Active Plugins

The default pipeline executes four plugins in strict sequential order:

```
CommonEventModel
       │
       ▼
1. OCSFFieldMapperPlugin         (Maps to OCSF v1.3 taxonomy)
       │
       ▼
2. MITRECommunitySupplementPlugin (Fills ATT&CK gaps for unannotated rules)
       │
       ▼
3. InlineRiskScorerPlugin        (Computes 0-100 real-time risk score)
       │
       ▼
4. GenericIOCExtractorPlugin     (Extracts IPs, hashes, domains, CVEs via regex)
       │
       ▼
Enriched CommonEventModel
```

#### 1. OCSFFieldMapperPlugin
Maps internal security event categories to the **Open Cybersecurity Schema Framework (OCSF v1.3)**:
- Populates `ocsf_class_uid`, `ocsf_category_uid`, `ocsf_activity_id`, and `ocsf_severity_id`.
- Driven entirely by `config/ocsf_mapping.json`.
- Applies category severity biases (e.g., `MALWARE` adds +2 to base OCSF severity, capped at 6).

#### 2. MITRECommunitySupplementPlugin
Fills missing MITRE ATT&CK tactics, techniques, and IDs for Wazuh rules that lack native MITRE annotations in their XML definitions:
- Driven by `config/mitre_community_supplement.json`.
- Only activates as a tertiary fallback if both native rule metadata and upstream decoders failed to provide MITRE tags.

#### 3. InlineRiskScorerPlugin
Computes an instantaneous, preliminary risk score (0–100) on each individual event during ingestion:
- **Formula**:
  $$\text{Score} = \min\left(100, (\text{rule\_level} \times \text{multiplier}) + \text{asset\_score} + \text{ocsf\_bias} + \text{bonuses}\right)$$
- Driven by `config/inline_risk_weights.json`.
- Applies asset criticality weighting (`CROWN_JEWEL` adds +25, `CRITICAL` adds +15).
- Grants bonus points if threat intel indicates a known malicious IP.

#### 4. GenericIOCExtractorPlugin
High-speed fallback IOC harvester utilizing pre-compiled regular expressions:
- Scans `full_log`, `raw_payload`, and `rule_description`.
- Extracts:
  - **IPv4**: Public routable addresses (RFC 1918, RFC 3927, and loopback ranges excluded).
  - **File Hashes**: SHA-256 (64 hex), SHA-1 (40 hex), MD5 (32 hex).
  - **Domains**: Valid TLD domain patterns.
  - **CVE Identifiers**: Matches `CVE-\d{4}-\d{4,7}` and auto-populates `ioa_summary`.
  - **URLs**: HTTP/HTTPS web endpoints.
- Results stored in `cem.extracted_iocs` for automated MISP threat intelligence export.



## 9. Stage 2: Deduplication & Sliding-Window Aggregation — pipeline/deduplicate.py

The core noise reduction engine. It collapses thousands of repetitive, high-frequency security alerts into consolidated **Aggregated Windows** while preserving forensic linkage to every individual underlying event.

### 9.1 calculate_canonical_dedup_key()

Generates a deterministic 32-character MD5 hash representing the aggregation bucket for an incoming event based on its category archetype:

```python
def calculate_canonical_dedup_key(cem: CommonEventModel) -> str:
    # Dynamic field selection based on event_category
    ...
```

- **Authentication Anomaly**: `tenant_id | AUTH_ANOMALY | source_ip | username | target_host`
- **Web Operational**: `tenant_id | WEB_OPERATIONAL | source_ip | uri_path | http_status`
- **Host / Execution**: `tenant_id | EXECUTION | agent_id | process_name | command_line_hash`
- **File Integrity**: `tenant_id | FILE_INTEGRITY | agent_id | file_path | change_type`
- **Network Traffic**: `tenant_id | NETWORK_TRAFFIC | source_ip | destination_ip | destination_port`
- **Default Fallback**: `tenant_id | category | actor | target`

---

### 9.2 AggregatedWindow

Represents a temporal grouping container for a specific deduplication key:

- **State Tracking**:
  - `window_start` / `window_end`: Exact UTC boundary timestamps.
  - `event_count`: Number of raw alerts collapsed into this bucket.
  - `evidence_event_ids`: Ordered list of `raw_event_id` strings (preserved for forensic evidence linking).
  - `max_rule_level`: Highest Wazuh rule level observed within this window.
  - `max_inline_risk_score`: Peak individual risk score among all child events.
  - `actor` / `target`: Primary threat actor and asset target entities.
  - `burst_detected`: True if `event_count >= BURST_THRESHOLD` (default: 10 events within 15 minutes).
- **Time Window Expiry**:
  - `is_expired(event_timestamp)` returns true when the event timestamp falls strictly beyond `window_start + window_duration_seconds`.

---

### 9.3 SlidingWindowAggregator

The stateful aggregation manager:

```python
class SlidingWindowAggregator:
    def __init__(self, default_window_seconds: int = 900):
        self.active_windows: Dict[str, AggregatedWindow] = {}
        ...

    def ingest_event(self, cem: CommonEventModel) -> List[Dict[str, Any]]:
        """Processes event, updates active window, emits closed windows."""
        ...

    def flush_all(self) -> List[Dict[str, Any]]:
        """Forces immediate finalization of all active in-flight windows."""
        ...

    def save_snapshot(self, filepath: Optional[str] = None) -> str:
        """Saves active state to JSON for crash recovery."""
        ...

    def load_snapshot(self, filepath: Optional[str] = None) -> int:
        """Restores in-flight state from disk snapshot."""
        ...
```

#### Deduplication Lifecycle
1. Event arrives with calculated `canonical_dedup_key`.
2. If an active window exists for this key:
   - Check if event timestamp is within window bounds.
   - If **within bounds**: Merge event, update peak scores, increment counter, append `event_id` to evidence list.
   - If **expired**: Finalize existing window, route to suppression governance, emit as ready aggregate, and instantiate a new active window starting at the current event's timestamp.
3. If no active window exists: Instantiate a new window.
4. On pipeline completion or shutdown: `flush_all()` drains and finalizes all in-flight windows.

#### Crash Recovery Mechanism
- `save_snapshot()` writes active window states to `persistence/dedup_state_snapshot.json`.
- On startup, if `--fresh` is not passed, `load_snapshot()` restores active windows, preventing window loss and duplicate ticket creation during pipeline reboots.



## 10. Stage 2/7: Suppression Governance — pipeline/governance.py

Enforces policy-driven alert suppression, SLA tracking, expiration auditing, and the absolute **Never-Suppress Guard**.

### 10.1 The S1–S5 Suppression Policy Taxonomy

Every suppression rule is classified into an auditable policy category:

| Class | Name | Intended Use Case | Default Expiry / SLA |
|-------|------|-------------------|----------------------|
| **S1** | `S1_KNOWN_GOOD` | Trusted baseline traffic, authorized vulnerability scanners, automated health checks, CDB allowlisted IPs. | 365 Days / Permanent |
| **S2** | `S2_FALSE_POSITIVE` | Confirmed false positive alerts verified by SOC Level 2/3 analysis. | 90 Days (Review Required) |
| **S3** | `S3_MAINTENANCE` | Temporary suppression during scheduled system maintenance, upgrades, or patch cycles. | Duration of Maintenance Window (< 24h) |
| **S4** | `S4_EXCEPTION` | Formally accepted business risks or legacy system exceptions with named business owners. | Maximum 180 Days |
| **S5** | `S5_CONDITIONAL` | Context-dependent suppression (restricted by day-of-week, business hours, subnet, or source geo). | 180 Days |

---

### 10.2 NeverSuppressGuard

A zero-bypass safety firewall protecting high-impact security incidents from accidental or malicious suppression.

```python
class NeverSuppressGuard:
    @staticmethod
    def evaluate(event_or_agg: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Returns (is_protected, protection_reason).
        If is_protected is True, the event CANNOT be suppressed under any circumstances.
        """
        ...
```

#### Absolute Immunity Invariants
1. **Critical Severity**: Rule level ≥ 12 or target severity `P0` / `P1`.
2. **Active Threat Intelligence**: Confirmed match against malicious feeds with confidence ≥ 70%.
3. **Critical Attack Categories**: `COMMAND_CONTROL`, `EXFILTRATION`, `IMPACT` (Ransomware), or `CREDENTIAL_ACCESS` against `CROWN_JEWEL` assets.
4. **Active Correlation Incident**: Any alert that is part of an in-flight, confirmed multi-stage attack track.

---

### 10.3 SuppressionGovernanceManager

The governance runtime controller:

```python
class SuppressionGovernanceManager:
    def __init__(self, db_manager: Optional[Any] = None):
        self._db = db_manager

    def evaluate_suppression(
        self,
        aggregate: Dict[str, Any]
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Returns (is_suppressed, suppression_class, suppression_rule_id).
        """
        ...
```

#### Evaluation Flow
1. **NeverSuppressGuard Check**: If the aggregate meets any critical criteria, suppression is vetoed immediately, returning `(False, None, None)` with an audit log reason.
2. **Active Rule Matching**: Matches aggregate parameters (`category`, `rule_id`, `actor`, `target`, `source_ip`) against active rules in `suppression.suppression_rules`.
3. **SLA Expiration Verification**: Checks if `NOW() > sla_expiry_timestamp`. Expired rules are automatically bypassed and flagged as `EXPIRED` in the database.
4. **Suppression Decision**: If an active, non-expired rule matches, the aggregate is tagged as `SUPPRESSED` with its corresponding `suppression_class` and `suppression_rule_id`.

---

### 10.4 Automated Expiration Auditing & SLA Management

The governance manager includes automated maintenance methods:
- **`audit_sla_expirations(conn)`**: Finds all rules where `sla_expiry_timestamp < CURRENT_TIMESTAMP` and transitions their status from `ACTIVE` to `EXPIRED`.
- **`get_group_detail(group_id, conn)`**: Retrieves parent-child suppression hierarchy for multi-tenant policy synchronization.



## 11. Stage 3: Behavioral Correlation — pipeline/correlate.py

The multi-stage behavioral correlation engine. It connects disparate security events across time, hostnames, and event categories to detect coordinated attack campaigns.

### 11.1 Behavioral Correlation Rules (CORR-001 – CORR-008)

The engine evaluates 8 behavioral attack sequence patterns loaded from `config/correlation_rules.json`:

```
1. CORR-001: Web Exploitation → Remote Execution (P1/P0)
   Stage 1: WEB_OPERATIONAL (SQLi, RFI, Path Traversal)
   Stage 2: EXECUTION (Shell spawn, LOLBin invocation)
   Window: 60 minutes | Keys: target_host

2. CORR-002: Lateral Movement via Credential Abuse (P1)
   Stage 1: CREDENTIAL_ACCESS (Dump / Spray)
   Stage 2: LATERAL_MOVEMENT (PsExec, WMI, SMB)
   Window: 120 minutes | Keys: attacker_source_ip, compromised_account

3. CORR-003: Ransomware Execution Sequence (P0)
   Stage 1: DEFENSE_EVASION (VSS delete, recovery disable)
   Stage 2: FILE_INTEGRITY (Mass rename / crypt)
   Window: 30 minutes | Keys: target_host

4. CORR-004: Reconnaissance Probe & High Burst Anomaly (P2/P3)
   Stage 1: DISCOVERY / NETWORK_TRAFFIC burst
   Window: 15 minutes | Keys: attacker_source_ip, target_host

5. CORR-005: Defense Evasion & Service Tampering (P1)
   Stage 1: DEFENSE_EVASION (Wazuh stop, audit clear)
   Stage 2: EXECUTION (Malicious script)
   Window: 45 minutes | Keys: target_host

6. CORR-006: Data Exfiltration Sequence (P2)
   Stage 1: DISCOVERY / CREDENTIAL_ACCESS
   Stage 2: EXFILTRATION (High outbound egress)
   Window: 180 minutes | Keys: attacker_source_ip

7. CORR-007: Privilege Escalation Chain (P1)
   Stage 1: AUTH_ANOMALY (Low-privilege session)
   Stage 2: PRIVILEGE_ESCALATION (Root/SYSTEM transition)
   Window: 60 minutes | Keys: target_host, compromised_account

8. CORR-008: Cloud / Container Breakout (P1)
   Stage 1: CLOUD_CONTAINER (Container exec, escape)
   Stage 2: PERSISTENCE (Host service creation)
   Window: 90 minutes | Keys: target_host
```

---

### 11.2 The process_aggregate() Pipeline Flow

Every **ACTIONABLE** aggregate emitted from Stage 2 passes through `process_aggregate()`:

```
ACTIONABLE Aggregate
         │
         ▼
Step 1: Multi-Stage Behavioral Rule Matching (_agg_tracks)
         │
         ▼
Step 2: Opportunistic Cross-Category Correlation
         │
         ▼
Step 3: Rule Precedence Deduplication Filter
         │ (Suppresses generic rules if specific multi-stage fired)
         ▼
Step 4: Standalone Aggregate Fallback (evaluate_standalone_aggregate)
         │
         ▼
Step 5: 24-Hour Cooldown & Ticket Deduplication Guard
         │
         ▼
Emitted Correlated Incidents
```

---

### 11.3 24-Hour Cooldown & Ticket Deduplication Guard

Prevents alert fatigue from repeated probes by tracking open and closed tickets across a 24-hour sliding horizon:

#### The Golden Rule: Absolute Immunity for P0 and P1
- **P0 (Critical)** and **P1 (High)** incidents have **absolute immunity**. They are **NEVER** suppressed by cooldowns, under any condition.

#### Cooldown Logic for P2 and P3
- **Check Cooldown**: If a closed P2 or P3 ticket exists for the same actor or target resolved within the last 24 hours (`q.cooldown_until > NOW()` or `resolved_at >= NOW() - 24h`), the new aggregate is suppressed with reason: `P2/P3 ticket closed within last 24h, identical aggregate suppressed`.
- **Append to Open**: If an active ticket is currently open in `soc_ops.soc_triage_queue` for the same entity pair, the incoming aggregate is appended to the existing ticket, updating its `last_seen_at` without generating a duplicate ticket.
- **Create New**: If no cooldown exists and no open ticket is present, a new `INC-P2-...` or `INC-P3-...` ticket is created.

---

### 11.4 Burst Escalation Matrix

Standalone bursts evaluated under `CORR-004` follow an escalation matrix:

| Condition | Assigned Severity | Action |
|-----------|-------------------|--------|
| `event_count >= 100` OR `burst_count >= 3` | **P2** | Escalated high-priority probe investigation |
| `event_count < 100` AND `burst_count < 3` | **P3** | Periodic external port reconnaissance |



## 12. Stage 4: Dynamic Risk Scoring — pipeline/score.py

Calculates an objective, multi-factor risk score (0–100) and maps incidents to actionable SOC triage priority tiers with contractual SLA deadlines.

### 12.1 Multi-Factor Scoring Architecture

Rather than relying solely on static Wazuh rule levels, `RiskScorer` synthesizes 8 distinct telemetry dimensions:

$$\text{Total Score} = \min\left(100, \sum_{i=1}^{8} F_i\right)$$

| Dimension | Evaluation Logic | Max Points |
|-----------|------------------|------------|
| **1. Base Severity** | Wazuh Rule Level (Level 0–16 mapped to base points) | 35 pts |
| **2. Asset Criticality** | `CROWN_JEWEL` (+25), `CRITICAL` (+15), `STANDARD` (+5), `DEV_TEST` (0) | 25 pts |
| **3. Threat Intelligence** | Active feed match with AbuseIPDB confidence ≥ 85% (+25), ≥ 70% (+15) | 25 pts |
| **4. Kill Chain Progression** | Late-stage ATT&CK tactics (`Exfiltration`, `Impact`, `Command and Control`) (+15), middle (+10), early (+5) | 15 pts |
| **5. Event Volume & Burst** | Sustained high frequency: `event_count >= 500` (+15), `100–499` (+10), `20–99` (+5) | 15 pts |
| **6. Historical Recurrence** | Cumulative lifetime bursts: `burst_count >= 5` (+10), `3–4` (+5) | 10 pts |
| **7. Multi-Stage Correlation** | Multi-step correlation rule fired (`CORR-001`, `CORR-002`, `CORR-003`) | 20 pts |
| **8. Temporal Anomaly** | Activity occurring outside standard business hours or on weekends | 5 pts |

---

### 12.2 SOC Priority Tier Mapping & Target SLAs

The computed composite score directly drives queue placement and triage priority:

| Score Range | Priority Tier | Severity Label | Contractual SLA | Description |
|-------------|---------------|----------------|-----------------|-------------|
| **81 – 100** | **P0** | `CRITICAL` | **< 15 minutes** | Active intrusions, ransomware, crown jewel compromise |
| **61 – 80** | **P1** | `HIGH` | **< 30 minutes** | Multi-stage attacks, credential dumps, unauthorized admin escalation |
| **41 – 60** | **P2** | `MEDIUM` | **< 4 hours** | High burst anomalies, repeated external probes, brute force |
| **21 – 40** | **P3** | `LOW` | **< 24 hours** | Routine port scans, isolated policy failures, non-critical web errors |
| **0 – 20** | **P4** | `INFORMATIONAL`| **< 7 days** | Low-noise informational telemetry, scheduled maintenance |

---

### 12.3 Factor Transparency & Explainability

For every scored incident, `RiskScorer` produces an auditable breakdown list of all applied factor items:

```json
[
  {"factor_name": "BASE_RULE_LEVEL", "points_applied": 30, "detail": "Rule Level 12"},
  {"factor_name": "ASSET_CRITICALITY", "points_applied": 25, "detail": "Host dc-prod-01 is CROWN_JEWEL"},
  {"factor_name": "THREAT_INTEL_MATCH", "points_applied": 25, "detail": "IP 185.177.x.x matched AbuseIPDB (95%)"},
  {"factor_name": "CORRELATION_MULTI_STAGE", "points_applied": 20, "detail": "Rule CORR-001 confirmed multi-stage chain"}
]
```

This explainability record is persisted directly in `risk_engine.calculated_risk_scores` and presented in the SOC Triage UI, giving analysts instant visibility into why a ticket was prioritized.



## 13. Data Layer — pipeline/database.py

The high-throughput persistence engine managing connection pooling, transactional batch inserts, upserts, and forensic evidence tracking across PostgreSQL 14+.

### 13.1 Connection Management

Engineered around `psycopg2.pool.ThreadedConnectionPool`:

```python
class DatabaseManager:
    def __init__(self, db_name: str = DB_NAME):
        self._pool: Optional[ThreadedConnectionPool] = None
        self.initialize_pool()

    @contextmanager
    def get_connection(self):
        """Context manager yielding managed connection with auto-return."""
        conn = self._pool.getconn()
        try:
            yield conn
        finally:
            self._pool.putconn(conn)
```

- **Pool Sizing**: Defaults to 4 minimum and 30 maximum concurrent connections.
- **Auto-Rollback**: Any exception raised inside `get_connection()` triggers an automatic rollback before returning the connection to the pool.
- **Graceful Reconnection**: Detects closed connections and auto-reinitializes pool on connection drops.

---

### 13.2 High-Throughput Bulk Operations

Utilizes PostgreSQL `execute_batch` and `execute_values` to achieve **7,000–11,000 events/second** ingestion throughput:

#### 1. bulk_insert_raw_events() & bulk_insert_normalized_events()
Batches raw and normalized alerts into `telemetry.raw_events` and `telemetry.normalized_events` in chunks of 5,000 rows.

#### 2. bulk_upsert_aggregated_alerts()
Inserts closed aggregation windows into `suppression.aggregated_alerts`. On conflict on `aggregate_id`, updates `event_count`, `window_end`, and `max_inline_risk_score`.

#### 3. bulk_upsert_cumulative_alerts()
Updates long-term entity baselines in `suppression.cumulative_alerts`:
```sql
INSERT INTO suppression.cumulative_alerts (
    cumulative_id, tenant_id, actor, target, category,
    first_seen_at, last_seen_at, total_events, total_burst_windows,
    tlp_level, sighting_count, source_feed, stix_indicator_id, mitre_technique_id
) VALUES (...)
ON CONFLICT (tenant_id, actor, target, category) DO UPDATE SET
    last_seen_at = GREATEST(cumulative_alerts.last_seen_at, EXCLUDED.last_seen_at),
    total_events = cumulative_alerts.total_events + EXCLUDED.total_events,
    total_burst_windows = cumulative_alerts.total_burst_windows + EXCLUDED.total_burst_windows,
    sighting_count = cumulative_alerts.sighting_count + EXCLUDED.sighting_count,
    is_dormant = FALSE;
```

#### 4. bulk_insert_evidence_mapping()
Inserts forensic links into `suppression.aggregate_evidence_mapping`:
- Links every `raw_event_id` to its parent `aggregate_id`.
- Guarantees **100% data preservation** — analysts can drill down from any aggregated ticket to the exact raw log payloads.

#### 5. bulk_insert_incidents_and_triage()
Atomically coordinates a multi-table transaction across:
1. `correlation.correlated_incidents` (Master incident metadata)
2. `correlation.incident_attack_stages` (Step-by-step evidence stages)
3. `risk_engine.calculated_risk_scores` (Numerical score & factor breakdown)
4. `soc_ops.soc_triage_queue` (Analyst queue item with assigned SLA)

---

### 13.3 Periodic Maintenance & Analytics Refresh

- **`refresh_cumulative_dormancy(reference_time)`**: Marks entity pairs as `DORMANT` if inactive for > 7 days. Supports offline historical replay by accepting `reference_time = MAX(dataset_timestamp)`.
- **`refresh_hourly_overview_rollup()`**: Pre-computes hourly count aggregates in `metrics.hourly_overview_rollup` for sub-second SOC dashboard widget rendering.
- **`ensure_retention_indexes()`**: Verifies BRIN and B-Tree timestamp indexes exist on all high-volume tables to support fast chunked purging.



## 14. Supplementary Modules

### 14.1 pipeline/threat_intel_sync.py

Automated Threat Intelligence Harvester & Sync Module (Phase 5). Extracts public IPs from raw events, classifies them into threat intelligence profiles, and populates the enrichment schema.

```python
def sync_threat_intelligence(db_name: str = "wazuh_soc_db"):
    ...
```

#### Pipeline Steps
1. **Extraction**: Queries all distinct `source_ip` addresses from `telemetry.raw_events` with event counts and time ranges.
2. **Classification**:
   - **Internal / Private**: Assigned `Internal_Pivot` / `Internal_Honeynet_Scanner` (Confidence: 85% if events > 1,000; else 40%).
   - **Known Exploiter Subnets** (`185.177.*`, `45.92.*`, `194.26.*`): Assigned `Shadow_Scanners` / `Automated_Web_Exploiter` (Confidence: 95%).
   - **Cloud Providers** (`20.*`, `4.*`, `52.*` for Azure; `3.*`, `15.*`, `34.*`, `54.*` for AWS/GCP): Assigned `Cloud_Crawler` (Confidence: 70%).
   - **Verified Domestic**: Tagged clean (Confidence: 0%).
   - **Generic External**: Assigned `Internet_Scanner` (Confidence: 60% if events > 50; else 20%).
3. **IoC Upsert**: Upserts classified records into `enrichment.threat_intelligence_iocs`.
4. **Normalized Event Update**: Sets `threat_intel_match = TRUE` and syncs `threat_intel_confidence` on all child events in `telemetry.normalized_events`.

---

### 14.2 pipeline/sync_live_ti_to_scores.py

Dynamically updates risk scores and priority tiers for all in-flight incidents whenever new threat intelligence arrives:

- **Dynamic Recalculation**:
  - Confidence ≥ 85% on `CROWN_JEWEL`/`CRITICAL` assets or `CORR-001`/`CORR-002` rules: **Score = 85 (P0)**.
  - Confidence ≥ 70% or `CORR-001`/`CORR-002` rules: **Score = 65 (P1)**.
  - Confidence ≥ 50% or `INC-P2-*` tickets: **Score = 50 (P2)**.
- **Queue Synchronization**: Propagates updated priority levels into `soc_ops.soc_triage_queue`.

---

### 14.3 pipeline/update_edf_view.py

Maintains the dynamic SOC Triage Queue view implementing the **Earliest Deadline First (EDF)** scheduling algorithm:

```sql
CREATE OR REPLACE VIEW soc_ops.v_actionable_triage_queue AS ...
```

#### SLA Deadlines & Compliance Status
- **P0**: `first_seen_at + 15 minutes` (Darurat Tertinggi)
- **P1**: `first_seen_at + 30 minutes` (Mendesak)
- **P2**: `first_seen_at + 4 hours` (Review Shift)
- **P3**: `first_seen_at + 24 hours` (Review Harian)
- **P4**: `first_seen_at + 7 days` (Audit Mingguan)
- **SLA Breach Detection**: Automatically tags tickets as `SLA BREACH (LEWAT BATAS)` if current time exceeds deadline.
- **Ordering Hierarchy**:
  1. Earliest deadline timestamp first (`batas_deadline_sla ASC`)
  2. Highest priority tier (`P0 > P1 > P2 > P3 > P4`)
  3. Highest composite risk score (`total_score DESC`)

---

### 14.4 pipeline/retention_manager.py

Enterprise-grade sliding-window 30-day (720 hours) retention engine.

```python
class RollingRetentionManager:
    def __init__(self, config_path: Optional[str] = None): ...
    def calculate_cutoff(self, reference_time: Optional[datetime] = None) -> datetime: ...
    def execute_retention_sweep(self, db_manager, reference_time=None, dry_run=False) -> Dict: ...
```

#### Core Capabilities
1. **Precision Cutoff**: Calculates retention cutoff down to the exact second (`NOW - 30 days`).
2. **Permanent Entity Safeguard**: `suppression.cumulative_alerts` is permanently preserved and protected from deletion by explicit invariant checks.
3. **Chunked Purging**: Deletes in bounded batches of 5,000 rows (`WITH to_delete AS (SELECT ctid ... LIMIT 5000) DELETE ...`) to prevent database table lock escalation.
4. **Post-Purge Vacuum**: Executes `VACUUM (ANALYZE)` in autocommit mode after successful purges to eliminate dead tuples and reclaim disk storage.
5. **Audit Logging**: Logs every execution (rows purged, duration, error state) to `logs/retention_audit.log`.

---

### 14.5 pipeline/consolidate_standalone_bursts.py

Executes a 24-hour deduplication pass over standalone burst anomalies:
- Scans `correlation.correlated_incidents` for standalone burst tickets created within 24 hours for identical actor/target pairs.
- Merges secondary bursts into the initial master incident, appending attack stages and updating event counters while marking duplicate tickets closed.



## 15. Pipeline Orchestrator — run_master_pipeline.py

The master CLI and background daemon orchestrator coordinating all pipeline stages, lifecycle events, and post-processing jobs.

### 15.1 CLI Arguments & Operational Modes

```bash
# Standard execution on dataset
python run_master_pipeline.py

# Fresh run (truncates existing database tables and ignores snapshots)
python run_master_pipeline.py --fresh

# Custom data folder and target database
python run_master_pipeline.py --dir /var/log/wazuh/alerts --db wazuh_soc_db

# Background daemon mode (continuously watches folder for new files)
python run_master_pipeline.py --daemon
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `--dir` | Path | `config.settings.DATA_DIR` | Directory containing raw Wazuh `.json` alert files |
| `--db` | String | `"wazuh_soc_db"` | PostgreSQL database name |
| `--fresh` | Flag | `False` | Truncates all tables and purges old state snapshots |
| `--daemon` | Flag | `False` | Continuous watcher polling directory every 10 seconds |

---

### 15.2 The 7-Step Master Pipeline Lifecycle

```
[Start]
  │
  ├─ Step 1: Database verification & snapshot cleanup (if --fresh)
  │
  ├─ Step 2: Stream Ingest → Normalization → Deduplication → Correlation
  │          • Per-file batch buffering (5,000 rows)
  │          • Crash recovery snapshot restoration (if not fresh)
  │          • Sliding window aggregation (15m STANDARD / 30m SLOW)
  │          • Governance suppression check (S1–S5 + NeverSuppressGuard)
  │          • Behavioral attack track evaluation (CORR-001–CORR-008)
  │          • Multi-factor risk scoring (0–100 → P0–P4)
  │          • Final window flush & evidence mapping persistence
  │          • Dataset-aware dormancy refresh
  │
  ├─ Step 3: Atomic database persistence (incidents, stages, triage queue)
  │
  ├─ Step 4: Threat Intelligence harvesting & live score recalculation
  │
  ├─ Step 5: 24h Standalone burst consolidation & EDF queue view update
  │
  ├─ Step 6: High-performance rollup refresh (hourly_overview_rollup)
  │
  └─ Step 7: 30-Day rolling retention sweep + VACUUM ANALYZE
[Complete]
```

---

### 15.3 Continuous Daemon Mode

`run_daemon_watcher(watch_dir, interval_sec=10)`:
- Maintains an in-memory registry of already processed log archives.
- Periodically scans `watch_dir` for new `.json` files.
- Automatically executes `run_full_pipeline_once()` when new files arrive.
- Supports graceful shutdown via `SIGINT` (Ctrl+C) and `SIGTERM`.

---

## 16. Package Initialization — pipeline/__init__.py

Defines package-level public exports and semantic version (`2.1.0`):

```python
from pipeline.models import (
    CommonEventModel, AggregatedAlertDB, CumulativeAlertDB,
    AggregateEvidenceMappingDB, WazuhRawAlert
)
from pipeline.ingest import (
    AlertStreamReader, CanonicalAssetResolver,
    classify_event_archetype, extract_os_platform, route_event_track
)
from pipeline.deduplicate import (
    SlidingWindowAggregator, AggregatedWindow, calculate_canonical_dedup_key
)
from pipeline.governance import SuppressionGovernanceManager
from pipeline.score import RiskScorer
from pipeline.correlate import CorrelationEngine
from pipeline.database import DatabaseManager

__version__ = "2.1.0"
```



## 17. Database Schema Reference

The pipeline persists data to a PostgreSQL 14+ database structured across **6 logical schemas** comprising 19 tables and optimized views:

```
wazuh_soc_db/
├── telemetry/             (High-volume raw and normalized event stores)
│   ├── raw_events
│   └── normalized_events
├── suppression/           (Aggregation, deduplication & governance)
│   ├── aggregated_alerts
│   ├── cumulative_alerts  (PERMANENT entity baseline — never purged)
│   ├── aggregate_evidence_mapping (Forensic 1-to-many trace)
│   ├── suppression_rules
│   ├── suppression_groups
│   └── suppression_audit_log
├── correlation/           (Multi-stage attack tracking)
│   ├── correlated_incidents
│   └── incident_attack_stages
├── risk_engine/           (Composite risk calculations & factor audit)
│   └── calculated_risk_scores
├── soc_ops/               (Triage queue, SLA management & analysts)
│   ├── soc_triage_queue
│   └── v_actionable_triage_queue (Dynamic EDF SLA View)
├── enrichment/            (Threat intelligence & asset inventory)
│   ├── threat_intelligence_iocs
│   └── asset_inventory_context
└── metrics/               (High-performance dashboard rollup caches)
    └── hourly_overview_rollup
```

### Table Specifications

| Schema | Table Name | Purpose | Retention |
|--------|------------|---------|-----------|
| `telemetry` | `raw_events` | Immutable raw alert payloads with parsed network/agent headers | 30 Days (Rolling) |
| `telemetry` | `normalized_events` | Strongly typed CommonEventModel representations with plugin enrichments | 30 Days (Rolling) |
| `suppression` | `aggregated_alerts` | 15m/30m collapsed alert windows with peak scores and suppression states | 30 Days (Rolling) |
| `suppression` | `cumulative_alerts` | Long-term actor/target entity baselines, lifetime burst counters, MISP sightings | **Permanent (Never Purged)** |
| `suppression` | `aggregate_evidence_mapping` | 1-to-many relational join table preserving forensic lineage from aggregate to raw events | 30 Days (Rolling) |
| `suppression` | `suppression_rules` | Registered S1–S5 suppression rules enforced by database CHECK constraints | Config / Governed |
| `correlation` | `correlated_incidents` | Confirmed attack incidents with MITRE chain attribution | 30 Days (Rolling) |
| `correlation` | `incident_attack_stages` | Ordered timeline of tactical steps comprising a correlated attack | 30 Days (Rolling) |
| `risk_engine` | `calculated_risk_scores` | Composite 0–100 scores, priority assignments (P0–P4), and JSON factor breakdowns | 30 Days (Rolling) |
| `soc_ops` | `soc_triage_queue` | Operational triage tickets with assignment state and 24h cooldown tracking | Active / Governed |
| `enrichment` | `threat_intelligence_iocs` | External IoC cache (AbuseIPDB, OTX) with confidence scores and threat actors | Managed / Synced |
| `metrics` | `hourly_overview_rollup` | Pre-calculated hourly event, aggregate, and incident volume rollups | Recomputed |



## 18. Suppression Taxonomy (S1–S5)

All suppression rules in the pipeline follow a strict, auditable **5-tier policy taxonomy** enforced across Python code, configuration registries, seed data, and PostgreSQL database constraints:

```sql
ALTER TABLE suppression.suppression_rules
ADD CONSTRAINT chk_suppression_class
CHECK (suppression_class IN (
    'S1_KNOWN_GOOD',
    'S2_FALSE_POSITIVE',
    'S3_MAINTENANCE',
    'S4_EXCEPTION',
    'S5_CONDITIONAL'
));
```

### Detailed Class Breakdown

#### S1: Known Good (`S1_KNOWN_GOOD`)
- **Definition**: Authorized system behavior, administrative automation, vulnerability scanner service accounts, internal health probes, and CDB allowlisted IP ranges.
- **Review Period**: Annual (365 days) or permanent.
- **Example**: Nessus vulnerability scanner scanning internal subnets from IP `10.0.100.50`.

#### S2: Confirmed False Positive (`S2_FALSE_POSITIVE`)
- **Definition**: Alerts verified by SOC Level 2/3 analysis to be benign anomalies caused by aggressive application logic, non-malicious compiler behavior, or over-sensitive signatures.
- **Review Period**: 90 Days. Requires periodic re-evaluation to detect underlying environmental changes.
- **Example**: Developer workstation running internal build scripts triggering rule `5501` (login session opened for root by daemon).

#### S3: Planned Maintenance (`S3_MAINTENANCE`)
- **Definition**: Scheduled change windows, OS upgrades, database migrations, or infrastructure disaster recovery exercises.
- **Review Period**: Duration of change window (typically < 24 hours).
- **Example**: Patch Tuesday automated kernel upgrade triggering mass reboot alerts and service stop events.

#### S4: Documented Exception (`S4_EXCEPTION`)
- **Definition**: Formally accepted business risks where security controls must be relaxed for legacy software, proprietary hardware, or specific business partner integrations.
- **Review Period**: Maximum 180 Days. Must include documented business justification and named risk owner.
- **Example**: Industrial control system requiring legacy SMBv1 communication.

#### S5: Conditional Contextual (`S5_CONDITIONAL`)
- **Definition**: Complex multi-condition suppression where events are only suppressed under specific environmental criteria (e.g., specific hours, originating subnets, or target environments).
- **Review Period**: 180 Days.
- **Example**: Remote administrative RDP sessions suppressed only if originating from the corporate VPN subnet during business hours.

---

## 19. MISP & Threat Intelligence Integration

The pipeline is natively designed for bidirectional integration with the **Malware Information Sharing Platform (MISP)** and external threat intelligence aggregators.

### 19.1 Native MISP Telemetry Fields

Both `suppression.cumulative_alerts` and `suppression.aggregated_alerts` include first-class schema columns for STIX 2.1 and MISP synchronization:

| Column | Type | Default | Description |
|--------|------|---------|-------------|
| `tlp_level` | `VARCHAR(12)` | `'TLP:AMBER'` | Traffic Light Protocol sharing scope (`TLP:WHITE`, `TLP:GREEN`, `TLP:AMBER`, `TLP:RED`) |
| `sighting_count` | `INT` | `0` | Automatically increments each time the entity is observed in an aggregation window |
| `source_feed` | `VARCHAR(64)` | `'wazuh-pipeline'` | Origin attribution for upstream MISP event tagging |
| `stix_indicator_id` | `VARCHAR(128)` | `NULL` | Globally unique STIX 2.1 UUID for cross-platform threat linking |
| `mitre_technique_id` | `VARCHAR(32)` | `NULL` | ATT&CK technique ID (e.g., `T1190`, `T1059`) for heat-map matrix export |

### 19.2 Export-Optimized PostgreSQL Indexes

```sql
CREATE INDEX idx_cumulative_misp_export
ON suppression.cumulative_alerts (source_feed, tlp_level, last_seen_at DESC)
WHERE sighting_count > 0;

CREATE INDEX idx_cumulative_mitre_technique
ON suppression.cumulative_alerts (mitre_technique_id)
WHERE mitre_technique_id IS NOT NULL;
```

These partial indexes enable near-instantaneous extraction of observable indicators for automated synchronization back to MISP threat sharing instances.



## 20. Operational Runbook

A guide for SOC analysts, incident responders, and detection engineers operating and maintaining the pipeline.

### 20.1 Daily Analyst Operations

#### Monitoring the Live Triage Queue
Analysts should query the Earliest Deadline First (EDF) view in PostgreSQL or the SOC Dashboard:

```sql
SELECT
    triage_id,
    priority,
    skor_risiko,
    judul_insiden,
    target_host,
    attacker_source_ip,
    batas_deadline_sla,
    status_kepatuhan_sla
FROM soc_ops.v_actionable_triage_queue
WHERE triage_status IN ('NEW', 'ASSIGNED', 'INVESTIGATING')
ORDER BY batas_deadline_sla ASC;
```

#### SLA Escalation Guidelines
- **`SLA BREACH (LEWAT BATAS)`**: Any ticket marked with this status must be escalated immediately to the SOC Shift Lead.
- **P0 Incidents (< 15m)**: Triggers immediate host isolation or IP block via active response.
- **P1 Incidents (< 30m)**: Requires immediate memory dump, credential reset, and lateral movement inspection.

---

### 20.2 Detection Engineer: Adding a New Normalization Plugin

SOC engineers can extend event enrichment without modifying `pipeline/ingest.py`:

```python
# 1. In pipeline/normalization_plugins.py, define the plugin class:
class CustomThreatGeoPlugin(NormalizationPlugin):
    @property
    def name(self) -> str:
        return "CustomThreatGeo"

    def enrich(self, cem: Any, raw: Any) -> Any:
        # Fast in-memory lookup (must complete in < 500 microseconds)
        if cem.source_ip and cem.source_ip.startswith("198.51."):
            cem.inline_risk_score = min(100, cem.inline_risk_score + 15)
        return cem

# 2. Append to ACTIVE_PLUGINS at the bottom of the file:
ACTIVE_PLUGINS.append(CustomThreatGeoPlugin())
```

---

### 20.3 Detection Engineer: Registering a New Suppression Rule

```sql
INSERT INTO suppression.suppression_rules (
    suppression_id,
    group_id,
    tenant_id,
    rule_name,
    suppression_class,
    target_rule_ids,
    match_conditions,
    sla_expiry_timestamp,
    status
) VALUES (
    'SUPP-2026-0042',
    'GRP-CORE-INFRA',
    'DEFAULT',
    'Suppress Internal Vulnerability Scanner on DMZ',
    'S1_KNOWN_GOOD',
    ARRAY['5710', '5712'],
    '{"source_ip": "10.0.50.25", "target_host": "dmz-web-*"}'::jsonb,
    CURRENT_TIMESTAMP + INTERVAL '365 days',
    'ACTIVE'
);
```

---

### 20.4 System Administrator: Maintenance Tasks

#### Executing a Retention Dry Run
Verify how many rows would be purged without actually issuing `DELETE` statements:

```python
from pipeline.database import DatabaseManager
db = DatabaseManager()
results = db.execute_rolling_retention(dry_run=True)
print(results)
```

#### Auditing Expired Suppression Rules
Automatically flag rules whose SLA review window has lapsed:

```python
from pipeline.governance import SuppressionGovernanceManager
from pipeline.database import DatabaseManager

db = DatabaseManager()
gov = SuppressionGovernanceManager(db_manager=db)
with db.get_connection() as conn:
    expired = gov.audit_sla_expirations(conn)
    print(f"Expired {len(expired)} outdated suppression rules.")
```

#### Resetting and Re-Ingesting Dataset (Fresh Benchmark Run)
To completely reset database state, drop old snapshots, and re-run benchmark telemetry:

```bash
python run_master_pipeline.py --fresh
```

---

### 20.5 Troubleshooting FAQ

| Symptom | Root Cause | Remediation |
|---------|------------|-------------|
| `OperationalError: connection pool exhausted` | High concurrency exceeding `DB_POOL_MAX_CONN` | Increase `DB_POOL_MAX_CONN` in `config/settings.py` or `.env` (default is 30). |
| Aggregated alerts not correlating into tickets | Alerts are suppressed by governance or rule conditions not met | Check `suppression.aggregated_alerts.is_suppressed`. If true, inspect `suppression_rule_id`. If false, verify events match stages in `config/correlation_rules.json`. |
| Pipeline killed due to Out-Of-Memory (OOM) | Input chunk size too large for available RAM | Decrease `CHUNK_SIZE` in `config/settings.py` (e.g., from 10,000 to 2,500). |
| Crash recovery snapshot fails to load | Incomplete JSON write from hard machine crash | Remove corrupted `persistence/dedup_state_snapshot.json` file. The pipeline will automatically rebuild state from raw event logs. |
| Cooldown suppressing genuine follow-up attacks | Secondary probe arrived within 24h of closed P2/P3 ticket | Verify alert severity. If the attack represents genuine escalation, upgrade rule level or target severity to P1/P0, which bypasses cooldowns unconditionally. |

---

*End of Comprehensive Documentation.*

