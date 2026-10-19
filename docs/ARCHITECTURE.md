# DOKUMEN SPESIFIKASI ARSITEKTUR SISTEM
## *Wazuh Enterprise Alert Grouping, Multi-Stage Correlation & Incident Triage Pipeline*

---

### 1. IKHTISAR ARSITEKTUR & TUJUAN DESAIN
Sistem ini dirancang untuk mengatasi permasalahan *Alert Fatigue* pada ekosistem SIEM Wazuh dengan memproses **840.000+ alert per bulan**, mengurangi kebisingan repetitif hingga **97,75%**, merekonstruksi rantai serangan multi-tahap (*Multi-Stage Cyber Kill Chain*), dan menyajikan antrean triage terprioritas dinamis (P0–P4) kepada analis SOC.

#### 4 Pilar Desain Utama:
1. **Preservasi Forensik Penuh (*Suppress Events, Not Evidence*):** 100% log mentah tetap tersimpan di database fisik partisi PostgreSQL.
2. **Deterministic Deduplication:** Pengelompokan burst kebisingan menggunakan composite MD5 hash dalam sliding window 15 menit.
3. **Stateful Behavioral Correlation:** Deteksi sekuensial taktik MITRE ATT&CK lintas event dan host.
4. **Dynamic Context-Aware Scoring:** Skor risiko dihitung berdasarkan keparahan deteksi, kekritisan aset (*Crown Jewels*), privilese akun, dan kontrol mitigasi.

---

### 2. ARSITEKTUR PIPELINE 4-TAHAP (END-TO-END)

```text
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                               4-STAGE DETECTION & TRIAGE PIPELINE                               │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘

 📡 TELEMETRY INGESTION [Stage 1]
    ├── Ingestion Engine (pipeline/ingest.py): Streaming chunks 10.000 events/batch
    ├── Raw Storage: telemetry.raw_events (Monthly partitioned: raw_events_YYYY_MM)
    └── Common Event Model (CEM) Normalization: telemetry.normalized_events (MITRE ATT&CK tagged)
            │
            ▼
 ⚡ NOISE SUPPRESSION & DEDUPLICATION [Stage 2]
    ├── 5-Class Suppression Taxonomy (S1 Known-Good, S2 Dedup, S3 Agg, S4 Maint, S5 Cond)
    ├── Sliding Window Aggregator (pipeline/deduplicate.py): 900s (15 min) duration
    ├── Hash Generator: MD5(rule_id | source_ip | destination_ip | username | agent_id)
    └── Storage: suppression.aggregated_alerts (97.75% Noise Reduction)
            │
            ▼
 🔗 CONTEXT ENRICHMENT & BEHAVIORAL CORRELATION [Stage 3]
    ├── Context Enrichment: Asset Criticality (Crown Jewel/Critical), Privileged User, IoCs
    ├── Correlation Engine (pipeline/correlate.py): Stateful multi-event kill chain tracker
    │     ├── CORR-001: Failed Logins (>=5) -> Successful Login (Same Source IP)
    │     ├── CORR-002: Login -> Sudo Execution -> Persistence
    │     ├── CORR-003: Encoded PowerShell -> Ingress Tool Transfer / LOLBAS
    │     ├── CORR-004: Lateral Movement Sweep (Admin Shares / WMI cross-host)
    │     └── CORR-005: Malware / Webshell Execution -> Active Outbound C2
    └── Storage: correlation.correlated_incidents & correlation.incident_stages
            │
            ▼
 🧮 DYNAMIC RISK SCORING & SOC WORKFLOW [Stage 4]
    ├── Risk Scoring Engine (pipeline/score.py): Composite Formula (0 - 100)
    │     Risk Score = Detection Severity (10-25) + Behavioral Confidence (15-20)
    │                + Asset Criticality (0-25) + Identity Privilege (0-10)
    │                + Chain Stages (5/stg) - Known Good Deductions (25-30)
    ├── Priority Alignment Check Invariant:
    │     • 81 - 100 -> P0 (CRITICAL) [SLA < 15 min]
    │     • 61 - 80  -> P1 (HIGH)     [SLA < 30 min]
    │     • 41 - 60  -> P2 (MEDIUM)   [SLA < 4 hours / Review Shift]
    │     • 21 - 40  -> P3 (LOW)      [SLA < 24 hours / Review Harian]
    │     • 0  - 20  -> P4 (INFORMATIONAL) [SLA < 7 days / Review Mingguan & Analisis Log]
    └── Storage: risk_engine.calculated_risk_scores & soc_ops.soc_triage_queue
```

---

### 3. MODULARISASI WAZUH XML RULESET (14 MODUL XML)
Aturan deteksi di layer Wazuh (`ruleset/rules/`) disusun secara hierarkis dengan alokasi Rule ID `100000` s.d. `110999`:

| Rule ID Range | File XML Modul | Fungsi & Taktik MITRE ATT&CK |
| :--- | :--- | :--- |
| `100000 - 100099` | `001-base-normalization.xml` | Normalisasi dasar log heterogen ke Common Event Model. |
| `100100 - 100199` | `010-auth-bruteforce.xml` | Deteksi Brute Force & Password Spraying (T1110). |
| `100200 - 100299` | `020-web-bot-noise.xml` | Klasifikasi & peredaman bot scanner 400/404 web server. |
| `100300 - 100399` | `030-network-scans.xml` | Deteksi Port Scanning & Sweep Reconnaissance (T1046). |
| `100400 - 100499` | `040-privilege-escalation.xml`| Deteksi Sudo abuse & Windows Token Impersonation (T1068). |
| `100500 - 100599` | `050-persistence.xml` | Deteksi Cronjob, Systemd, Registry Auto-start (T1053, T1547). |
| `100600 - 100699` | `060-lateral-movement.xml` | Deteksi Admin Shares, PsExec, WMI/WinRM remote exec (T1021). |
| `100700 - 100799` | `070-correlation.xml` | Aturan korelasi rantai serangan hulu. |
| `100800 - 100899` | `080-suppression.xml` | Aturan supresi S1–S5 & pengecualian scanner resmi. |
| `100900 - 100999` | `090-risk-scoring.xml` | Modul tagging faktor risiko dan klasifikasi aset. |
| `101000 - 101099` | `095-governance-log.xml` | Audit log perubahan aturan supresi & eskalasi. |

---

### 4. STRUKTUR 7 SKEMA POSTGRESQL (19 TABEL MASTER)
Database diorganisasikan ke dalam 7 skema modular:
1. **`telemetry`**: `raw_events` (Partitioned by timestamp), `normalized_events` (Partitioned by processed_at).
2. **`enrichment`**: `asset_inventory_context`, `identity_context`, `threat_intelligence_iocs`.
3. **`suppression`**: `maintenance_windows`, `suppression_rules`, `suppression_audit_log`, `aggregated_alerts`, `aggregate_evidence_mapping`.
4. **`correlation`**: `correlation_rules`, `correlated_incidents`, `incident_stages`.
5. **`risk_engine`**: `risk_scoring_factors`, `calculated_risk_scores`.
6. **`soc_ops`**: `soc_triage_queue`, `incident_investigation_notes`, `incident_response_actions`.
7. **`metrics`**: `operational_metrics_daily`.

---

### 5. SPESIFIKASI HIGH AVAILABILITY & PARTISI BULANAN
* **Declarative Range Partitioning:** Tabel `raw_events` dan `normalized_events` dipartisi secara bulanan (`YYYY_MM`) untuk memastikan kecepatan query dan kemudahan rotasi retensi (90 hari raw, 180 hari normalized).
* **Automated Maintenance Stored Procedures:**
  * `create_monthly_partitions(months_ahead)`: Menyiapkan partisi bulan berikutnya secara otomatis.
  * `purge_expired_partitions(retention_days)`: Men-detach dan menghapus partisi yang melewati masa retensi hukum.
