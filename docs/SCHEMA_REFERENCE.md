# KAMUS DATA & REFERENSI SKEMA DATABASE (19 TABEL)
## *Production-Grade PostgreSQL 14+ Data Dictionary for Wazuh Alert Grouping Pipeline*

---

### 1. RINGKASAN DESAIN SKEMA RELASIONAL
Database `wazuh_soc_db` dirancang dengan arsitektur **7 Domain Skema Logika (19 Tabel Master)** dengan dukungan *Declarative Range Partitioning*, *GIN Trigram Indexes*, dan *Integrity Check Constraints*.

---

### 2. DOMAIN 1: TELEMETRI & NORMALISASI

#### 1. `telemetry.raw_events` *(Partitioned by timestamp)*
Menyimpan 100% data log mentah asli dari sensor/agent Wazuh untuk preservasi bukti hukum forensik (*Suppress Events, Not Evidence*).

| Nama Kolom | Tipe Data | Constraint | Deskripsi |
| :--- | :--- | :--- | :--- |
| `event_id` | VARCHAR(64) | PK (Composite) | Pengenal unik log dari Wazuh. |
| `timestamp` | TIMESTAMPTZ | PK (Composite) | Waktu presisi log dibuat pada endpoint. |
| `tenant_id` | VARCHAR(64) | NOT NULL | Pengenal multi-tenancy organisasi. |
| `agent_id` | VARCHAR(32) | NOT NULL | ID agent Wazuh pelapor. |
| `agent_name` | VARCHAR(255) | NOT NULL | Nama hostname agent Wazuh. |
| `agent_ip` | INET | NULL | IP agent Wazuh. |
| `source_ip` | INET | NULL | IP sumber koneksi/penyerang. |
| `destination_ip`| INET | NULL | IP tujuan serangan. |
| `source_port` | INTEGER | NULL | Port sumber. |
| `destination_port`| INTEGER | NULL | Port tujuan. |
| `protocol` | VARCHAR(16) | NULL | Protokol jaringan (TCP/UDP/ICMP). |
| `username` | VARCHAR(255) | NULL | Nama pengguna akun terkait. |
| `location` | VARCHAR(255) | NULL | File path atau sumber log channel. |
| `decoder_name` | VARCHAR(64) | NULL | Nama decoder Wazuh yang mencocokkan. |
| `raw_payload` | TEXT | NOT NULL | Payload log mentah asli utuh (JSON/Syslog). |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Waktu log di-ingest ke database. |

#### 2. `telemetry.normalized_events` *(Partitioned by processed_at)*
Representasi log yang telah distandardisasi ke dalam format Common Event Model (CEM) dengan tag taktik MITRE ATT&CK.

| Nama Kolom | Tipe Data | Constraint | Deskripsi |
| :--- | :--- | :--- | :--- |
| `normalized_event_id` | VARCHAR(64) | PK (Composite) | ID unik event ternormalisasi. |
| `processed_at` | TIMESTAMPTZ | PK (Composite) | Timestamp saat normalisasi diproses. |
| `raw_event_id` | VARCHAR(64) | NOT NULL | Foreign key ke `raw_events(event_id)`. |
| `event_timestamp` | TIMESTAMPTZ | NOT NULL | Timestamp asli event. |
| `rule_id` | INTEGER | NOT NULL | Rule ID Wazuh yang terpicu. |
| `rule_level` | INTEGER | CHECK (0..16) | Tingkat keparahan Wazuh (0-16). |
| `rule_description` | TEXT | NOT NULL | Deskripsi aturan deteksi. |
| `classification_groups` | TEXT[] | NOT NULL | Array grup taksonomi (web, auth, malware). |
| `mitre_attack_ids` | VARCHAR(16)[] | NULL | Array MITRE ID (T1110, T1078, dll.). |
| `mitre_tactics` | VARCHAR(64)[] | NULL | Array taktik (Initial Access, Execution). |
| `mitre_techniques` | VARCHAR(128)[]| NULL | Array nama teknik. |
| `compliance_frameworks`| JSONB | DEFAULT '{}' | Pemetaan kepatuhan (PCI-DSS, NIST 800-53). |
| `asset_criticality_tier`| VARCHAR(32) | DEFAULT 'STANDARD'| Tingkat kekritisan aset target. |
| `is_asset_internet_exposed`| BOOLEAN | DEFAULT FALSE | Apakah aset terbuka ke internet publik. |
| `is_privileged_user` | BOOLEAN | DEFAULT FALSE | Apakah user berhak akses administrator/root. |
| `is_service_account` | BOOLEAN | DEFAULT FALSE | Apakah user merupakan akun mesin/layanan. |
| `threat_intel_match` | BOOLEAN | DEFAULT FALSE | Apakah IP cocok dengan reputasi IoC berbahaya. |
| `threat_intel_confidence`| INTEGER | DEFAULT 0 | Skor keyakinan intelijen ancaman (0-100). |

---

### 3. DOMAIN 2: ENRICHMENT & THREAT INTELLIGENCE

#### 3. `enrichment.asset_inventory_context`
Katalog master aset dan tingkat kekritisan infrastruktur (*Crown Jewels*).
* **Kolom:** `asset_id` (PK), `hostname` (UNIQUE), `ip_address`, `mac_address`, `asset_type`, `criticality_tier` (CROWN_JEWEL, CRITICAL, HIGH, STANDARD, LAB), `criticality_score` (0-25), `environment`, `is_internet_exposed`, `owner_department`, `created_at`, `updated_at`.

#### 4. `enrichment.identity_context`
Katalog profil pengguna dan tingkat privilese akun.
* **Kolom:** `identity_id` (PK), `username` (UNIQUE), `full_name`, `email`, `department`, `account_type` (STANDARD_USER, PRIVILEGED_ADMIN, SERVICE_ACCOUNT, SYSTEM), `is_privileged`, `expected_hosts`, `risk_baseline_score`, `created_at`, `updated_at`.

#### 5. `enrichment.threat_intelligence_iocs`
Database reputasi indikator ancaman (IoCs).
* **Kolom:** `ioc_id` (PK), `indicator_value` (Composite Unique), `indicator_type` (IPV4, IPV6, DOMAIN, URL, MD5, SHA256), `threat_actor`, `malware_family`, `confidence_score` (0-100), `source_feed`, `description`, `is_active`, `first_seen_at`, `expires_at`.

---

### 4. DOMAIN 3: SUPRESI & AGREGASI

#### 6. `suppression.maintenance_windows`
Jadwal pemeliharaan resmi untuk pengurangan skor risiko otomatis (S4).
* **Kolom:** `window_id` (PK), `title`, `target_hostname`, `target_ip`, `ticket_id`, `approved_by`, `window_start`, `window_end`, `status`.

#### 7. `suppression.suppression_rules`
Tabel tata kelola aturan supresi S1–S5 berbatas waktu dengan Separation of Duties.
* **Kolom:** `suppression_id` (PK), `rule_name`, `suppression_class` (S1_KNOWN_GOOD, S2_DEDUPLICATION, S3_AGGREGATION, S4_MAINTENANCE, S5_CONDITIONAL), `target_rule_ids`, `author`, `approver`, `ticket_id`, `business_reason`, `scope_definition` (JSONB), `status` (ACTIVE, EXPIRED, DISABLED), `created_date`, `expires_date`, `review_cycle`.
* **Constraint:** `chk_separation_of_duties CHECK (author <> approver)`.

#### 8. `suppression.suppression_audit_log`
Catatan jejak audit modifikasi aturan supresi untuk kepatuhan GRC.
* **Kolom:** `audit_id` (PK), `suppression_id`, `action_type` (CREATE, UPDATE, EXPIRE, DELETE, SUSPEND), `performed_by`, `performed_at`, `change_details` (JSONB).

#### 9. `suppression.aggregated_alerts`
Objek peringatan terkompresi hasil mesin deduplikasi sliding window 15 menit (Reduksi 97,75%).
* **Kolom:** `aggregation_id` (PK), `rule_id`, `deduplication_key` (MD5 Hash), `tenant_id`, `agent_id`, `source_ip`, `destination_ip`, `username`, `event_count`, `window_start`, `window_end`, `status` (OPEN, ESCALATED, CLOSED), `created_at`, `updated_at`.

#### 10. `suppression.aggregate_evidence_mapping`
Tabel relasi M:N yang menghubungkan objek terkompresi ke setiap baris log mentah asli (*Preservasi Forensik 100%*).
* **Kolom:** `aggregation_id` (FK), `raw_event_id` (FK), `event_timestamp`, `mapped_at`. Primary Key Composite: `(aggregation_id, raw_event_id)`.

---

### 5. DOMAIN 4: KORELASI SERANGAN & KILL CHAIN

#### 11. `correlation.correlation_rules`
Definisi skenario rantai serangan multi-tahap.
* **Kolom:** `correlation_rule_id` (PK), `rule_code`, `rule_name`, `description`, `timeframe_seconds`, `target_severity` (P0, P1, P2, P3), `mitre_attack_pattern` (JSONB), `is_active`.

#### 12. `correlation.correlated_incidents`
Objek insiden gabungan yang berhasil direkonstruksi dari rangkaian event.
* **Kolom:** `incident_id` (PK: `INC-XXXX`), `correlation_rule_id` (FK), `tenant_id`, `title`, `narrative`, `initial_access_vector`, `attacker_source_ip`, `compromised_account`, `target_host`, `incident_status` (DETECTED, TRIAGED, CONTAINED, RESOLVED, CLOSED), `first_seen_at`, `last_seen_at`.

#### 13. `correlation.incident_stages`
Urutan sekuensial kronologis tahapan serangan dalam sebuah insiden.
* **Kolom:** `stage_id` (PK), `incident_id` (FK), `sequence_order` (1, 2, 3...), `stage_name`, `reference_id`, `evidence_type` (RAW_EVENT, AGGREGATED_ALERT), `stage_description`, `detected_at`.

---

### 6. DOMAIN 5: ENGINE SKOR RISIKO DINAMIS

#### 14. `risk_engine.risk_scoring_factors`
Rincian transparansi bobot skor per faktor yang berkontribusi pada insiden.
* **Kolom:** `factor_id` (PK), `incident_id` (FK), `factor_type` (DETECTION_SEVERITY, ASSET_CRITICALITY, IDENTITY_PRIVILEGE, ATTACK_CHAIN_LENGTH, KNOWN_GOOD_DEDUCTION), `weight_added` (Integer positif/negatif), `justification`, `calculated_at`.

#### 15. `risk_engine.calculated_risk_scores`
Skor risiko total (0–100) dan penentuan prioritas operasional (P0–P4).
* **Kolom:** `scoring_id` (PK), `incident_id` (FK Unique), `total_score` (0-100), `soc_priority` (P0, P1, P2, P3, P4), `scoring_version`, `calculated_at`.
* **Constraint:** `chk_score_priority_alignment` (Memastikan integritas matematis skor vs prioritas P0-P4).

---

### 7. DOMAIN 6: WORKFLOW & RESPON ANALIS SOC

#### 16. `soc_ops.soc_triage_queue`
Antrean tiket aktif yang tampil pada dashboard Analis SOC.
* **Kolom Fisik:** `triage_id` (PK: `TRG-XXXX`), `incident_id` (FK Unique ke `correlated_incidents`), `assigned_analyst`, `priority` (`P0`, `P1`, `P2`, `P3`, `P4`), `triage_status` (`NEW`, `ASSIGNED`, `INVESTIGATING`, `PENDING_ACTION`, `RESOLVED`, `CLOSED`), `resolution_outcome` (`TRUE_POSITIVE_ACTIONABLE`, `TRUE_POSITIVE_NO_ACTION`, `FALSE_POSITIVE_TUNING_REQ`, `OPERATIONAL_NOISE`, `BENIGN_AUTHORIZED`), `false_positive_reason`, `mean_time_to_triage_seconds`, `created_at`, `updated_at`, `resolved_at`.
* **Kalkulasi SLA Deadline Dinamis:** Target batas waktu SLA tidak disimpan statis di kolom tabel fisik, melainkan dihitung run-time secara dinamis melalui SQL View `soc_ops.v_actionable_triage_queue` dengan algoritma *Earliest Deadline First* (EDF):
  * **P0 (Critical):** `created_at + INTERVAL '15 minutes'` (< 15 Menit)
  * **P1 (High):** `created_at + INTERVAL '30 minutes'` (< 30 Menit)
  * **P2 (Medium):** `created_at + INTERVAL '4 hours'` (< 4 Jam / Review Shift)
  * **P3 (Low):** `created_at + INTERVAL '24 hours'` (< 24 Jam / Review Harian)
  * **P4 (Informational):** `created_at + INTERVAL '7 days'` (< 7 Hari / Review Mingguan & Analisis Log telemetri, bukan auto-suppress).

#### 17. `soc_ops.incident_investigation_notes`
Buku catatan investigasi kolaboratif analis SOC.
* **Kolom:** `note_id` (PK), `incident_id` (FK), `author_analyst`, `note_text`, `is_hypothesis`, `created_at`.

#### 18. `soc_ops.incident_response_actions`
Log tindakan mitigasi dan containment (SOAR).
* **Kolom:** `action_id` (PK), `incident_id` (FK), `action_type` (ISOLATE_HOST, BLOCK_IP_FIREWALL, RESET_USER_PASSWORD, KILL_PROCESS), `executed_by`, `execution_status` (SUCCESS, FAILED, PENDING), `target_entity`, `details` (JSONB), `executed_at`.

---

### 8. DOMAIN 7: METRIK KPI OPERASIONAL GRC

#### 19. `metrics.operational_metrics_daily`
Rekapitulasi harian kinerja pipeline, rasio reduksi kebisingan, dan kepatuhan SLA.
* **Kolom:** `metric_id` (PK), `metric_date` (UNIQUE Date), `raw_events_count`, `wazuh_alerts_count`, `suppressed_events_count`, `aggregated_alerts_count`, `correlated_incidents_count`, `analyst_reviewed_count`, `true_positives_count`, `actionable_incidents_count`, `suppression_escapes_count`, `avg_mean_time_to_triage_sec`, `noise_reduction_percentage` (Generated Column).
