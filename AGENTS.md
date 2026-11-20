# SOC Architecture & Workflow Standards (Single Source of Truth)

Dokumen ini adalah acuan arsitektur baku untuk sistem WAZUH ASOC Enterprise SecOps. Dokumen ini wajib dibaca dan dipatuhi oleh seluruh agent AI, developer, dan analis SOC dalam memahami aliran data, siklus hidup tiket, dan metrik dashboard.

---

## 1. Siklus Hidup & Aturan AI Triage Tiket (P0 – P4)

Semua tiket (**P0, P1, P2, P3, dan P4**) memiliki perlakuan yang sama dalam AI Triage:

### A. Matriks SLA Prioritas Tiket
Prioritas tiket ditentukan secara deterministik oleh engine klasifikasi kategori/subkategori:
* **P0 (Critical):** SLA **15 Menit** (*Breach* / *Privilege Escalation*).
* **P1 (High):** SLA **60 Menit** (*Perimeter Breach* / *Command & Control*).
* **P2 (Medium):** SLA **4 Jam** (*Active Exploitation* / *Web Attack* / *Malware*).
* **P3 (Low):** SLA **24 Jam** (*Vulnerability* / *CVE Detected* / *FIM* / *Policy Violation*).
* **P4 (Informational):** SLA **7 Hari** (*Reconnaissance* / *Scanning* / *Web Operational* / *Service Health*).

> **PENTING:** Prioritas P0–P4 **hanya menentukan durasi SLA** dan waktu buffer penutupan agregat. P4 **BUKAN** diabaikan atau dipisahkan dari pipeline.

---

### B. Alur AI Cascading Triage
Ketika SLA tiket habis dan jendela buffer agregat (`window_buffer_until`) telah selesai, seluruh tiket (P0–P4) diproses oleh **Cascading AI Triage Pipeline** (`pipeline/p4_sla_worker.py`):
1. **Enrichment:** Pengayaan indikator IOC via MISP & AbuseIPDB.
2. **Cascading AI Execution:**
   * **Tier 1:** Machine Learning Classifier (ML)
   * **Tier 2:** Local LLM
   * **Tier 3:** Cloud LLM (dengan soft-voting)

---

### C. Keputusan & Percabangan Status (Confidence Threshold 85%)

| Hasil AI Triage | Ambang Batas (*Confidence*) | Keputusan Sistem | Status Tiket | Penanganan Fitur Dashboard |
| :--- | :--- | :--- | :--- | :--- |
| **BENIGN** | $\ge 85\%$ | `AUTO_CLOSE` / `AUTO_SUPPRESS` | `triage_status = 'CLOSE'`, `resolution_outcome = 'BENIGN'` | Masuk ke fitur **Policy Bundle** (khususnya submenu **By Ticket**) sebagai kandidat aturan supresi. |
| **THREAT** | $\ge 85\%$ | `CREATE_IRIS_CASE` | `triage_status = 'CLOSE'`, `resolution_outcome = 'TRUE_POSITIVE_ACTIONABLE'`, `assigned_analyst = 'iris_orchestrator'` | Masuk ke fitur **Verified Threat**, dieskalasi ke platform IRIS, dan memicu korelasi **Threat Campaign Clusterer**. |
| **INCONCLUSIVE** | $< 85\%$ | `AUDIT_SOC_ANALYST` | `triage_status = 'GROUNDTRUTH'`, `ground_truth_status = 'ACT NEED'`, `assigned_analyst = 'tier1_soc_analyst'` | Masuk ke antrean fitur **Ground Truth** untuk ditinjau manual oleh Human SOC Analyst dan divalidasi oleh SOC Manager. |

---

## 2. Definisi Metrik Funnel Dashboard (MAIN / ANALYTICS)

Kartu metrik pada layar overview dashboard merefleksikan hierarki filtrasi ancaman berikut:

1. **INGEST (`telemetry.raw_events`):**
   Total seluruh log event mentah yang masuk dari agen Wazuh.
2. **CLUSTER (`suppression.aggregated_alerts`):**
   Total alert yang telah diagregasi dan dikelompokkan ke dalam time window oleh engine supresi/agregasi.
3. **TICKET (`soc_ops.soc_triage_queue`):**
   Total tiket triage yang dihasilkan (mencakup seluruh prioritas P0, P1, P2, P3, dan P4). Hubungan Cluster ke Ticket adalah Many-to-Many ($M:N$).
4. **INCIDENT (`correlation.correlated_incidents` / Verified Threats):**
   Total insiden ancaman terkonfirmasi yang memerlukan respons keamanan aktif (`resolution_outcome = 'TRUE_POSITIVE_ACTIONABLE'` atau tereskalasi ke IRIS).
5. **GROUNDTRUTH:**
   Total kasus di mana AI Tier 3 menghasilkan confidence $< 85\%$ yang membutuhkan intervensi dan audit analis manusia (`ground_truth_status = 'ACT NEED'`).
6. **CAMPAIGN (`correlation.threat_campaign_clusters`):**
   Total kampanye ancaman terkoordinasi multi-tahap yang mengelompokkan insiden-insiden terkonfirmasi.
