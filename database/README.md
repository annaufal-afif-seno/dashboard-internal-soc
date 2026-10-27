# PANDUAN ARSITEKTUR STRUKTURAL DATABASE WAZUH ASOC
## Skema Relasional, Partisi Data, dan Indeks Performa Tinggi

Dokumen ini adalah panduan resmi struktur basis data **Wazuh Autonomous SOC (ASOC)**. Seluruh skema telah disusun secara modular per domain fungsional, teruji secara terukur (*zero dual-write, sub-second query, GIN trigram text search, dan partition pruning*).

---

## 1. PETA STRUKTUR FOLDER `database/`

```
database/
├── README.md                      # Panduan arsitektur, peta relasi, & kamus data (Dokumen ini)
├── complete_schema.sql            # Dump DDL konsolidasi utuh (Single Source of Truth)
├── seed_data.sql                  # Data master awal (Aset, Identitas, IoC Threat Intel, Rules)
│
├── schemas/                       # STRUKTUR MODULAR PER SKEMA (Clean Architecture)
│   ├── 00_init_database.sql       # Inisialisasi ekstensi (pg_trgm, uuid-ossp, pgcrypto) & skema
│   │
│   ├── 01_telemetry/              # Domain 1: Log Penyerapan Telemetri (Raw & Normalized)
│   │   ├── 01_tables.sql          # Unified events, raw_events, normalized_events, checkpoints
│   │   └── 02_indexes.sql         # Indeks timestamp, raw_event_id partisi, & GIN JSONB
│   │
│   ├── 02_suppression/            # Domain 2: Deduplikasi & Reduksi Kebisingan (Sliding-Window)
│   │   ├── 01_tables.sql          # aggregated_alerts, cumulative_alerts, evidence_mapping, rules
│   │   ├── 02_views.sql           # v_actionable_aggregates
│   │   └── 03_indexes.sql         # 4 GIN Trigram index (actor, target, rule_desc, ioa_summary)
│   │
│   ├── 03_correlation/            # Domain 3: Korelasi Rantai Serangan Multi-Tahap
│   │   ├── 01_tables.sql          # correlated_incidents, incident_stages, correlation_rules
│   │   └── 02_indexes.sql         # Foreign key & first_seen_at time-range indexes
│   │
│   ├── 04_risk_engine/            # Domain 4: Kalkulasi Skor Risiko Dinamis (Multi-Factor)
│   │   └── 01_tables.sql          # calculated_risk_scores, risk_scoring_factors
│   │
│   ├── 05_soc_ops/                # Domain 5: Operasional Antrian Tiket Triage & Ground Truth
│   │   ├── 01_tables.sql          # soc_triage_queue, soc_users, ground_truth, notes, actions
│   │   ├── 02_views.sql           # v_actionable_triage_queue (EDF SLA), v_ai_confusion_matrix
│   │   └── 03_indexes.sql         # Partial composite queue index (priority, created_at)
│   │
│   ├── 06_enrichment/             # Domain 6: Konteks Aset, Identitas, & Threat Intelligence
│   │   └── 01_tables.sql          # asset_inventory_context, identity_context, threat_intel_iocs
│   │
│   └── 07_metrics/                # Domain 7: Rollup Tata Kelola & Metrik Operasional
│       └── 01_tables.sql          # hourly_overview_rollup, operational_metrics_daily
│
└── migrations/                    # RIWAYAT MIGRASI SEKUENSIAL (100% PRESERVED FOR COMPATIBILITY)
    ├── 001_initial_schema.sql
    ├── ...
    ├── 016_performance_indexes.sql        # Migrasi Optimasi: Indeks partisi & GIN Trigram
    └── 017_unified_lean_telemetry_table.sql # Migrasi Optimasi: Unified Lean Table
```

---

## 2. DIAGRAM RELASI ENTITAS ANTAR SKEMA (ERD)

Arsitektur database mengalir secara terarah dari penyerapan log mentah menuju penyajian tiket berprioritas:

```mermaid
erDiagram
    TELEMETRY_EVENTS ||--o{ SUPPRESSION_AGGREGATES : "deduplicated into"
    SUPPRESSION_AGGREGATES ||--o{ CORRELATION_STAGES : "forms attack step"
    CORRELATION_STAGES }o--|| CORRELATED_INCIDENTS : "belongs to"
    CORRELATED_INCIDENTS ||--|| RISK_SCORES : "evaluated by"
    CORRELATED_INCIDENTS ||--|| TRIAGE_QUEUE : "routed as ticket"
    TRIAGE_QUEUE }o--|| SOC_USERS : "assigned to analyst"
    SUPPRESSION_AGGREGATES ||--o{ THREAT_IOCS : "enriched by"
    CORRELATED_INCIDENTS ||--o{ GROUND_TRUTH : "benchmarked against"

    TELEMETRY_EVENTS {
        varchar event_id PK
        timestamptz event_timestamp PK
        int rule_id
        inet source_ip
        jsonb raw_payload
    }
    SUPPRESSION_AGGREGATES {
        varchar aggregation_id PK
        varchar deduplication_key
        int event_count
        timestamptz window_start
        timestamptz window_end
        varchar status
    }
    CORRELATED_INCIDENTS {
        varchar incident_id PK
        varchar title
        varchar severity
        timestamptz first_seen_at
        timestamptz last_seen_at
    }
    RISK_SCORES {
        bigserial score_id PK
        varchar entity_id
        int total_score
        varchar priority
    }
    TRIAGE_QUEUE {
        varchar triage_id PK
        varchar incident_id FK
        varchar priority
        varchar triage_status
        varchar assigned_analyst
    }
```

---

## 3. RINGKASAN REVISI & OPTIMASI TERBARU YANG DILINDUNGI

Seluruh struktur di atas **100% mempertahankan seluruh revisi performa** yang telah diuji secara live:

1. **Migration 016 (Indeks Performa & GIN Trigram)**:
   * Indeks partisi `raw_event_id` pada seluruh tabel `telemetry.normalized_events` (mempercepat query forensik dari 9,95s menjadi **60 ms**).
   * 4 GIN Trigram Index pada `suppression.aggregated_alerts` (`actor`, `target`, `rule_description`, `ioa_summary`) untuk pencarian teks `ILIKE` kilat.
   * Indeks parsial komposit pada `soc_ops.soc_triage_queue (priority, created_at DESC) WHERE status IN ('open', 'in_progress', 'pending_investigation')`.
2. **Migration 017 (Unified Lean Table `telemetry.events`)**:
   * Tabel tunggal terpartisi bulanan berbasis `RANGE (event_timestamp)` yang menyatukan metadata filter cepat dengan bukti mentah `raw_payload JSONB`.
   * Menghilangkan 50% *write I/O amplification* dan menghapus kunci asing penghambat *bulk insert*.
3. **Earliest Deadline First (EDF) View**:
   * View `soc_ops.v_actionable_triage_queue` yang otomatis menghitung batas deadline SLA dinamis berdasarkan urgensi prioritas (P0: 15 menit, P1: 1 jam, P2: 4 jam, P3: 24 jam).
4. **Engine Parameter Tuning**:
   * Alokasi memori `shared_buffers = 2GB` dan `work_mem = 16MB` aktif menjaga seluruh kumpulan data panas berada di memori RAM.

---

## 4. CARA PENGGUNAAN & NAVIGASI BAGI DEVELOPER / DBA

* **Untuk Melihat Skema Utuh Satu File**:
  Buka [database/complete_schema.sql](file:///c:/Users/Pongo/Downloads/wazuh%20alert%20grouping%20-/database/complete_schema.sql).
* **Untuk Mempelajari atau Memodifikasi Query per Domain**:
  Buka folder modular di [database/schemas/](file:///c:/Users/Pongo/Downloads/wazuh%20alert%20grouping%20-/database/schemas/).
* **Untuk Eksekusi Migrasi Bertahap di Aplikasi Python**:
  Aplikasi backend secara otomatis membaca urutan file pada [database/migrations/](file:///c:/Users/Pongo/Downloads/wazuh%20alert%20grouping%20-/database/migrations/) via `DatabaseManager.run_migrations()`.
* **Untuk Inisialisasi Data Uji / Master Seed**:
  Gunakan berkas [database/seed_data.sql](file:///c:/Users/Pongo/Downloads/wazuh%20alert%20grouping%20-/database/seed_data.sql).
