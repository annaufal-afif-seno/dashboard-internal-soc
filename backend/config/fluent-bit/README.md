# Panduan Integrasi Fluent Bit Output Plugin (`out_postgre`)

Dokumen ini menjelaskan tata cara kompilasi, konfigurasi, dan pengoperasian plugin **Fluent Bit Output Go (`out_postgre.go`)** untuk mengalirkan telemetri mentah Wazuh Alert Stream ke database PostgreSQL (`telemetry.raw_events`) sesuai arsitektur 7-Schema ASOC.

---

## 1. Arsitektur Aliran Data (End-to-End)

```
+-------------------------------------------------------------------------------+
| WAZUH SERVER / AGENT                                                          |
| Alert JSON: /var/ossec/logs/alerts/alerts.json (Level 0 - 16, Zero Drop)      |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
| FLUENT BIT ENGINE + C-SHARED PLUGIN (out_postgre.so)                          |
| - Leader Election HA via table: asoc_leader                                   |
| - Verifikasi proses aktif Wazuh Manager (isWazuhManagerActive)                |
| - Ekstraksi ECS / CIM: Actor, Target, Ports, Protocol, Decoder, Tenant        |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
| POSTGRESQL (telemetry.raw_events + telemetry.raw_events_default)             |
| - Immutable forensic store (Zero Alert Drop)                                  |
| - Idempotent upsert: ON CONFLICT (event_id, timestamp) DO NOTHING             |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
| PYTHON ASOC PIPELINE (scripts/ops/stream_raw_events_to_pipeline.py)          |
| 1. Normalisasi CEM -> telemetry.normalized_events                             |
| 2. Deduplikasi 15 Menit -> suppression.aggregated_alerts & evidence_mapping  |
| 3. Korelasi Rantai Serangan -> correlation.correlated_incidents & stages      |
| 4. Dynamic Risk Scoring -> risk_engine.calculated_risk_scores                 |
| 5. Antrean Triage SOC -> soc_ops.soc_triage_queue (P0-P4 + Dynamic SLA EDF)   |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
| REACT SOC DASHBOARD (IncidentTriageQueue.jsx & SystemMaintenance.jsx)         |
+-------------------------------------------------------------------------------+
```

---

## 2. Cara Kompilasi Plugin di Server Linux

Plugin dibuat menggunakan arsitektur **C-shared Go Plugin**. Jalankan langkah berikut di server Linux yang memiliki compiler Go (v1.20+) dan `gcc`:

```bash
# 1. Masuk ke direktori plugin
cd /path/to/fluent-bit/plugins

# 2. Inisialisasi go module jika belum ada
go mod init wazuh-fluentbit-pg
go get github.com/fluent/fluent-bit-go/output
go get github.com/lib/pq

# 3. Kompilasi ke binary C-shared library (.so)
go build -buildmode=c-shared -o out_postgre.so out_postgre.go

# 4. Pindahkan file .so ke direktori Fluent Bit
sudo mkdir -p /etc/fluent-bit/plugins
sudo cp out_postgre.so /etc/fluent-bit/plugins/
```

---

## 3. Konfigurasi Fluent Bit

### A. `plugins.conf`
Letakkan di `/etc/fluent-bit/plugins.conf`:
```ini
[PLUGINS]
    Path /etc/fluent-bit/plugins/out_postgre.so
```

### B. `fluent-bit.conf`
Letakkan di `/etc/fluent-bit/fluent-bit.conf`:
```ini
[SERVICE]
    Flush        2
    Daemon       Off
    Log_Level    info
    Parsers_File parsers.conf
    Plugins_File plugins.conf

[INPUT]
    Name             tail
    Tag              wazuh.alerts
    Path             /var/ossec/logs/alerts/alerts.json
    Parser           json
    DB               /var/log/fluent-bit-wazuh.db
    Mem_Buf_Limit    64MB
    Buffer_Chunk_Size 1MB
    Buffer_Max_Size  10MB
    Skip_Long_Lines  Off
    Refresh_Interval 1

[OUTPUT]
    Name                  out_postgre
    Match                 wazuh.alerts
    Uri                   postgres://postgres:postgres@127.0.0.1:5432/wazuh_soc_db?sslmode=disable
    Table                 telemetry.raw_events
    Node_ID               wazuh-node-1
    Node_Priority         100
    Check_Wazuh_Process   true
    Disable_Leader_Election false
    Retry_Limit           10
```

---

## 4. Parameter Konfigurasi Plugin

| Parameter | Default | Keterangan |
| :--- | :--- | :--- |
| `Uri` | `$PG_URI` | Connection URI lengkap PostgreSQL |
| `Host` | `127.0.0.1` | Host PostgreSQL jika `Uri` tidak diisi |
| `Port` | `5432` | Port PostgreSQL |
| `User` | `postgres` | User PostgreSQL |
| `Password` | `""` | Password PostgreSQL |
| `Database` | `wazuh_soc_db` | Nama basis data target ASOC |
| `Table` | `telemetry.raw_events` | Tabel tujuan penyerapan telemetri mentah |
| `Node_ID` | Hostname / `wazuh-node-1` | Identitas node untuk cluster failover |
| `Node_Priority` | `100` | Prioritas perebutan leader (angka lebih tinggi menang) |
| `Check_Wazuh_Process` | `true` | Cek status hidup Wazuh Manager lokal via PID & systemctl |
| `Disable_Leader_Election` | `false` | Set `true` jika single-node standalone tanpa cluster failover |

---

## 5. Menjalankan Python Pipeline dari `telemetry.raw_events`

Setelah Fluent Bit aktif mengalirkan alert ke `telemetry.raw_events`, jalankan background worker Python untuk memprosesnya ke antrean triage:

```bash
# Mode Single Pass (memproses semua alert yang belum terproses lalu selesai)
python scripts/ops/stream_raw_events_to_pipeline.py --once

# Mode Continuous Daemon (memantau terus-menerus setiap 2 detik)
python scripts/ops/stream_raw_events_to_pipeline.py --continuous --interval 2
```
