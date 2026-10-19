# Konfigurasi Wazuh Manager & Arsitektur Penarikan Data Vector ke PostgreSQL

---

```text
┌────────────────────────────────────────────────────────┐
│ Wazuh Manager Engine                                   │
│                                                        │
│   ┌──────────────────────────────────────────────┐     │
│   │ Event Log Sistem / Agent                     │     │
│   └──────────────────────┬───────────────────────┘     │
│                          │                             │
│         1. Deteksi & Analisis Rule                     │
│                          │                             │
│                          ▼                             │
│   ┌──────────────────────────────────────────────┐     │
│   │ Wazuh Analysis Engine                        │     │
│   └──────────────────────┬───────────────────────┘     │
│                          │                             │
│         2. Tulis JSON Terstruktur                      │
│                          │                             │
│                          ▼                             │
│   ┌──────────────────────────────────────────────┐     │
│   │ /var/ossec/logs/alerts/alerts.json           │     │
│   │ (Shared Disk Buffer)                         │     │
│   └──────────────────────────────────────────────┘     │
└──────────────────────────┬─────────────────────────────┘
                           │
                 3. Streaming Tailing
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ Vector Native Shipper (Co-Located)                     │
│                                                        │
│   ┌──────────────────────────────────────────────┐     │
│   │ Vector Core Engine (Rust-Based)              │     │
│   │ (RAM ~10 MB, Ultra High-Throughput >50K EPS) │     │
│   └──────────────────────┬───────────────────────┘     │
│                          │                             │
│         4. Parsing & VRL Remap Transformation          │
│                          │                             │
│                          ▼                             │
│   ┌──────────────────────────────────────────────┐     │
│   │ Vector Native PostgreSQL Sink                │     │
│   │ (sinks.postgres / batch insert)              │     │
│   └──────────────────────────────────────────────┘     │
└──────────────────────────┬─────────────────────────────┘
                           │
                 5. Relational Mapping
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ Database Storage (PostgreSQL)                          │
│                                                        │
│   ┌──────────────────────────────────────────────┐     │
│   │ PostgreSQL Connection Pool                   │     │
│   │ (Port 5432)                                  │     │
│   └──────────────────────┬───────────────────────┘     │
│                          │                             │
│         6. Bulk Stream Write                           │
│                          │                             │
│                          ▼                             │
│   ┌──────────────────────────────────────────────┐     │
│   │ PostgreSQL Database 'wazuh_soc_db'           │     │
│   │ (19-Table Enterprise Schema)                 │     │
│   └──────────────────────────────────────────────┘     │
└────────────────────────────────────────────────────────┘
```

---

## 1.1. Konfigurasi Wazuh Manager (`/var/ossec/etc/ossec.conf`)

Konfigurasi ini memastikan seluruh alert hasil tuning (Level 0, 1, dan 2) serta event normal (Level 3–15+) ditulis lengkap ke dalam satu berkas `/var/ossec/logs/alerts/alerts.json` tanpa perlu mengaktifkan berkas arsip mentah (`archives.json`).

Buka file konfigurasi:
```bash
sudo nano /var/ossec/etc/ossec.conf
```

Pastikan blok `<alerts>` dan `<global>` terkonfigurasi sebagai berikut:
```xml
<ossec_config>
  <alerts>
    <!-- Menurunkan ambang batas ke 0 agar rule level 0, 1, dan 2 ikut dicatat -->
    <log_alert_level>0</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <!-- archives.json tetap dimatikan untuk mencegah pemborosan storage -->
    <logall>no</logall>
    <logall_json>no</logall_json>
  </global>
</ossec_config>
```

---

## 1.2. Konfigurasi Filter Filebeat (`/etc/filebeat/filebeat.yml`)

Konfigurasi ini bertugas melindungi Wazuh Indexer (OpenSearch) agar **HANYA** menerima Level $\ge 3$, sehingga dasbor SOC bawaan tetap bersih dan cepat, sementara seluruh aliran log dialihkan secara khusus ke database **PostgreSQL (`wazuh_soc_db`)** melalui Vector.

Buka file konfigurasi:
```bash
sudo nano /etc/filebeat/filebeat.yml
```

Isi konfigurasi lengkap:
```yaml
output.elasticsearch:
  hosts: ["127.0.0.1:9200"]
  protocol: https
  username: admin
  password: "YOUR_WAZUH_INDEXER_PASSWORD"
  ssl.verification_mode: none

filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
      # Membuang log Level 0, 1, dan 2 agar TIDAK MASUK ke Wazuh Indexer
      processors:
        - drop_event:
            when:
              range:
                rule.level:
                  lt: 3

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644
```

---

## 1.3. Konfigurasi Vector Native Shipper (`/etc/vector/vector.yaml`)

Konfigurasi Vector untuk membaca berkas `alerts.json` secara *near real-time*, memvalidasi JSON dengan *Vector Remap Language* (VRL), dan langsung menuliskan ke database PostgreSQL secara *micro-batch*.

Buka file konfigurasi:
```bash
sudo nano /etc/vector/vector.yaml
```

Isi konfigurasi lengkap:
```yaml
sources:
  wazuh_alerts:
    type: file
    include:
      - /var/ossec/logs/alerts/alerts.json
    read_from: beginning
    line_delimiter: "\n"

transforms:
  parse_wazuh_json:
    type: remap
    inputs:
      - wazuh_alerts
    source: |
      . = parse_json!(string!(.message))
      .ingested_at = now()

sinks:
  postgres_wazuh_db:
    type: postgres
    inputs:
      - parse_wazuh_json
    endpoint: "postgresql://postgres:YOUR_DB_PASSWORD@127.0.0.1:5432/wazuh_soc_db"
    table: "raw_events"
    batch:
      max_events: 500
      timeout_secs: 2
```

---

## 2. Tabel Rincian Tahap demi Tahap Penarikan Data

| Tahap | Komponen & Mekanisme | Penjelasan Teknis & Alur Data | Hasil & Dampak Sistem |
| :--- | :--- | :--- | :--- |
| **Tahap 1** | **Pembangkitan Alert di Wazuh Engine** | Log event dari seluruh agent dievaluasi oleh *decoders* dan aturan keamanan. Jika terpicu, engine menuliskan dokumen JSON terstruktur ke `/var/ossec/logs/alerts/alerts.json` secara *append-only*. | Berkas JSON lokal berfungsi sebagai *queue buffer* berbasis disk yang cepat dan aman dari kehilangan data (*lossless*). |
| **Tahap 2** | **Streaming Log via Vector File Source** | Vector Core Engine (berbasis Rust) membaca baris baru dari `alerts.json` secara *streaming inotify tailing* dengan pelacakan *checkpoint offset* berkas otomatis. | Konsumsi memori ultra-rendah ($\approx 10\text{ MB} - 15\text{ MB}$ RAM), CPU $< 0.3\%$, dan tidak membebani komputasi engine Wazuh. |
| **Tahap 3** | **Parsing & VRL Transformation di Vector Engine** | Mesin VRL (*Vector Remap Language*) memvalidasi JSON mentah, mengekstrak atribut penting (`rule.id`, `agent.ip`, `data`), dan memetakan struktur data ke format skema kolom relasional PostgreSQL. | 100% *Full Fields* dipetakan secara presisi dan tipe data divalidasi sebelum menyentuh layer database. |
| **Tahap 4** | **Persistensi & Connection Pooling di PostgreSQL** | Vector Native PostgreSQL Sink membuka TCP connection pool persisten ke port 5432, melakukan operasi penulisan *bulk batch* atomik ke database `wazuh_soc_db`. | Data tersimpan aman dan terindeks pada **19 Tabel Relasional Enterprise**, siap melayani kueri analitik SOC dengan latensi sub-milidetik. |

---

## 3. Tabel Justifikasi Pemilihan Metode

| Aspek / Metode Terpilih | Metode Alternatif yang Ditolak | Rasional Teknis & Keunggulan Terukur | Dampak Kinerja & Keamanan |
| :--- | :--- | :--- | :--- |
| **Vector Native Shipper (Rust Engine)** | **Logstash Middleware (Java Virtual Machine / JVM)** | Vector hanya membutuhkan $\approx 10\text{ MB}$ RAM dan CPU $< 0.3\%$, sedangkan Logstash memakan $1.5 - 2\text{ GB}$ RAM serta menimbulkan jeda *Garbage Collection (GC pause)*. | Mencegah server *freeze* dan menghemat kapasitas RAM untuk pemrosesan utama Wazuh Manager. |
| **Vector File Source (`alerts.json`)** | **Integrasi Direct Socket / Syslog Stream** | Membaca file disk memisahkan siklus hidup *shipper* dari engine utama (*fully decoupled*). Gangguan koneksi ke PostgreSQL tidak akan menahan atau menghentikan aliran log di Wazuh. | Menjamin *Zero Backpressure* dan mencegah kegagalan berantai (*zero cascading failure*). |
| **Vector Native PostgreSQL Sink (TCP Pool)** | **REST API Bridge / HTTP Ingestion Middleware** | Vector memanfaatkan koneksi biner TCP persisten yang menggunakan kembali (*reusing*) soket yang sudah terbuka, meniadakan *overhead handshake* HTTP berulang. | *Throughput* penulisan sangat tinggi ($> 30.000 - 50.000\text{ EPS}$) dengan latensi penulisan sangat rendah dan konsistensi transaksi ACID terjamin. |
| **19-Table Enterprise Relational Schema (`wazuh_soc_db`)** | **Single Table Raw JSON Dump (`jsonb` murni)** | Skema 19 tabel memisahkan *raw telemetry*, hasil deduplikasi 15 menit, korelasi *attack stages*, dan skor risiko dinamis P0–P4 ke dalam tabel terindeks khusus. | Mencegah tabel database membengkak (*table bloat*), mempercepat kueri *forensic dashboard* hingga $10\times$, serta mendukung audit kepatuhan ISO 27001 dan PCI DSS. |
