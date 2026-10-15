#!/usr/bin/env python3
"""
threat_intel_check.py
======================
Cek reputasi IP secara otomatis ke AbuseIPDB dan VirusTotal.
Terintegrasi penuh dengan Arsitektur Database PostgreSQL & File Excel Tanpa Mengubah Scope Phase 5.

Mendukung 2 Mode Input:
1. File Excel: "Daftar_IP_per_Rule_ID.xlsx" (atau file excel lainnya)
2. Database Langsung: Otomatis membaca 780 IP unik dari PostgreSQL (telemetry.raw_events)

Cara pakai:
----------
1. Simpan API key di file .env:
     ABUSEIPDB_API_KEY=key1,key2
     VT_API_KEY=key1,key2

2. Jalankan:
     python pipeline/threat_intel_check.py --input-db --output-db --output-xlsx Threat_Intel_Result.xlsx
"""

import argparse
import ipaddress
import json
import os
import re
import sys
import time
from pathlib import Path

import requests
import psycopg2
from openpyxl import Workbook, load_workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

from config.settings import DB_HOST, DB_PORT, DB_USER, DB_PASSWORD

IP_REGEX = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"


# ----------------------------------------------------------------------------
# Util: load .env kalau ada (tanpa perlu install python-dotenv)
# ----------------------------------------------------------------------------
def load_dotenv_simple(path=".env"):
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key, val = key.strip(), val.strip().strip('"').strip("'")
        os.environ.setdefault(key, val)


def parse_api_keys(raw, max_keys=8):
    """Pecah string 'key1,key2,key3' jadi list, buang spasi & entri kosong."""
    if not raw:
        return []
    keys = [k.strip() for k in raw.split(",") if k.strip()]
    return keys[:max_keys]


class KeyRotator:
    """
    Menyimpan beberapa API key untuk satu layanan dan otomatis rotasi jika 429/invalid.
    """
    def __init__(self, keys, name):
        self.keys = keys
        self.name = name
        self.idx = 0
        self.exhausted = set()

    @property
    def current(self):
        if not self.keys:
            return None
        return self.keys[self.idx]

    def rotate(self, reason=""):
        if len(self.keys) <= 1:
            return False
        old_idx = self.idx
        self.idx = (self.idx + 1) % len(self.keys)
        print(f"  [{self.name}] pindah API key #{old_idx+1} -> #{self.idx+1} ({reason})")
        return self.idx != old_idx

    def mark_invalid(self):
        self.exhausted.add(self.idx)

    def all_exhausted(self):
        return len(self.exhausted) >= len(self.keys)


# ----------------------------------------------------------------------------
# 1A. Ekstrak IP dari Database PostgreSQL
# ----------------------------------------------------------------------------
def extract_ips_from_postgres(db_name="wazuh_soc_db"):
    """Membaca 780 IP unik langsung dari tabel telemetry.raw_events."""
    conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, database=db_name, user=DB_USER, password=DB_PASSWORD)
    cur = conn.cursor()
    schema_prefix = "telemetry." if db_name == "wazuh_soc_db" else "public."
    cur.execute(f"""
        SELECT source_ip, count(*) as total_events
        FROM {schema_prefix}raw_events
        WHERE source_ip IS NOT NULL AND source_ip != ''
        GROUP BY source_ip
        ORDER BY total_events DESC;
    """)
    ip_data = {}
    for ip, cnt in cur.fetchall():
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback:
                continue
        except ValueError:
            continue
        ip_data[ip] = {"rules": {"Wazuh_Alerts"}, "total_events": cnt}
    conn.close()
    return ip_data


# ----------------------------------------------------------------------------
# 1B. Ekstrak IP publik dari file Excel
# ----------------------------------------------------------------------------
def extract_ips_from_workbook(path, only_rule=None):
    wb = load_workbook(path, data_only=True, read_only=True)
    ip_data = {}

    for sheet_name in wb.sheetnames:
        if sheet_name == "Summary":
            continue
        m = re.search(r"(\d+)", sheet_name)
        rule_id = m.group(1) if m else sheet_name
        if only_rule and str(rule_id) != str(only_rule):
            continue

        ws = wb[sheet_name]
        for row in ws.iter_rows(values_only=True):
            if not row or row[0] is None:
                continue
            ip_candidate = str(row[0]).strip()
            events = row[1] if len(row) > 1 else None
            if IP_REGEX.match(ip_candidate) and isinstance(events, (int, float)):
                try:
                    addr = ipaddress.ip_address(ip_candidate)
                except ValueError:
                    continue
                if addr.is_private:
                    continue
                entry = ip_data.setdefault(ip_candidate, {"rules": set(), "total_events": 0})
                entry["rules"].add(str(rule_id))
                entry["total_events"] += int(events)

    wb.close()
    return ip_data


# ----------------------------------------------------------------------------
# 2. Cache sederhana berbasis file JSON
# ----------------------------------------------------------------------------
def load_cache(path):
    p = Path(path)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_cache(path, cache):
    Path(path).write_text(json.dumps(cache, indent=2), encoding="utf-8")


# ----------------------------------------------------------------------------
# 3. Panggilan API — AbuseIPDB
# ----------------------------------------------------------------------------
def check_abuseipdb(ip, rotator, max_retries=3):
    total_attempts = max_retries * max(len(rotator.keys), 1)

    for attempt in range(1, total_attempts + 1):
        if rotator.all_exhausted():
            print("  [AbuseIPDB] semua API key tidak valid. Melewati pengecekan.")
            return {"error": "all_keys_invalid"}

        api_key = rotator.current
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}

        try:
            resp = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=15)
        except requests.RequestException as e:
            print(f"  [AbuseIPDB] error koneksi untuk {ip}: {e}")
            time.sleep(2)
            continue

        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return {
                "abuse_score": data.get("abuseConfidenceScore"),
                "total_reports": data.get("totalReports"),
                "country": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "is_tor": data.get("isTor"),
                "last_reported": data.get("lastReportedAt"),
                "usage_type": data.get("usageType"),
            }
        elif resp.status_code == 429:
            print(f"  [AbuseIPDB] rate limit tercapai untuk key #{rotator.idx+1} pada {ip}.")
            if not rotator.rotate("rate limit 429"):
                wait = 15
                print(f"  [AbuseIPDB] cuma 1 key tersedia, menunggu {wait}s...")
                time.sleep(wait)
        elif resp.status_code in (401, 403):
            print(f"  [AbuseIPDB] API key #{rotator.idx+1} tidak valid.")
            rotator.mark_invalid()
            rotator.rotate("key invalid")
        else:
            print(f"  [AbuseIPDB] HTTP {resp.status_code} untuk {ip}: {resp.text[:200]}")
            time.sleep(2)

    return {"error": "failed_after_retries"}


# ----------------------------------------------------------------------------
# 4. Panggilan API — VirusTotal
# ----------------------------------------------------------------------------
def check_virustotal(ip, rotator, max_retries=3):
    url = VT_URL.format(ip=ip)
    n_keys = max(len(rotator.keys), 1)
    total_attempts = max_retries * n_keys
    consecutive_429 = 0

    for attempt in range(1, total_attempts + 1):
        if rotator.all_exhausted():
            print("  [VirusTotal] semua API key tidak valid. Melewati pengecekan.")
            return {"error": "all_keys_invalid"}

        api_key = rotator.current
        headers = {"x-apikey": api_key}

        try:
            resp = requests.get(url, headers=headers, timeout=15)
        except requests.RequestException as e:
            print(f"  [VirusTotal] error koneksi untuk {ip}: {e}")
            time.sleep(2)
            continue

        if resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "vt_malicious": stats.get("malicious"),
                "vt_suspicious": stats.get("suspicious"),
                "vt_harmless": stats.get("harmless"),
                "vt_undetected": stats.get("undetected"),
                "vt_reputation": attrs.get("reputation"),
                "vt_country": attrs.get("country"),
                "vt_as_owner": attrs.get("as_owner"),
                "vt_categories": ", ".join(
                    sorted(set(attrs.get("categories", {}).values()))
                ) if attrs.get("categories") else "",
            }
        elif resp.status_code == 429:
            print(f"  [VirusTotal] rate limit tercapai untuk key #{rotator.idx+1} pada {ip}.")
            consecutive_429 += 1
            if consecutive_429 >= n_keys * 2:
                print(f"  [VirusTotal] semua {n_keys} key kena rate limit berturut-turut. Melewati sisa VT.")
                return {"error": "daily_limit_likely_exhausted"}
            if not rotator.rotate("rate limit 429"):
                wait = 20
                print(f"  [VirusTotal] cuma 1 key tersedia, menunggu {wait}s...")
                time.sleep(wait)
            else:
                time.sleep(2)
        elif resp.status_code in (401, 403):
            print(f"  [VirusTotal] API key #{rotator.idx+1} tidak valid.")
            rotator.mark_invalid()
            rotator.rotate("key invalid")
            consecutive_429 = 0
        elif resp.status_code == 404:
            return {"vt_malicious": None, "vt_note": "IP tidak ditemukan di VirusTotal"}
        else:
            consecutive_429 = 0
            print(f"  [VirusTotal] HTTP {resp.status_code} untuk {ip}: {resp.text[:200]}")
            time.sleep(2)

    return {"error": "failed_after_retries"}


# ----------------------------------------------------------------------------
# 5. Verdict sederhana berdasarkan skor gabungan
# ----------------------------------------------------------------------------
def compute_verdict(result):
    abuse_score = result.get("abuse_score")
    vt_mal = result.get("vt_malicious")

    is_bad = False
    if isinstance(abuse_score, (int, float)) and abuse_score >= 75:
        is_bad = True
    if isinstance(vt_mal, (int, float)) and vt_mal >= 5:
        is_bad = True

    is_suspicious = False
    if isinstance(abuse_score, (int, float)) and 25 <= abuse_score < 75:
        is_suspicious = True
    if isinstance(vt_mal, (int, float)) and 1 <= vt_mal < 5:
        is_suspicious = True

    if is_bad:
        return "MALICIOUS"
    if is_suspicious:
        return "SUSPICIOUS"
    return "CLEAN / TIDAK CUKUP DATA"


# ----------------------------------------------------------------------------
# 6. Simpan hasil ke Database PostgreSQL (Tabel threat_intelligence_iocs)
# ----------------------------------------------------------------------------
def persist_results_to_postgres(results, db_name="wazuh_soc_db"):
    schema_prefix = "enrichment." if db_name == "wazuh_soc_db" else "public."
    conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, database=db_name, user=DB_USER, password=DB_PASSWORD)
    cur = conn.cursor()

    records = []
    for ip, res in results.items():
        score = res.get("abuse_score") or (res.get("vt_malicious") * 10 if res.get("vt_malicious") else 0)
        verdict = compute_verdict(res)
        actor = "Known_Threat_Actor" if verdict == "MALICIOUS" else ("Suspicious_Scanner" if verdict == "SUSPICIOUS" else "Benign_Host")
        feed = "AbuseIPDB + VirusTotal Live"
        desc = f"ISP: {res.get('isp', 'Unknown')} | Country: {res.get('country', 'N/A')} | Verdict: {verdict}"
        records.append((ip, "IPV4", actor, verdict, int(score), feed, desc, True))

    cur.executemany(f"""
        INSERT INTO {schema_prefix}threat_intelligence_iocs 
        (indicator_value, indicator_type, threat_actor, malware_family, confidence_score, source_feed, description, is_active)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (indicator_value, indicator_type) DO UPDATE
        SET confidence_score = EXCLUDED.confidence_score,
            threat_actor = EXCLUDED.threat_actor,
            malware_family = EXCLUDED.malware_family,
            source_feed = EXCLUDED.source_feed,
            description = EXCLUDED.description;
    """, records)
    conn.commit()
    conn.close()
    print(f"[+] Berhasil menyimpan {len(records)} hasil live TI ke PostgreSQL ({schema_prefix}threat_intelligence_iocs)!")


# ----------------------------------------------------------------------------
# 7. Tulis hasil ke Excel
# ----------------------------------------------------------------------------
def write_results_xlsx(ip_data, results, out_path):
    wb = Workbook()
    ws = wb.active
    ws.title = "Threat Intel Result"

    font_name = "Arial"
    header_font = Font(name=font_name, bold=True, color="FFFFFF", size=11)
    header_fill = PatternFill(start_color="1F4E78", end_color="1F4E78", fill_type="solid")
    normal_font = Font(name=font_name, size=10)
    title_font = Font(name=font_name, bold=True, size=14, color="1F4E78")
    center = Alignment(horizontal="center", vertical="center")
    left = Alignment(horizontal="left", vertical="center")
    thin = Side(style="thin", color="BFBFBF")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)

    verdict_fill = {
        "MALICIOUS": PatternFill(start_color="F8696B", end_color="F8696B", fill_type="solid"),
        "SUSPICIOUS": PatternFill(start_color="FFEB84", end_color="FFEB84", fill_type="solid"),
        "CLEAN / TIDAK CUKUP DATA": PatternFill(start_color="63BE7B", end_color="63BE7B", fill_type="solid"),
    }

    ws["A1"] = "Hasil Pengecekan Threat Intelligence (AbuseIPDB + VirusTotal)"
    ws["A1"].font = title_font
    ws.merge_cells("A1:N1")

    headers = [
        "IP Address", "Rule ID Terkait", "Total Kejadian",
        "AbuseIPDB Score", "AbuseIPDB Reports", "AbuseIPDB Country",
        "AbuseIPDB ISP", "AbuseIPDB Usage Type",
        "VT Malicious", "VT Suspicious", "VT Harmless",
        "VT Reputation", "VT Categories", "Verdict",
    ]
    row = 3
    for col, h in enumerate(headers, start=1):
        c = ws.cell(row=row, column=col, value=h)
        c.font = header_font
        c.fill = header_fill
        c.alignment = center
        c.border = border

    r = row + 1
    def sort_key(item):
        ip, meta = item
        res = results.get(ip, {})
        score = res.get("abuse_score") or 0
        vt = res.get("vt_malicious") or 0
        return -(score + vt * 10)

    for ip, meta in sorted(ip_data.items(), key=sort_key):
        res = results.get(ip, {})
        verdict = compute_verdict(res)

        values = [
            ip,
            ", ".join(sorted(meta["rules"])) if isinstance(meta["rules"], set) else str(meta["rules"]),
            meta["total_events"],
            res.get("abuse_score"),
            res.get("total_reports"),
            res.get("country"),
            res.get("isp"),
            res.get("usage_type"),
            res.get("vt_malicious"),
            res.get("vt_suspicious"),
            res.get("vt_harmless"),
            res.get("vt_reputation"),
            res.get("vt_categories"),
            verdict,
        ]
        for col, val in enumerate(values, start=1):
            c = ws.cell(row=r, column=col, value=val)
            c.font = normal_font
            c.border = border
            c.alignment = left if col in (1, 2, 7, 8, 13) else center
            if col == len(values):
                c.fill = verdict_fill.get(verdict, PatternFill())
                c.font = Font(name=font_name, size=10, bold=True)
        r += 1

    widths = [18, 16, 14, 14, 16, 14, 22, 16, 12, 12, 12, 14, 26, 24]
    for i, w in enumerate(widths, start=1):
        ws.column_dimensions[get_column_letter(i)].width = w
    ws.freeze_panes = "A4"

    wb.save(out_path)
    print(f"\nHasil tersimpan di Excel: {out_path}")


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Cek threat intelligence IP via AbuseIPDB & VirusTotal")
    parser.add_argument("--input", default="Daftar_IP_per_Rule_ID.xlsx", help="File Excel input")
    parser.add_argument("--input-db", action="store_true", help="Ambil daftar IP langsung dari database PostgreSQL (telemetry.raw_events)")
    parser.add_argument("--output", default="Threat_Intel_Result.xlsx", help="File Excel output")
    default_cache = "data/cache/ti_cache.json" if os.path.exists("data/cache/ti_cache.json") else "ti_cache.json"
    parser.add_argument("--cache", default=default_cache, help="File cache JSON")
    parser.add_argument("--limit", type=int, default=None, help="Batasi jumlah IP yang dicek")
    parser.add_argument("--only-rule", default=None, help="Hanya cek IP dari Rule ID tertentu")
    parser.add_argument("--skip-abuseipdb", action="store_true")
    parser.add_argument("--skip-virustotal", action="store_true")
    parser.add_argument("--abuseipdb-delay", type=float, default=1.5, help="Jeda (detik) antar request AbuseIPDB")
    parser.add_argument("--vt-delay", type=float, default=16.0, help="Jeda (detik) antar request VirusTotal")
    args = parser.parse_args()

    load_dotenv_simple()

    abuseipdb_keys = parse_api_keys(os.environ.get("ABUSEIPDB_API_KEY", ""))
    vt_keys = parse_api_keys(os.environ.get("VT_API_KEY", ""))

    abuse_rotator = KeyRotator(abuseipdb_keys, "AbuseIPDB")
    vt_rotator = KeyRotator(vt_keys, "VirusTotal")

    if not args.skip_abuseipdb and not abuseipdb_keys:
        print("INFO: ABUSEIPDB_API_KEY belum diset. Lewati live request AbuseIPDB (pakai cache jika ada).")
        args.skip_abuseipdb = True
    elif len(abuseipdb_keys) > 1:
        print(f"[AbuseIPDB] {len(abuseipdb_keys)} API key terdaftar, akan rotasi otomatis.")

    if not args.skip_virustotal and not vt_keys:
        print("INFO: VT_API_KEY belum diset. Lewati live request VirusTotal (pakai cache jika ada).")
        args.skip_virustotal = True
    elif len(vt_keys) > 1:
        print(f"[VirusTotal] {len(vt_keys)} API key terdaftar, akan rotasi otomatis.")

    if args.input_db:
        print("[+] Mengambil daftar IP publik langsung dari PostgreSQL telemetry.raw_events...")
        ip_data = extract_ips_from_postgres()
    elif Path(args.input).exists():
        print(f"[+] Membaca daftar IP publik dari file Excel: {args.input}")
        ip_data = extract_ips_from_workbook(args.input, only_rule=args.only_rule)
    else:
        print(f"[-] File input {args.input} tidak ditemukan. Beralih otomatis ke database PostgreSQL...")
        ip_data = extract_ips_from_postgres()

    ips = list(ip_data.keys())
    print(f"[+] Total ditemukan {len(ips)} IP publik unik untuk dicek.")

    if args.limit:
        ips = ips[: args.limit]
        print(f"[!] Dibatasi menjadi {len(ips)} IP (--limit).")

    cache = load_cache(args.cache)
    results = {}

    for idx, ip in enumerate(ips, start=1):
        entry = cache.get(ip, {})
        needs_api = False

        if not args.skip_abuseipdb and "abuse_score" not in entry:
            needs_api = True
            res = check_abuseipdb(ip, abuse_rotator)
            entry.update(res)
            if res.get("error") == "all_keys_invalid":
                args.skip_abuseipdb = True
            time.sleep(args.abuseipdb_delay)

        if not args.skip_virustotal and "vt_malicious" not in entry:
            needs_api = True
            res = check_virustotal(ip, vt_rotator)
            entry.update(res)
            if res.get("error") in ("all_keys_invalid", "daily_limit_likely_exhausted"):
                args.skip_virustotal = True
            time.sleep(args.vt_delay)

        if needs_api:
            print(f"  [{idx}/{len(ips)}] Checked live: {ip} -> Verdict: {compute_verdict(entry)}")

        cache[ip] = entry
        results[ip] = entry

        if idx % 10 == 0:
            save_cache(args.cache, cache)

    save_cache(args.cache, cache)

    # Simpan ke PostgreSQL jika opsi diaktifkan
    if args.output_db:
        persist_results_to_postgres(results, "wazuh_soc_db")
        persist_results_to_postgres(results, "wazuh_alerts")

    write_results_xlsx(ip_data, results, args.output)


if __name__ == "__main__":
    main()
