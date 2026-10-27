"""
Generate Executive Forensic Summaries for all Threat Campaigns
==============================================================
Populates correlation.threat_campaign_clusters.narrative_summary
with AI-generated executive summaries.
"""

import sys
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import psycopg2
import requests
import json
import time
import logging
import config.settings as s

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("GenerateExecutiveSummaries")

def generate_summaries():
    conn = psycopg2.connect(
        host=s.DB_HOST, port=s.DB_PORT, dbname=s.DB_NAME, user=s.DB_USER, password=s.DB_PASSWORD
    )
    cur = conn.cursor()

    cur.execute("""
        SELECT 
            c.cluster_id, c.target_host, c.priority, c.cluster_status,
            c.total_distinct_actors, c.total_raw_events_count,
            c.mitre_tactics_chain, i.title, i.narrative
        FROM correlation.threat_campaign_clusters c
        JOIN correlation.correlated_incidents i ON c.pivot_incident_id = i.incident_id
        ORDER BY 
            CASE c.priority WHEN 'P0' THEN 1 WHEN 'P1' THEN 2 WHEN 'P2' THEN 3 ELSE 4 END,
            c.total_raw_events_count DESC;
    """)
    rows = cur.fetchall()
    total = len(rows)
    logger.info(f"[*] Found {total} threat campaigns to summarize.")

    gemini_url = f"https://generativelanguage.googleapis.com/v1beta/models/{s.CLOUD_LLM_MODEL}:generateContent?key={s.GEMINI_API_KEY}"

    success_count = 0
    for idx, r in enumerate(rows, 1):
        cluster_id, target, prio, status, actors, logs, tactics, title, narr = r
        tactics_str = ", ".join(tactics) if tactics else "General Security Anomalies"

        prompt = f"""Anda adalah Senior SOC Lead & Threat Intelligence Specialist.
Tuliskan Executive Summary (Ringkasan Forensik Eksekutif) dalam 2-3 kalimat profesional berbahasa Indonesia untuk kampanye serangan siber berikut:

ID Kampanye: {cluster_id}
Target Korban: {target}
Tingkat Keparahan / Priority: {prio} (Status: {status})
Jumlah Aktor/IP Terlibat: {actors} aktor
Total Log Serangan: {logs:,} peristiwa
Rantai Taktik MITRE ATT&CK: {tactics_str}
Aktivitas Pivot: {title}
Konteks Forensik: {narr}

Aturan Penulisan:
1. Tulis tepat 2 hingga 3 kalimat padat, tajam, dan profesional dalam Bahasa Indonesia.
2. Jelaskan tahapan serangan dari penetrasi awal hingga dampak akhir (misal eksploitasi, eskalasi root/admin, brute force terdistribusi).
3. Berikan rekomendasi mitigasi teknis ringkas (misal isolasi host, rotasi kredensial, atau blokir IP IOC).
4. Output HANYA berupa teks ringkasan, tanpa awalan seperti 'Ringkasan:' atau tanda kutip.
"""

        summary_text = None
        # Attempt Gemini
        try:
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.2, "maxOutputTokens": 280}
            }
            resp = requests.post(gemini_url, json=payload, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                summary_text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
        except Exception as e:
            logger.warning(f"Gemini error for {cluster_id}: {e}")

        # Fallback to Local LLM (Qwen) if Gemini unavailable
        if not summary_text:
            try:
                local_url = f"{s.LOCAL_LLM_ENDPOINT}/api/generate"
                payload = {
                    "model": s.LOCAL_LLM_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.2, "num_predict": 250}
                }
                resp = requests.post(local_url, json=payload, timeout=20)
                if resp.status_code == 200:
                    summary_text = resp.json().get("response", "").strip()
            except Exception as e_loc:
                logger.warning(f"Local LLM error for {cluster_id}: {e_loc}")

        # Deterministic domain fallback if offline
        if not summary_text:
            summary_text = (
                f"Kampanye ancaman {prio} terdeteksi menargetkan server {target} dengan melibatkan {actors} aktor penyerang dan total {logs:,} rekaman log telemetri mencakup taktik {tactics_str}. "
                f"Analisis forensik mengidentifikasi aktivitas intrusi kritis berbasis '{title}' yang berpotensi menyebabkan kompromi perimeter. "
                f"Direkomendasikan segera mengisolasi host terdampak, mencabut sesi akun aktif, dan memblokir seluruh alamat IP aktor pada firewall perimeter."
            )

        # Update database
        cur.execute("""
            UPDATE correlation.threat_campaign_clusters
            SET narrative_summary = %s,
                updated_at = CURRENT_TIMESTAMP
            WHERE cluster_id = %s;
        """, (summary_text, cluster_id))
        conn.commit()

        success_count += 1
        logger.info(f"[{idx}/{total}] Generated summary for {cluster_id} ({target}): {summary_text[:85]}...")
        time.sleep(0.3)

    logger.info("=" * 80)
    logger.info(f"[SUCCESS] Executive Forensic Summaries updated for {success_count}/{total} campaigns.")
    logger.info("=" * 80)
    cur.close()
    conn.close()

if __name__ == "__main__":
    generate_summaries()
