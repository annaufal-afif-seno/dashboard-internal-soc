"""
SLA Expiry AI Dispatch Worker (All Priorities P0-P4)
====================================================
Canonical entry point for processing all expired triage tickets across all priorities (P0, P1, P2, P3, P4).

Alur Arsitektur (PRD Section 6):
1. Enrich (MISP + AbuseIPDB) setelah SLA tiket menutup dan buffer window berakhir.
2. Evaluasi Cascading AI: Tier 1 (ML) -> Tier 2 (Local LLM) -> Tier 3 (Cloud LLM).
3. Hasil Triage:
   - Confidence >= 85% & BENIGN: Auto-close tiket -> Masuk ke fitur Policy Bundle (By Ticket).
   - Confidence >= 85% & THREAT: Auto-close & Eskalasi IRIS -> Masuk ke fitur Verified Threat & Campaign Clustering.
   - Confidence < 85%: Set status 'GROUNDTRUTH' dengan ground_truth_status 'ACT NEED' -> Masuk ke fitur Ground Truth untuk audit manual analis SOC & approval Manager.

Note:
File ini menyediakan entrypoint representatif untuk 'pipeline.p4_sla_worker'.
"""

from pipeline.p4_sla_worker import (
    get_expired_tickets,
    process_expired_tickets,
    get_expired_p4_tickets,
    process_expired_p4_tickets,
    SLA_MATRIX_MINUTES,
)

__all__ = [
    "get_expired_tickets",
    "process_expired_tickets",
    "get_expired_p4_tickets",
    "process_expired_p4_tickets",
    "SLA_MATRIX_MINUTES",
]

if __name__ == "__main__":
    import argparse
    from config.settings import DB_NAME
    parser = argparse.ArgumentParser(description="SLA Expiry AI Dispatch Worker (All Priorities P0-P4)")
    parser.add_argument("--db", default=DB_NAME, help="Target database name")
    parser.add_argument("--limit", type=int, default=None, help="Max tickets to process")
    args = parser.parse_args()

    results = process_expired_tickets(db_name=args.db, limit=args.limit)
    print(f"Processed {results.get('total_expired', 0)} tickets. Auto-closed: {results.get('auto_closed', 0)}, Escalated: {results.get('escalated', 0)}")
