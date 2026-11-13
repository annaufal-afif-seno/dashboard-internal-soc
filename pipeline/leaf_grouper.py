"""
========================================================================================
APEX LEAF GROUPING ENGINE (VERSION 4.0 / LEVEL 2 ACTIVITY GROUPS)
========================================================================================
Implements Level 2 Activity Groups from the Wazuh Alert Intelligence & Correlation Platform
Technical Design Document (Section 3, 9, 10, 11, 15).

Key Architectural Guarantees:
1. Dynamic Sliding Idle Window (W): Idle gap sliding window per category policy.
2. Caps: Strict MAX_DURATION and MAX_ALERTS cap with continuation group lineage.
3. Concurrency Safety: Dual-Key Namespace Advisory Locking (tenant_hash, fp_hash)
   with canonical lexicographical lock acquisition order (0% Deadlock Guarantee).
4. Late Arrival & Out-of-Order:
   - Window expansion with `is_late = TRUE`.
   - Reopen closed groups within grace period W.
   - Virtual Bridge Merge O(1) via `merged_into_id` (zero heavy disk rewrites).
5. Human Analyst Guard: State machine transition lock preventing automated override
   of human analyst investigations and dispositions.
6. Scalable Evidence Mapping: Atomic membership with ON CONFLICT DO NOTHING.
7. Bounded Metadata: Max 50 distinct samples + distinct counter (Anti-OOM / Anti-TOAST).
========================================================================================
"""

import uuid
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple, Set
from dateutil import parser as dt_parser

from pipeline.database import DatabaseManager
from pipeline.category_catalog import CategoryPolicy, classify_alert
from pipeline.fingerprint_engine import Fingerprint, generate_fingerprint

logger = logging.getLogger("LeafGrouper")
logger.setLevel(logging.INFO)

# ── Helper: Parse Window / Duration String ────────────────────────────────────
def parse_window_seconds(spec: Optional[str], default: int = 600) -> int:
    """Parses human-readable duration strings (e.g., '10m', '1h', '36h', '14d') into seconds."""
    if not spec or not isinstance(spec, str):
        return default
    s = spec.strip().lower()
    try:
        if s.endswith("s"):
            return max(1, int(s[:-1]))
        elif s.endswith("m"):
            return max(1, int(s[:-1]) * 60)
        elif s.endswith("h"):
            return max(1, int(s[:-1]) * 3600)
        elif s.endswith("d"):
            return max(1, int(s[:-1]) * 86400)
        return max(1, int(s))
    except Exception:
        return default


def parse_utc_timestamp(ts_val: Any) -> datetime:
    """Parses any timestamp into a microsecond UTC datetime object."""
    if isinstance(ts_val, datetime):
        if ts_val.tzinfo is None:
            return ts_val.replace(tzinfo=timezone.utc)
        return ts_val.astimezone(timezone.utc)
    if isinstance(ts_val, str) and ts_val:
        try:
            dt = dt_parser.parse(ts_val)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            pass
    return datetime.now(timezone.utc)


# ── Leaf Grouper Engine ───────────────────────────────────────────────────────
class LeafGrouperEngine:
    """
    High-Throughput, Atomically Locked Level 2 Activity Group Engine.
    Executes in PostgreSQL transactions with Advisory Locks.
    """

    @staticmethod
    def process_alert(
        cur,
        alert_id: str,
        event_time: datetime,
        tenant_id: str,
        category: CategoryPolicy,
        fp: Fingerprint,
        agent_name: str,
        source_ip: str,
        target: str,
        policy_version: int = 8
    ) -> Tuple[str, str]:
        """
        Processes a single normalized alert into a Leaf Activity Group.
        Returns (group_id, action_taken): action in ('JOINED', 'CREATED', 'REOPENED', 'MERGED')
        """
        window_sec = parse_window_seconds(category.window, 600)
        max_duration_sec = parse_window_seconds(category.max_duration, 3600)
        max_alerts = category.max_alerts or 5000
        baseline_rate = category.baseline_per_min or 3

        # ── 1. Acquire Dual-Key Namespace Advisory Lock ──────────────────────────
        # classid = 32-bit hash of tenant_id, objid = 32-bit hash of fingerprint
        cur.execute(
            """
            SELECT pg_advisory_xact_lock(
                ('x' || substr(md5(%s), 1, 8))::bit(32)::int,
                ('x' || substr(%s, 1, 8))::bit(32)::int
            );
            """,
            (tenant_id, fp.hash)
        )

        # ── 2. Query Candidate Open Groups for this Fingerprint ─────────────────
        cur.execute(
            """
            SELECT group_id, policy_version, first_seen, last_seen, alert_count,
                   continuation_of_id, root_campaign_id, triage_status, assigned_analyst,
                   window_duration_sec, max_duration_sec, tracked_samples, tracked_counts
            FROM telemetry.alert_activity_groups
            WHERE tenant_id = %s AND fingerprint = %s AND status = 'open'
            ORDER BY first_seen DESC
            FOR UPDATE;
            """,
            (tenant_id, fp.hash)
        )
        open_groups = cur.fetchall()

        if open_groups:
            # Evaluate against most recent open group
            cand = open_groups[0]
            cand_id = cand[0]
            cand_pol_ver = cand[1]
            cand_first = cand[2]
            cand_last = cand[3]
            cand_count = cand[4]
            cand_cont_id = cand[5]
            cand_root_id = cand[6] or cand_id
            cand_triage = cand[7]
            cand_analyst = cand[8]
            cand_win_sec = cand[9]
            cand_max_sec = cand[10]
            cand_samples = cand[11] or {}
            cand_counts = cand[12] or {}

            # Join Test Criteria
            w_delta = timedelta(seconds=cand_win_sec)
            window_ok = (event_time >= (cand_first - w_delta)) and (event_time <= (cand_last + w_delta))
            
            new_first = min(cand_first, event_time)
            new_last = max(cand_last, event_time)
            span_ok = (new_last - new_first).total_seconds() <= cand_max_sec
            capacity_ok = (cand_count < max_alerts)
            policy_ok = (cand_pol_ver == policy_version)

            if window_ok and span_ok and capacity_ok and policy_ok:
                # ── Join Test Success: Add to Existing Open Group ──────────────
                is_late = event_time < cand_last
                updated_count = cand_count + 1
                
                # Merge tracked samples (bounded to 50 items)
                merged_samples = dict(cand_samples)
                merged_counts = dict(cand_counts)
                for k, v_list in fp.tracked_samples.items():
                    existing = set(merged_samples.get(k, []))
                    for item in v_list:
                        if len(existing) < 50:
                            existing.add(item)
                    merged_samples[k] = list(existing)
                    merged_counts[k] = merged_counts.get(k, 0) + fp.tracked_distinct_counts.get(k, 1)

                duration_mins = max(1.0, (new_last - new_first).total_seconds() / 60.0)
                peak_rate = round(updated_count / duration_mins, 2)
                is_spike = peak_rate >= max(10 * baseline_rate, 15)
                is_pinned = (category.pin_level is not None and getattr(category, "pin_level", 12) >= 12)

                # Analyst Guard: If human touched triage, don't overwrite with 'UNASSIGNED'
                status_sql = ""
                if cand_triage in ("UNASSIGNED", "OPEN"):
                    status_sql = ", triage_status = 'OPEN'"

                cur.execute(
                    f"""
                    UPDATE telemetry.alert_activity_groups SET
                        first_seen = %s,
                        last_seen = %s,
                        alert_count = %s,
                        tracked_samples = %s::jsonb,
                        tracked_counts = %s::jsonb,
                        peak_rate_per_min = %s,
                        is_spike = %s,
                        is_pinned = %s,
                        updated_at = NOW()
                        {status_sql}
                    WHERE group_id = %s;
                    """,
                    (
                        new_first, new_last, updated_count,
                        json.dumps(merged_samples), json.dumps(merged_counts),
                        peak_rate, is_spike, is_pinned, cand_id
                    )
                )

                # Insert membership link
                cur.execute(
                    """
                    INSERT INTO telemetry.activity_group_alerts (
                        group_id, alert_id, event_time, is_late, added_at
                    ) VALUES (%s, %s, %s, %s, NOW())
                    ON CONFLICT (group_id, alert_id) DO NOTHING;
                    """,
                    (cand_id, alert_id, event_time, is_late)
                )

                return cand_id, "JOINED"

            else:
                # ── Join Test Failed: Close Active Group Gracefully ────────────
                reason = "window_expired"
                if not span_ok:
                    reason = "max_duration"
                elif not capacity_ok:
                    reason = "max_alerts"
                elif not policy_ok:
                    reason = "policy_superseded"

                cur.execute(
                    """
                    UPDATE telemetry.alert_activity_groups SET
                        status = 'closed',
                        closed_reason = %s,
                        updated_at = NOW()
                    WHERE group_id = %s;
                    """,
                    (reason, cand_id)
                )

                # Record audit log
                cur.execute(
                    """
                    INSERT INTO telemetry.activity_group_events (
                        group_id, event_type, reason, details
                    ) VALUES (%s, 'closed', %s, %s::jsonb);
                    """,
                    (cand_id, reason, json.dumps({"final_alert_count": cand_count, "last_seen": cand_last.isoformat()}))
                )

                # Fall through to create continuation group below with lineage link
                prev_group_id = cand_id
                prev_root_id = cand_root_id
        else:
            prev_group_id = None
            prev_root_id = None

        # ── 3. Check for Late Arrival Reopen or Bridge Merge ──────────────────
        cur.execute(
            """
            SELECT group_id, first_seen, last_seen, window_duration_sec, max_duration_sec, alert_count, root_campaign_id
            FROM telemetry.alert_activity_groups
            WHERE tenant_id = %s AND fingerprint = %s AND status = 'closed'
            ORDER BY last_seen DESC
            LIMIT 2;
            """,
            (tenant_id, fp.hash)
        )
        closed_cand = cur.fetchall()

        if closed_cand:
            c1 = closed_cand[0]
            c1_id, c1_first, c1_last, c1_win, c1_max, c1_count, c1_root = c1
            grace_delta = timedelta(seconds=c1_win)

            # Reopen Check: Event falls inside closed window grace
            if (event_time >= c1_first - grace_delta) and (event_time <= c1_last + grace_delta):
                new_first = min(c1_first, event_time)
                new_last = max(c1_last, event_time)
                
                # Check Bridge Merge if second closed group exists
                if len(closed_cand) > 1:
                    c2 = closed_cand[1]
                    c2_id, c2_first, c2_last, _, _, c2_count, _ = c2
                    # If this event bridges c2 and c1
                    bridge_span = (max(c1_last, new_last) - min(c2_first, new_first)).total_seconds()
                    if bridge_span <= c1_max:
                        # Virtual Bridge Merge O(1): c2 is older, c1 merges into c2
                        cur.execute(
                            """
                            UPDATE telemetry.alert_activity_groups SET
                                status = 'merged',
                                merged_into_id = %s,
                                updated_at = NOW()
                            WHERE group_id = %s;
                            """,
                            (c2_id, c1_id)
                        )
                        cur.execute(
                            """
                            UPDATE telemetry.alert_activity_groups SET
                                first_seen = %s,
                                last_seen = %s,
                                alert_count = alert_count + %s + 1,
                                status = 'open',
                                closed_reason = NULL,
                                updated_at = NOW()
                            WHERE group_id = %s;
                            """,
                            (min(c2_first, new_first), max(c1_last, new_last), c1_count, c2_id)
                        )
                        cur.execute(
                            """
                            INSERT INTO telemetry.activity_group_alerts (
                                group_id, alert_id, event_time, is_late, added_at
                            ) VALUES (%s, %s, %s, TRUE, NOW())
                            ON CONFLICT (group_id, alert_id) DO NOTHING;
                            """,
                            (c2_id, alert_id, event_time)
                        )
                        cur.execute(
                            """
                            INSERT INTO telemetry.activity_group_events (
                                group_id, event_type, reason, details
                            ) VALUES (%s, 'merged', 'bridge_merge', %s::jsonb);
                            """,
                            (c2_id, json.dumps({"absorbed_group_id": c1_id, "trigger_alert": alert_id}))
                        )
                        return c2_id, "MERGED"

                # Standard Reopen
                cur.execute(
                    """
                    UPDATE telemetry.alert_activity_groups SET
                        status = 'open',
                        closed_reason = NULL,
                        first_seen = %s,
                        last_seen = %s,
                        alert_count = alert_count + 1,
                        updated_at = NOW()
                    WHERE group_id = %s;
                    """,
                    (new_first, new_last, c1_id)
                )
                cur.execute(
                    """
                    INSERT INTO telemetry.activity_group_alerts (
                        group_id, alert_id, event_time, is_late, added_at
                    ) VALUES (%s, %s, %s, TRUE, NOW())
                    ON CONFLICT (group_id, alert_id) DO NOTHING;
                    """,
                    (c1_id, alert_id, event_time)
                )
                cur.execute(
                    """
                    INSERT INTO telemetry.activity_group_events (
                        group_id, event_type, reason, details
                    ) VALUES (%s, 'reopened', 'late_arrival_in_grace', %s::jsonb);
                    """,
                    (c1_id, json.dumps({"event_time": event_time.isoformat()}))
                )
                return c1_id, "REOPENED"

        # ── 4. Create Brand New Group (Or Continuation Group) ────────────────
        new_group_id = f"APX-LG-{uuid.uuid4().hex[:12].upper()}"
        root_id = prev_root_id or new_group_id

        cur.execute(
            """
            INSERT INTO telemetry.alert_activity_groups (
                group_id, policy_version, category_code, category_domain,
                fingerprint, fingerprint_quality, status, first_seen, last_seen,
                window_duration_sec, max_duration_sec, alert_count,
                continuation_of_id, root_campaign_id, tenant_id,
                agent_name, source_ip, target, fingerprint_input,
                tracked_samples, tracked_counts, is_spike, peak_rate_per_min,
                is_pinned, triage_status, created_at, updated_at
            ) VALUES (
                %s, %s, %s, %s,
                %s, %s, 'open', %s, %s,
                %s, %s, 1,
                %s, %s, %s,
                %s, %s, %s, %s::jsonb,
                %s::jsonb, %s::jsonb, FALSE, 1.0,
                %s, 'OPEN', NOW(), NOW()
            );
            """,
            (
                new_group_id, policy_version, category.code, category.domain,
                fp.hash, fp.quality, event_time, event_time,
                window_sec, max_duration_sec,
                prev_group_id, root_id, tenant_id,
                agent_name or "unknown", source_ip or "none", target or "none",
                json.dumps(fp.body), json.dumps(fp.tracked_samples),
                json.dumps(fp.tracked_distinct_counts),
                (category.pin_level is not None and getattr(category, "pin_level", 12) >= 12)
            )
        )

        # Insert initial alert membership
        cur.execute(
            """
            INSERT INTO telemetry.activity_group_alerts (
                group_id, alert_id, event_time, is_late, added_at
            ) VALUES (%s, %s, %s, FALSE, NOW())
            ON CONFLICT (group_id, alert_id) DO NOTHING;
            """,
            (new_group_id, alert_id, event_time)
        )

        # Audit creation event
        cur.execute(
            """
            INSERT INTO telemetry.activity_group_events (
                group_id, event_type, reason, details
            ) VALUES (%s, 'created', %s, %s::jsonb);
            """,
            (
                new_group_id,
                "continuation" if prev_group_id else "new_fingerprint",
                json.dumps({"continuation_of": prev_group_id, "category": category.code})
            )
        )

        return new_group_id, "CREATED"


# ── Batch Processor for Pipeline Integration ─────────────────────────────────
def process_apex_leaf_grouping_batch(
    db: DatabaseManager,
    batch_records: List[Dict[str, Any]]
) -> Dict[str, int]:
    """
    Main Entrypoint: Processes an ingest micro-batch into Level 2 Leaf Activity Groups.
    Ensures sorted lock acquisition to eliminate deadlocks.
    """
    if not batch_records:
        return {"processed": 0, "joined": 0, "created": 0, "reopened": 0, "merged": 0}

    stats = {"processed": 0, "joined": 0, "created": 0, "reopened": 0, "merged": 0}

    # Step 1: Pre-classify and pre-fingerprint alerts
    prepared_items = []
    for item in batch_records:
        norm_id = item.get("normalized_event_id") or str(uuid.uuid4())
        alert_payload = item.get("apex_data") or item
        event_time_raw = (
            alert_payload.get("timestamps", {}).get("event_time")
            or alert_payload.get("timestamps", {}).get("alert_time")
            or item.get("event_timestamp")
        )
        event_time = parse_utc_timestamp(event_time_raw)
        tenant_id = alert_payload.get("tenant_id") or item.get("tenant_id") or "DEFAULT"
        agent_name = alert_payload.get("observer", {}).get("agent_name") or item.get("agent_name") or "unknown"
        source_ip = alert_payload.get("network", {}).get("src_ip") or item.get("source_ip") or "none"
        target = alert_payload.get("network", {}).get("dst_ip") or alert_payload.get("http", {}).get("url_path") or item.get("target") or "none"

        cat = classify_alert(alert_payload)
        fp = generate_fingerprint(alert_payload, cat)

        prepared_items.append({
            "alert_id": norm_id,
            "event_time": event_time,
            "tenant_id": tenant_id,
            "category": cat,
            "fingerprint": fp,
            "agent_name": agent_name,
            "source_ip": source_ip,
            "target": target,
            "policy_version": 8
        })

    # Step 2: Canonical Lexicographical Sorting by (tenant_id, fingerprint_hash, event_time)
    # This mathematically prevents cross-worker deadlocks!
    prepared_items.sort(key=lambda x: (x["tenant_id"], x["fingerprint"].hash, x["event_time"]))

    # Step 3: Atomic Batch Execution with PostgreSQL Transaction
    try:
        with db.get_connection() as conn:
            with conn.cursor() as cur:
                for p in prepared_items:
                    _, action = LeafGrouperEngine.process_alert(
                        cur=cur,
                        alert_id=p["alert_id"],
                        event_time=p["event_time"],
                        tenant_id=p["tenant_id"],
                        category=p["category"],
                        fp=p["fingerprint"],
                        agent_name=p["agent_name"],
                        source_ip=p["source_ip"],
                        target=p["target"],
                        policy_version=p["policy_version"]
                    )
                    stats["processed"] += 1
                    act_key = action.lower()
                    if act_key in stats:
                        stats[act_key] += 1
            conn.commit()
    except Exception as e:
        logger.error(f"Error processing leaf grouping batch: {e}", exc_info=True)

    return stats
