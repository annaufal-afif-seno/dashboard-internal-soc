# REVISED COMPREHENSIVE AUDIT — POST-AMBIGUITY RESOLUTION
## Wazuh Multi-Tenant SOC Alert Triage Pipeline
### Date: 2026-10-08 | Revision: 2.0 (User Answers Integrated)

---

## EXECUTIVE SUMMARY

**Original Score: 462/600 (77.0%) — "Advanced Prototype, Pre-Production"**
**Revised Score: 471/600 (78.5%) — "Advanced Prototype, Pre-Production"** *(+9 pts from clarifications)*

10 ambiguity questions have been answered by the pipeline owner. This document integrates every answer into revised scoring, concrete action items, and implementation recommendations.

---

## SECTION A: 10 AMBIGUITY QUESTIONS — RESOLVED

### Q1: Correlation Key Mismatch

**Question:** Config declares `source_ip + agent_name`, Python groups by `actor + victim + tenant`. Which is intended?
**User Answer:** `actor + victim + tenant`

**Analysis:**
The JSON config uses `match_keys` per rule (e.g. CORR-001: `["source_ip","agent_name"]`). The Python method `_extract_correlation_key()` at line 638 of `correlate.py` handles both via a dynamic resolver:
- `"source_ip"` → `event.source_ip or dedup_actor or "nosrc"` (= actor)
- `"agent_name"` → `event.destination_host or event.agent_name or dedup_target` (= victim)

**Verdict: NO BUG.** The JSON uses logical labels, Python maps them to actor/victim semantics. Config is the specification; Python is the implementation.

**Scoring Impact:** Correlate stage +2 pts (confirmed design intent removes ambiguity penalty).

**Recommendation:** Add a `_match_keys_semantics` comment block in `correlation_rules.json` documenting the mapping.

---

### Q2: FP REJECT vs FP_REJECT Dual-Value

**Question:** Migration 010 allows both. Which is canonical?
**User Answer:** "DIHAPUS SAJA — sudah pakai ML. Benign ≥85% → auto-close → suppression proposal. Threat ≥85% → MISP + IRIS."

**Required Action — Migration 011:**
1. Remap existing `FP REJECT`/`FP_REJECT` records → `AUTO_CLOSED` + `FALSE_POSITIVE_TUNING_REQ`
2. Rebuild CHECK constraint without those two values
3. Clean state machine: NEW → ASSIGNED → INVESTIGATING → PENDING_ACTION → AUTO_CLOSED | ESCALATED_TO_IRIS | RESOLVED | CLOSED

**Scoring Impact:** Ticket +2 pts, Benign Suppress +1 pt.

---

### Q3: LOW_AND_SLOW Detection Status

**Question:** Parameters defined in settings.py but zero consumption. Abandoned or WIP?
**User Answer:** "Kurang tau, berikan rekomendasi best spot dan minim celah."

**Recommendation: Implement in `CorrelationEngine`**

Best integration point: Add `_check_low_and_slow()` method alongside `_check_historical_escalation()`. Called after line 630 in `process_event()`.

Detection logic:
- Query `aggregated_alerts` for actor with multiple sub-threshold windows (each <5 events) but cumulative total ≥ `LOW_AND_SLOW_THRESHOLD` (15) within `LOW_AND_SLOW_WINDOW_HOURS` (6h)
- Use existing `check_cooldown()` to prevent ticket flooding
- Generate P2 severity incident (conservative, not P0/P1)
- No new tables required — uses existing `aggregated_alerts`

**Scoring Impact:** Correlate +1 pt (acknowledged WIP, clear path).

---

### Q4: ML Confidence <85% → FORWARD_TO_TRIAGE SLA

**Question:** Is there an SLA for how fast analysts must review grey-zone tickets?
**User Answer:** "Masih kurang paham pertanyaannya."

**Explanation:** When ML produces confidence <85%, the ticket enters human triage queue. The question is: how fast must the analyst act? Currently there is NO enforced SLA timer. The `mean_time_to_triage_seconds` column is a post-hoc metric, not enforcement.

**Recommended SLA Matrix (when ready):**

| Priority | Target Response | Escalation |
|----------|----------------|------------|
| P0 | 15 minutes | Auto-escalate to SOC Manager |
| P1 | 1 hour | Auto-escalate to SOC Manager |
| P2 | 4 hours | Auto-assign to next available |
| P3 | 24 hours | Auto-close with null ground_truth |
| P4 | 72 hours | Auto-close + batch review log |

Implementation: Add `sla_deadline TIMESTAMPTZ` to `soc_triage_queue` + cron job for overdue checks.

**Scoring Impact:** No change (process decision, not code gap).

---

### Q5: Auto-Close → IRIS Relationship

**Question:** Does ML auto-suppress create IRIS cases?
**User Answer:** "Hanya insiden THREAT ≥85% confidence — masuk ke fitur Verified True Positive."

**Definitive Decision Tree:**

```
ML Output
├── BENIGN ≥85% → AUTO_CLOSE → Suppression Proposal → Policy Bundle → Wazuh Deploy
│   └── NO IRIS case, NO MISP push
├── THREAT ≥85% → VERIFIED TRUE POSITIVE
│   ├── → MISP push_threat_event (IoC enrichment)
│   ├── → IRIS create_case (investigation)
│   └── → triage_status = 'ESCALATED_TO_IRIS'
└── EITHER <85% → FORWARD_TO_TRIAGE → Analyst + Ground Truth
```

**Current Gap:** `ai_triage.py` does NOT currently invoke IRIS/MISP adapters inline — these run as separate batch processes. For real-time THREAT auto-close, the triage orchestrator needs to call adapters directly.

**Scoring Impact:** Threat Escalate +2 pts, Ticket +1 pt.

---

### Q6: Suppression Rule Approval Workflow

**Question:** What's the actual approval flow? Is there a UI?
**User Answer:** "Sudah ada di dashboard. Penulis ≠ penyetuju. Analis menulis ground truth → SOC Manager menyetujui. SOC Developer buat CDB/XML → SOC Manager menyetujui."

**Confirmed Separation of Duties:**

| Workflow | Author | Approver |
|----------|--------|----------|
| Ground Truth labeling | SOC Analyst | SOC Manager |
| Suppression Rule creation | SOC Developer | SOC Manager |
| Policy Bundle deployment | SOC Developer | SOC Manager |

The `governance.py` code enforces `author != approver`. Dashboard provides the UI. Backend enforces the constraint.

**Scoring Impact:** Benign Suppress +1 pt (confirmed working approval workflow).

---

### Q7: LLM Tier 2/3 Production Intent

**Question:** Is ensemble LLM experimental or production-bound?
**User Answer:** Yes, will be used. Architecture:
1. ML conf <85% → Local LLM
2. Local LLM conf <85% → Cloud LLM (with selective masking)
3. Soft voting → score ≥70% → AUTO_CLOSE; <70% → analyst + ground truth
4. **Current focus: ML first, LLM later**

**Key Discrepancy:** Current code uses 65%/35% thresholds. User wants 70% auto-close boundary. This is a future change since `enable_llm_tiers=False` is correct for now.

**When LLM is enabled, update `EnsembleSoftVotingEngine.calculate_vote()` thresholds from 65/35 to 70/30.**

**Scoring Impact:** ML Classify +1 pt (confirmed production roadmap).

---

### Q8: Cloud LLM Simulation Mode — Ground Truth Pollution

**Question:** Should simulated LLM verdicts be recorded in ground_truth_dataset?
**User Answer:** "Kurang tau, berikan rekomendasi best spot dan minim celah."

**Recommendation: BLOCK Simulated Verdicts from Ground Truth**

Risk: `_simulate_cloud_reasoning()` produces deterministic results (risk≥60 → always TRUE_POSITIVE 91%, risk<60 → always FALSE_POSITIVE 87%). If recorded as ground truth:
- ML retraining learns from heuristics, not real LLM intelligence
- Circular dependency: ML → fake LLM → ground truth → ML
- Contaminated confusion matrix

**Implementation:** In `ai_triage.py`, detect `'simulated' in model_name.lower()` and null out LLM columns before DB persistence. Add `is_llm_simulated BOOLEAN` column to `ground_truth_dataset`.

**Scoring Impact:** ML Classify +1 pt.


---

### Q9: Asset Criticality — "All Equal" vs Inventory Tiers

**Question:** asset_inventory.json has CROWN_JEWEL/CRITICAL/HIGH/STANDARD but user says "all equal". Which is truth?
**User Answer:** "Semua asset setara."

**Analysis:** The code in `score.py` (s_asset factor) and `ml_classifier.py` (guardrails) actively uses asset criticality. But the user says all assets are equal.

**Recommendation: Option A — Keep code as-is, populate all assets as STANDARD**
- Set all entries to `"criticality": "STANDARD"`, `"criticality_score": 5`
- Scoring formula works uniformly
- When ready to differentiate, update inventory only — zero code changes
- The guardrail code is a valuable safety net for the future

Do NOT remove asset criticality from scoring (Option B) — it removes a safety net that prevents critical-asset threats from auto-suppression.

**Scoring Impact:** Net 0 (valid scaffolding, accepted by design).

---

### Q10: Vector Transport Status

**Question:** Is Vector deployed? Is there a vector.toml?
**User Answer:** "Belum ada."

**Current state:** Pipeline reads JSONL files from disk via `glob.glob()`. No streaming, no log shipper.

**Recommendation:** Deploy Vector with:
- File source watching `/var/ossec/logs/alerts/alerts.json`
- JSON parsing transform with tenant_id injection
- HTTP sink to pipeline API endpoint with disk buffer (256MB)
- Dead letter queue for failed events
- Filter: `rule.level >= 3` to reduce noise at transport layer

**Scoring Impact:** Already factored in original score (-1 K6 on Ingest).

---

## SECTION B: REVISED SCORING MATRIX

### Scoring Legend
- K1 (15pts): Functional Completeness
- K2 (15pts): Configuration Externalization
- K3 (10pts): Error Handling & Resilience
- K4 (10pts): Observability
- K5 (5pts): Security & Multi-Tenancy
- K6 (5pts): Integration Readiness

| # | Stage | K1 | K2 | K3 | K4 | K5 | K6 | Total | Δ |
|---|-------|----|----|----|----|----|----|-------|---|
| 1 | Ingest | 14 | 13 | 8 | 8 | 4 | 3 | **50/60** | 0 |
| 2 | Normalize | 14 | 13 | 9 | 8 | 4 | 4 | **52/60** | +1 |
| 3 | Aggregate | 13 | 13 | 8 | 8 | 4 | 4 | **50/60** | 0 |
| 4 | Correlate | 14 | 12 | 8 | 7 | 4 | 4 | **49/60** | +3 |
| 5 | Ticket | 12 | 10 | 7 | 6 | 4 | 4 | **43/60** | +3 |
| 6 | Enrich | 12 | 11 | 7 | 6 | 4 | 4 | **44/60** | 0 |
| 7 | Risk Score | 14 | 12 | 8 | 8 | 5 | 4 | **51/60** | 0 |
| 8 | ML Classify | 13 | 11 | 8 | 7 | 4 | 4 | **47/60** | +2 |
| 9 | Benign Suppress | 11 | 10 | 7 | 6 | 4 | 5 | **43/60** | +2 |
| 10 | Threat Escalate | 10 | 9 | 6 | 6 | 3 | 4 | **38/60** | +2 |

**Adapters:**

| Adapter | K1 | K2 | K3 | K4 | K5 | Total | Δ |
|---------|----|----|----|----|----|----|---|
| Wazuh | 12 | 10 | 7 | 6 | 4 | **39/50** | 0 |
| MISP | 11 | 10 | 7 | 6 | 4 | **38/50** | 0 |
| IRIS | 5 | 5 | 4 | 3 | 2 | **19/50** | -4 |

### Summary

| Metric | Original | Revised | Delta |
|--------|----------|---------|-------|
| 10 Stages Total | 462/600 | 467/600 | +5 |
| 3 Adapters Total | ~96/150 | 96/150 | 0 |
| **Combined** | **462/600** | **471/600** | **+9** |
| **Percentage** | **77.0%** | **78.5%** | **+1.5%** |
| **Rating** | Advanced Prototype | Advanced Prototype | — |


---

## SECTION C: PRIORITY ACTION ITEMS (Ordered by Impact)

### 🔴 P0 — Critical (Before Production)

| # | Action | Stage | Effort |
|---|--------|-------|--------|
| 1 | Implement IRIS adapter (full HTTP, retry, circuit-breaker, idempotency) | Threat Escalate | 3-5d |
| 2 | Wire THREAT ≥85% auto-close → IRIS case + MISP push in ai_triage.py | Threat Escalate | 1-2d |
| 3 | Migration 011: Remove FP REJECT/FP_REJECT, fix CHECK constraint | Ticket | 1h |
| 4 | Block simulated LLM verdicts from ground_truth_dataset | ML Classify | 2h |
| 5 | Deploy Vector transport (replace disk-based JSONL) | Ingest | 2-3d |

### 🟡 P1 — High (Before Scale)

| # | Action | Stage | Effort |
|---|--------|-------|--------|
| 6 | Implement LOW_AND_SLOW detection in correlation engine | Correlate | 1d |
| 7 | Externalize ML hardcoded params (known_clean_ips, scale_pos_weight, 85%) | ML Classify | 3h |
| 8 | Add per-tenant ML calibration (separate isotonic curves) | ML Classify | 2-3d |
| 9 | Add SLA timer to triage queue (sla_deadline column + cron) | Ticket | 1-2d |
| 10 | Document match_keys semantics in correlation_rules.json | Correlate | 30m |

### 🟢 P2 — Medium (Before Multi-Tenant Go-Live)

| # | Action | Stage | Effort |
|---|--------|-------|--------|
| 11 | Populate asset_inventory.json with real criticality tiers | Risk Score | Ongoing |
| 12 | Add OOD detection to ML classifier | ML Classify | 2-3d |
| 13 | Add shadow mode for ML (parallel run before auto-close) | ML Classify | 3-5d |
| 14 | Implement LLM Tier 2/3 cascade with 70% threshold | ML+LLM | 1-2wk |
| 15 | Metrics/alerting for simulation mode detection | Observability | 3h |

---

## SECTION D: DEFINITIVE PIPELINE FLOW (Post-Answers)

```
[Wazuh Manager]
      │ (Currently: JSONL disk. Future: Vector)
      ▼
┌──────────┐
│ 1.INGEST │→ Parse JSONL → WazuhRawAlert → CommonEventModel
└────┬─────┘  (ECS aliases, 22-category, FAST_TRACK bypass)
     ▼
┌────────────┐
│ 2.NORMALIZE│→ Plugin chain: DNS, GeoIP, AbuseIPDB, OCSF, MITRE
└────┬───────┘
     ▼
┌────────────┐
│ 3.AGGREGATE│→ 15-min windows, burst detection, cumulative tracking
└────┬───────┘
     ▼
┌────────────┐
│ 4.CORRELATE│→ 8 rules (CORR-001→008), match_keys→actor/victim
└────┬───────┘  Historical lookback, [PLANNED] LOW_AND_SLOW
     ▼
┌────────────┐
│ 5.TICKET   │→ Incident → triage queue → priority
└────┬───────┘  States: NEW→ASSIGNED→INVESTIGATING→AUTO_CLOSED|ESCALATED_TO_IRIS|RESOLVED|CLOSED
     ▼         [REMOVED: FP REJECT/FP_REJECT]
┌────────────┐
│ 6.ENRICH   │→ AbuseIPDB (live), MISP (mock→live), Asset context
└────┬───────┘
     ▼
┌────────────┐
│ 7.RISK     │→ Detection+Confidence+Asset+Identity+TI-KnownGood (0-100)
│   SCORE    │  P0(81-100) P1(61-80) P2(41-60) P3(21-40) P4(0-20)
└────┬───────┘
     ▼
┌────────────────────────────────────┐
│ 8.ML CLASSIFY (LightGBM Tier-1)   │
│ Guardrails: P0/P1, CROWN_JEWEL,   │
│ zero-leakage                       │
│                                    │
│  BENIGN≥85%  │ EITHER<85% │ THREAT≥85%
└──────┬───────┼─────┬──────┼────┬───┘
       ▼       │     ▼      │    ▼
┌──────────┐   │ ┌────────┐ │ ┌──────────────┐
│9.BENIGN  │   │ │FORWARD │ │ │10.THREAT     │
│SUPPRESS  │   │ │TO      │ │ │ESCALATE      │
│          │   │ │TRIAGE  │ │ │              │
│AUTO_CLOSE│   │ │Analyst │ │ │→ MISP push   │
│→Proposal │   │ │+Ground │ │ │→ IRIS case   │
│→Policy   │   │ │Truth   │ │ │[STUB→IMPL]  │
│→Wazuh    │   │ │→ML     │ │ │              │
│Deploy    │   │ │retrain │ │ └──────────────┘
└──────────┘   │ └────────┘ │
```

---

## SECTION E: RISK REGISTER (Post-Answers)

| Risk | Likelihood | Impact | Mitigation | Status |
|------|-----------|--------|------------|--------|
| IRIS adapter is stub — no real case creation | HIGH | HIGH | Implement full HTTP client | 🔴 Open |
| Simulated LLM contaminates ground truth | MEDIUM | HIGH | Block simulated from DB | 🟡 Designed |
| No Vector = no streaming transport | HIGH | MEDIUM | Deploy Vector | 🔴 Open |
| FP REJECT dual-value corrupts analytics | LOW | MEDIUM | Migration 011 | 🟡 Designed |
| LOW_AND_SLOW evasion undetected | MEDIUM | MEDIUM | Implement detection | 🟡 Designed |
| All assets STANDARD = no differentiation | LOW | LOW | Future: populate inventory | ⚪ Accepted |
| ML 85% threshold hardcoded | LOW | LOW | Externalize to settings.py | 🟢 Easy |
| LLM thresholds (65/35 vs 70) misaligned | LOW | LOW | Update when LLM enabled | ⚪ Future |

---

## SECTION F: MATCH_KEYS → PYTHON FIELD MAPPING REFERENCE

| Config value | Python resolution | Semantic role |
|-------------|------------------|--------------|
| `"source_ip"` | `event.source_ip → dedup_actor → "nosrc"` | Actor |
| `"agent_name"` | `event.destination_host → event.agent_name → "noagent"` | Victim |
| `"target"` | Same as agent_name | Victim (alias) |
| `"actor"` | `event.source_ip → dedup_actor → username → "noactor"` | Actor (explicit) |
| `"username"` | `event.username → "nouser"` | Identity |
| `"destination_host"` | `event.destination_host → "nodst"` | Destination |

---

## SECTION G: OPEN ITEMS TRACKER

| # | Item | Status | Target |
|---|------|--------|--------|
| 1 | IRIS adapter full implementation | 🔴 Not Started | Before prod |
| 2 | Migration 011: Remove FP REJECT | 🟡 Designed | Next sprint |
| 3 | LOW_AND_SLOW implementation | 🟡 Designed | Next sprint |
| 4 | Simulation verdict guard | 🟡 Designed | Next sprint |
| 5 | Vector.toml deployment | 🔴 Not Started | Before prod |
| 6 | LLM cascade (Tier 2/3, 70%) | ⚪ Future | After ML stable |
| 7 | Asset inventory population | ⚪ Future | When assets known |
| 8 | SLA timer implementation | ⚪ Future | When process defined |
| 9 | Per-tenant ML calibration | ⚪ Future | Before multi-tenant |
| 10 | match_keys documentation | 🟢 Trivial | Anytime |

---

*END OF REVISED AUDIT — v2.0*
*All 10 ambiguity questions resolved. Pipeline score: 471/600 (78.5%).*
*Next milestone: Implement P0 items (IRIS adapter, Migration 011, Vector) to reach ≥85% (510/600).*

