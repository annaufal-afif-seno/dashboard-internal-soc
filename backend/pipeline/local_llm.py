"""
Tier-2 Local / Private LLM Triage Client (Ollama Integration)
=============================================================
Evaluates ambiguous incidents (where Tier-1 ML Confidence < 85%) using
local open-source LLM (Qwen on remote dedicated PC via Ollama).

Policy (Prinsip Cascading AI Triage):
  - If Local LLM Confidence >= 85.0%:
      * BENIGN -> AUTO_CLOSE (Suppressed with Wazuh rule proposal)
      * THREAT -> FORWARD_TO_TRIAGE (Auto-escalated to Analyst as High Priority)
  - If Local LLM Confidence < 85.0%:
      * REQUIRE_GROUND_TRUTH (Escalated to Human Analyst for definitive manual label)
"""

import os
import json
import time
import logging
import urllib.request
import urllib.error
import ipaddress
from typing import Dict, Any, Optional, List

from config.settings import (
    LOCAL_LLM_URL,
    LOCAL_LLM_MODEL,
    LOCAL_LLM_TIMEOUT,
    LOCAL_LLM_CONFIDENCE_THRESHOLD,
    AUTO_GT_CONFIDENCE_FLOOR,
    DB_HOST,
    DB_PORT,
    DB_NAME,
    DB_USER,
    DB_PASSWORD,
)

logger = logging.getLogger("LocalLLMTriageClient")


def sanitize_prompt_text(text: str) -> str:
    """
    Sanitize untrusted alert text from potential LLM Prompt Injection (OWASP LLM01 / MITRE AML.T0051).
    Neutralizes attempts by attackers to override system prompts via log payloads.
    """
    import re
    if not text:
        return ""
    sanitized = str(text)
    injection_patterns = [
        r"(?i)(ignore|disregard|forget)\s+(previous|above|all)\s+(instructions?|system\s+prompts?|rules?)",
        r"(?i)(you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+([a-zA-Z0-9_\-\s]+)",
        r"(?i)(verdict|decision)\s*[:=]\s*[\"']?(benign|safe|false_positive)[\"']?",
        r"(?i)system\s*:\s*",
        r"(?i)\[system\s+instruction[^\]]*\]",
        r"(?i)\[inst\].*?\[/inst\]",
    ]
    for pattern in injection_patterns:
        sanitized = re.sub(pattern, "[FILTERED_ADVERSARIAL_INSTRUCTION]", sanitized)
    return sanitized


class LocalLLMTriageClient:
    """
    Tier-2 Private LLM Client connecting to Ollama on local network.
    Evaluates ambiguous incidents with deep context & reasoning.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[int] = None,
        threshold: Optional[float] = None,
    ):
        self.base_url = (base_url or LOCAL_LLM_URL).rstrip("/")
        self.model = model or LOCAL_LLM_MODEL
        self.timeout = timeout or LOCAL_LLM_TIMEOUT
        self.threshold = threshold or LOCAL_LLM_CONFIDENCE_THRESHOLD

    def is_available(self) -> bool:
        """Check if remote Ollama service is reachable and responsive."""
        try:
            url = f"{self.base_url}/api/tags"
            req = urllib.request.Request(url, headers={"User-Agent": "Wazuh-SOC-Triage/1.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status == 200
        except Exception as e:
            logger.warning(f"[LocalLLM] Service unreachable at {self.base_url}: {e}")
            return False

    def build_prompt(self, incident: Dict[str, Any]) -> str:
        """Build specialized Cyber SOC L2 prompt for forensic context evaluation."""
        inc_id = incident.get("incident_id") or "UNKNOWN"
        title = sanitize_prompt_text(incident.get("title") or "Security Incident")
        narrative = sanitize_prompt_text(incident.get("narrative") or "No narrative provided.")
        target_host = incident.get("target_host") or "Unknown Host"
        crit_tier = incident.get("host_criticality") or "STANDARD"
        total_risk = incident.get("total_risk_score") or incident.get("total_score") or 50
        priority = incident.get("priority") or "P2"
        rule_code = incident.get("rule_code") or incident.get("correlation_rule_id") or "ANOMALOUS_PROBE"

        # Resolve attacker IP and locality
        src_ip = (
            incident.get("attacker_source_ip")
            or incident.get("source_ip")
            or incident.get("src_ip")
            or "Unknown"
        )
        ip_locality = "EXTERNAL_PUBLIC"
        if src_ip and src_ip != "Unknown":
            try:
                ip_obj = ipaddress.ip_address(str(src_ip).strip())
                if ip_obj.is_private or ip_obj.is_loopback:
                    ip_locality = "INTERNAL_PRIVATE_RFC1918"
            except ValueError:
                pass

        # Stages & events telemetry
        ev_count = incident.get("event_count") or incident.get("events_count") or 1
        stages = incident.get("stages") or []
        stages_count = len(stages) if isinstance(stages, list) and stages else incident.get("stages_count", 1)

        stage_lines = []
        if isinstance(stages, list) and stages:
            for s in stages[:10]:
                if isinstance(s, dict):
                    st_name = s.get("stage_name") or s.get("category") or "ACTION"
                    st_desc = s.get("stage_description") or s.get("description") or ""
                else:
                    st_name = str(s)
                    st_desc = str(s)
                stage_lines.append(f"  - Stage [{st_name}]: {st_desc}")
        stages_summary = "\n".join(stage_lines) if stage_lines else f"  - {stages_count} total forensic stage(s)"

        few_shot_context = self.fetch_few_shot_precedents(limit=2)

        prompt = f"""You are a Senior Cyber SOC Analyst L2. Analyze the following ambiguous security incident and provide your authoritative forensic verdict.

INCIDENT DETAILS:
- Incident ID: {inc_id}
- Title: {title}
- Target Asset: {target_host} (Criticality Tier: {crit_tier})
- Attacker Source IP: {src_ip} (Network Locality: {ip_locality})
- Correlation Rule: {rule_code}
- Priority & Risk Score: Priority {priority} (Total Risk Score: {total_risk}/100)
- Event Volume: {ev_count} raw alert events across {stages_count} stages
- Narrative: {narrative}

FORENSIC STAGES OBSERVED:
{stages_summary}
{few_shot_context}
EVALUATION INSTRUCTIONS:
1. Determine if this incident is BENIGN (Operational Noise / Admin Typo / Benign Routine) or THREAT (True Security Incident / Malicious Intrusion).
2. Assign a calibrated confidence score between 0.0 and 100.0%.
3. Identify applicable MITRE ATT&CK techniques if applicable (or "NONE").
4. Provide a clear forensic rationale for your determination.

OUTPUT FORMAT (Respond STRICTLY in valid JSON matching this exact schema):
{{
  "verdict": "BENIGN" or "THREAT",
  "confidence": <float between 0.0 and 100.0>,
  "mitre_technique": "<technique ID or list>",
  "reasoning": "<forensic explanation>",
  "recommended_action": "AUTO_CLOSE" or "FORWARD_TO_TRIAGE"
}}"""
        return prompt

    def fetch_few_shot_precedents(self, limit: int = 2) -> str:
        """Fetch human analyst-verified precedents to dynamically enrich LLM context."""
        try:
            import psycopg2
            conn = psycopg2.connect(
                host=DB_HOST, port=DB_PORT, database=DB_NAME,
                user=DB_USER, password=DB_PASSWORD, connect_timeout=2
            )
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT incident_id, target_host, priority, rule_code, ground_truth_label, analyst_notes
                    FROM soc_ops.ground_truth_dataset
                    WHERE label_source = 'HUMAN_ANALYST' AND analyst_notes IS NOT NULL
                    ORDER BY id DESC
                    LIMIT %s;
                """, (limit,))
                rows = cur.fetchall()
            conn.close()
            if not rows:
                return ""
            lines = ["\nVERIFIED HUMAN SOC ANALYST GROUND TRUTH (LEARNED PRECEDENTS):"]
            for r in rows:
                v_str = "THREAT" if r[4] == 1 else "BENIGN"
                note_snippet = str(r[5]).split(" | ")[-1][:180]
                lines.append(f"- Incident [{r[0]}] Host: {r[1]} ({r[2]}, Rule: {r[3]}): Verdict={v_str} | Note: {note_snippet}")
            return "\n".join(lines) + "\n"
        except Exception:
            return ""

    def evaluate_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate an incident via Ollama Qwen model and apply Tier-2 decision logic.
        """
        inc_id = incident.get("incident_id") or "UNKNOWN"
        prompt = self.build_prompt(incident)
        t0 = time.time()

        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": "You are a Senior Cyber SOC Analyst L2. Analyze the incident context and respond strictly in valid JSON matching the exact schema without additional markdown fences.",
            "format": "json",
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_predict": 512,
            },
        }

        url = f"{self.base_url}/api/generate"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw_data = json.loads(resp.read().decode("utf-8"))
                elapsed = time.time() - t0

                # Extract JSON from response or thinking
                resp_text = raw_data.get("response", "").strip()
                if not resp_text and raw_data.get("thinking"):
                    # Fallback extract from thinking if model put output there
                    th_text = raw_data.get("thinking", "")
                    s_idx = th_text.find("{")
                    e_idx = th_text.rfind("}")
                    if s_idx != -1 and e_idx != -1:
                        resp_text = th_text[s_idx : e_idx + 1]

                # Robustly find JSON boundaries
                s_idx = resp_text.find("{")
                e_idx = resp_text.rfind("}")
                if s_idx != -1 and e_idx != -1:
                    resp_text = resp_text[s_idx : e_idx + 1]

                parsed = json.loads(resp_text)
                verdict_raw = str(parsed.get("verdict", "UNCERTAIN")).strip().upper()
                if any(k in verdict_raw for k in ("THREAT", "MALICIOUS", "ATTACK", "SUSPICIOUS", "TRUE_POSITIVE", "TRUE POSITIVE", "ANOMALY")):
                    verdict = "THREAT"
                else:
                    verdict = "BENIGN"

                raw_conf = parsed.get("confidence", 50.0)
                if isinstance(raw_conf, (int, float)):
                    conf = float(raw_conf)
                else:
                    c_str = str(raw_conf).strip().upper().replace("%", "")
                    try:
                        conf = float(c_str)
                    except ValueError:
                        if "CRIT" in c_str or "VERY HIGH" in c_str:
                            conf = 95.0
                        elif "HIGH" in c_str:
                            conf = 90.0
                        elif "MED" in c_str or "MODERATE" in c_str:
                            conf = 75.0
                        elif "LOW" in c_str:
                            conf = 50.0
                        else:
                            conf = 50.0

                if 0.0 < conf <= 1.0:
                    conf = conf * 100.0
                conf = max(0.0, min(100.0, round(conf, 2)))
                reasoning = parsed.get("reasoning", "Evaluated by Local Security Reasoning LLM.")
                mitre_tech = parsed.get("mitre_technique", "NONE")

                # Apply Tier-2 Cascading Decision Logic:
                # If confidence >= 85.0 -> AUTO (BENIGN -> AUTO_CLOSE, THREAT -> FORWARD_TO_TRIAGE)
                # If confidence < 85.0 -> REQUIRE_GROUND_TRUTH (Escalated to human analyst)
                if conf >= self.threshold:
                    if verdict == "BENIGN":
                        decision = "AUTO_CLOSE"
                        rec_action = "AUTO_CLOSE"
                    else:
                        decision = "FORWARD_TO_TRIAGE"
                        rec_action = "AUTO_ESCALATE"
                else:
                    decision = "REQUIRE_GROUND_TRUTH"
                    rec_action = "REQUIRE_GROUND_TRUTH"

                result = {
                    "incident_id": inc_id,
                    "model_tier": "Local LLM",
                    "model_name": self.model,
                    "verdict": verdict,
                    "confidence": conf,
                    "decision": decision,
                    "recommended_action": rec_action,
                    "reasoning": f"Qwen ({self.model}): {reasoning}",
                    "mitre_technique": mitre_tech,
                    "execution_time_seconds": round(elapsed, 2),
                    "status": "SUCCESS",
                }

                # Persist evaluation to database
                self._persist_evaluation(inc_id, result)
                return result

        except Exception as e:
            logger.error(f"[LocalLLM] Error evaluating {inc_id}: {e}")
            fallback_res = {
                "incident_id": inc_id,
                "model_tier": "Local LLM",
                "model_name": self.model,
                "verdict": "UNCERTAIN",
                "confidence": 0.0,
                "decision": "REQUIRE_GROUND_TRUTH",
                "recommended_action": "REQUIRE_GROUND_TRUTH",
                "reasoning": f"Local LLM evaluation failed ({e}). Escalated for human ground truth.",
                "mitre_technique": "NONE",
                "execution_time_seconds": round(time.time() - t0, 2),
                "status": "ERROR",
            }
            return fallback_res

    def _persist_evaluation(self, incident_id: str, eval_result: Dict[str, Any]) -> None:
        """Save Local LLM verdict and confidence into PostgreSQL ground_truth_dataset."""
        try:
            import psycopg2

            conn = psycopg2.connect(
                host=DB_HOST,
                port=DB_PORT,
                database=DB_NAME,
                user=DB_USER,
                password=DB_PASSWORD,
                connect_timeout=3,
            )
            cur = conn.cursor()

            # Map verdict to DB convention: TRUE_POSITIVE for Threat, FALSE_POSITIVE for Benign
            db_verdict = "TRUE_POSITIVE" if eval_result["verdict"] == "THREAT" else "FALSE_POSITIVE"
            conf = eval_result["confidence"]
            notes = eval_result["reasoning"]

            # Active Learning & Anti-Poisoning Gate:
            # Only promote to Ground Truth if confidence meets the high assurance floor (>= 95.0%)
            # and decision was an unequivocal auto-resolution (not vetoed, not ambiguous)
            is_auto_action = eval_result.get("decision") in ("AUTO_CLOSE", "FORWARD_TO_TRIAGE")
            if conf >= AUTO_GT_CONFIDENCE_FLOOR and is_auto_action:
                gt_label = 1 if eval_result["verdict"] == "THREAT" else 0
                label_src = "LOCAL_LLM_AUTO"
                dec_path = f"TIER2_{eval_result['decision']}"

                cur.execute(
                    """
                    UPDATE soc_ops.ground_truth_dataset
                    SET local_llm_verdict = %s,
                        local_llm_confidence = %s,
                        ground_truth_label = %s,
                        label_source = %s,
                        decision_path = %s,
                        is_used_in_training = FALSE,
                        analyst_notes = COALESCE(analyst_notes || ' | ', '') || %s
                    WHERE incident_id = %s;
                    """,
                    (db_verdict, conf, gt_label, label_src, dec_path, notes, incident_id),
                )
                logger.info(f"[LocalLLM Distillation] High-assurance verdict ({conf}% >= {AUTO_GT_CONFIDENCE_FLOOR}%) promoted to Ground Truth ({gt_label}) for ML: {incident_id}")
            else:
                # Sub-assurance (< 95.0%), ambiguous, or vetoed cases require definitive human analyst sign-off
                dec_path = f"TIER2_{eval_result.get('decision', 'REQUIRE_GROUND_TRUTH')}"
                cur.execute(
                    """
                    UPDATE soc_ops.ground_truth_dataset
                    SET local_llm_verdict = %s,
                        local_llm_confidence = %s,
                        decision_path = %s,
                        label_source = 'PENDING_HUMAN',
                        analyst_notes = COALESCE(analyst_notes || ' | ', '') || %s
                    WHERE incident_id = %s;
                    """,
                    (db_verdict, conf, dec_path, notes, incident_id),
                )
                logger.info(f"[LocalLLM Escalation] Sub-assurance verdict ({conf}% < {AUTO_GT_CONFIDENCE_FLOOR}%). Preserved as PENDING_HUMAN: {incident_id}")

            conn.commit()
            cur.close()
            conn.close()
        except Exception as e:
            logger.warning(f"[LocalLLM] Could not persist evaluation to DB for {incident_id}: {e}")
