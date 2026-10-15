"""
Tier-3 Cloud LLM Triage Client (Google Gemini Integration with Data Sanitization)
=================================================================================
Evaluates ambiguous incidents escalated from Tier-1 ML and Tier-2 Local LLM.
Features:
- Built-in Data Sanitizer / Anonymizer (Zero-Leakage Invariant)
- Direct Google Gemini REST API (zero extra heavyweight dependencies)
- Native Structured JSON Output Mode
- Cascading Triage Decision Logic (>= 85% Auto, < 85% Require Human GT)
- PostgreSQL ground_truth_dataset persistence
"""

import os
import re
import json
import time
import logging
import ipaddress
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

from config.settings import (
    GEMINI_API_KEY,
    CLOUD_LLM_MODEL,
    CLOUD_LLM_TIMEOUT,
    CLOUD_LLM_CONFIDENCE_THRESHOLD,
    DB_HOST,
    DB_PORT,
    DB_NAME,
    DB_USER,
    DB_PASSWORD,
)

logger = logging.getLogger("CloudLLMTriageClient")


class CloudLLMTriageClient:
    """
    Tier-3 Cloud LLM Client connecting to Google Gemini.
    Provides authoritative high-level forensic triage for complex or borderline incidents.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[int] = None,
        threshold: Optional[float] = None,
    ):
        self.api_key = api_key if api_key is not None else GEMINI_API_KEY
        self.model = model or CLOUD_LLM_MODEL
        self.timeout = timeout or CLOUD_LLM_TIMEOUT
        self.threshold = threshold or CLOUD_LLM_CONFIDENCE_THRESHOLD
        self.endpoint_url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        )

    def is_available(self) -> bool:
        """Check if Gemini API Key is configured and accessible."""
        if not self.api_key or len(self.api_key.strip()) < 10:
            return False
        try:
            # Lightweight connectivity check
            url = f"{self.endpoint_url}?key={self.api_key}"
            payload = {
                "contents": [{"parts": [{"text": "ping"}]}],
                "generationConfig": {"maxOutputTokens": 5}
            }
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status == 200
        except Exception as e:
            logger.warning(f"[CloudLLM] Gemini check failed: {e}")
            return False

    def sanitize_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """
        Data Sanitizer / Anonymizer (Minim Celah & Zero PII Leakage):
        - Masks internal RFC1918 IPs while preserving locality context.
        - Preserves external public IPs for threat intel reputation analysis.
        - Sanitizes internal passwords/tokens in narratives.
        """
        sanitized = dict(incident)
        src_ip = str(incident.get("attacker_source_ip") or "Unknown").strip()

        # Anonymize internal IP addresses
        if src_ip and src_ip != "Unknown":
            try:
                ip_obj = ipaddress.ip_address(src_ip)
                if ip_obj.is_private or ip_obj.is_loopback:
                    octets = src_ip.split(".")
                    last_octet = octets[-1] if len(octets) == 4 else "X"
                    sanitized["attacker_source_ip"] = f"INTERNAL_SUBNET_NODE_{last_octet}"
                    sanitized["ip_locality"] = "INTERNAL_PRIVATE_RFC1918"
                else:
                    sanitized["ip_locality"] = "EXTERNAL_PUBLIC_INTERNET"
            except ValueError:
                sanitized["ip_locality"] = "UNKNOWN_LOCALITY"

        # Sanitize narrative from possible sensitive tokens / passwords
        narrative = str(sanitized.get("narrative") or "")
        narrative_clean = re.sub(r"(password|pwd|token|secret)\s*[:=]\s*\S+", r"\1=REDACTED", narrative, flags=re.IGNORECASE)

        # Sanitize from prompt injection attacks (OWASP LLM01 / MITRE AML.T0051)
        injection_patterns = [
            r"(?i)(ignore|disregard|forget)\s+(previous|above|all)\s+(instructions?|system\s+prompts?|rules?)",
            r"(?i)(you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+([a-zA-Z0-9_\-\s]+)",
            r"(?i)(verdict|decision)\s*[:=]\s*[\"']?(benign|safe|false_positive)[\"']?",
            r"(?i)system\s*:\s*",
            r"(?i)\[system\s+instruction[^\]]*\]",
            r"(?i)\[inst\].*?\[/inst\]",
        ]
        for p in injection_patterns:
            narrative_clean = re.sub(p, "[FILTERED_ADVERSARIAL_INSTRUCTION]", narrative_clean)
        sanitized["narrative"] = narrative_clean

        # Sanitize title
        title = str(sanitized.get("title") or "")
        for p in injection_patterns:
            title = re.sub(p, "[FILTERED_ADVERSARIAL_INSTRUCTION]", title)
        sanitized["title"] = title

        return sanitized

    def fetch_incident_stages(self, incident_id: str) -> str:
        """Fetch chronological forensic execution stages from database."""
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
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT sequence_order, stage_name, evidence_type, stage_description
                    FROM correlation.incident_stages
                    WHERE incident_id = %s
                    ORDER BY sequence_order ASC;
                """, (incident_id,))
                rows = cur.fetchall()
            conn.close()
            if not rows:
                return "- [ISOLATED_ACTIVITY] Single standalone telemetry event. No multi-stage sequence recorded."
            lines = []
            for r in rows:
                lines.append(f"- Step {r[0]} [{r[1]}]: {r[3]}")
            return "\n".join(lines)
        except Exception as e:
            logger.warning(f"[CloudLLM] Could not fetch stages for {incident_id}: {e}")
            return "- Telemetry sequence details unavailable."

    def fetch_few_shot_precedents(self, limit: int = 3) -> str:
        """Fetch human analyst-verified precedents to dynamically ground LLM in operational reality."""
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
            lines = ["\nVERIFIED HUMAN SOC ANALYST GROUND TRUTH (LEARNED BASELINE):"]
            for r in rows:
                v_str = "THREAT" if r[4] == 1 else "BENIGN"
                note_snippet = str(r[5]).split(" | ")[-1][:180]
                lines.append(f"- Incident [{r[0]}] Target: {r[1]} ({r[2]}, Rule: {r[3]}): Verdict={v_str} | Note: {note_snippet}")
            return "\n".join(lines)
        except Exception as e:
            logger.warning(f"[CloudLLM] Could not fetch precedents: {e}")
            return ""

    def build_prompt(self, incident: Dict[str, Any]) -> str:
        """
        Build Action & Evidence-First Cyber SOC L3 prompt for Google Gemini.
        Zero Bias Invariant:
        - Evaluates chronological execution logs and raw evidence.
        - Stripped of artificial 'Crown Jewel' bias (all production assets are treated equally).
        - Source agnostic: Attacks can be internal or external; actions dictate malice.
        """
        s = self.sanitize_incident(incident)

        inc_id = s.get("incident_id") or "UNKNOWN"
        title = s.get("title") or "Security Incident"
        narrative = s.get("narrative") or "No narrative provided."
        target_host = s.get("target_host") or "Target Host"
        total_risk = s.get("total_risk_score") or 50
        priority = s.get("priority") or "P2"
        rule_code = s.get("rule_code") or s.get("correlation_rule_id") or "ANOMALOUS_PROBE"
        src_ip = s.get("attacker_source_ip") or "Unknown"
        ev_count = s.get("event_count") or 1

        # Fetch actual chronological execution stages
        stages_log = s.get("stages_log") or self.fetch_incident_stages(inc_id)
        precedents = self.fetch_few_shot_precedents(limit=3)

        prompt = f"""You are a Principal Cyber Security SOC Analyst L3. Analyze the following security incident strictly based on its FORENSIC EXECUTION LOG and ACTION EVIDENCE.

INCIDENT TELEMETRY:
- Incident ID: {inc_id}
- Title: {title}
- Target Host: {target_host}
- Source Actor / IP: {src_ip}
- Correlation Rule: {rule_code}
- Priority & Risk Score: {priority} (Total Risk Score: {total_risk}/100)
- Event Volume: {ev_count} raw alert event(s)

CHRONOLOGICAL FORENSIC EXECUTION LOG (ACTION EVIDENCE):
{stages_log}

SUMMARY NARRATIVE:
{narrative}
{precedents}
CORE FORENSIC PRINCIPLES (EVIDENCE & ACTION FIRST):
1. EVALUATE WHAT WAS ACTUALLY DONE:
   - A true threat exhibits an active progression of malicious actions: e.g., Initial Access -> Privilege Escalation (sudo execution) -> Persistence (crontab/service modification), OR Obfuscated Execution (encoded commands) with Tool Ingress.
2. ISOLATED SPIKES & ROUTINE PROBES (BENIGN):
   - If the chronological log shows only an isolated event or routine authentication failure without any privilege escalation, persistence, or payload execution, it is OPERATIONAL NOISE (BENIGN). Do NOT assume a compromise occurred unless malicious actions are present in the log.
3. ATTACKER ORIGIN AGNOSTIC:
   - Compromises can originate from internal nodes (insider/lateral movement) or public internet. Do not dismiss an action because it is internal, and do not panic solely because an internal host connected to another host without malicious commands. Focus on what was executed.

OUTPUT FORMAT: Respond STRICTLY in valid JSON matching this exact schema:
{{
  "verdict": "BENIGN" or "THREAT",
  "confidence": <float between 0.0 and 100.0>,
  "mitre_technique": "<technique ID or list>",
  "reasoning": "<forensic explanation based on log evidence>",
  "recommended_action": "AUTO_CLOSE" or "FORWARD_TO_TRIAGE"
}}"""
        return prompt

    def evaluate_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate an incident via Google Gemini REST API and apply Tier-3 decision logic.
        """
        inc_id = incident.get("incident_id") or "UNKNOWN"
        t0 = time.time()

        if not self.api_key:
            return {
                "incident_id": inc_id,
                "model_tier": "Cloud LLM (Gemini)",
                "model_name": self.model,
                "verdict": "UNCERTAIN",
                "confidence": 0.0,
                "decision": "REQUIRE_GROUND_TRUTH",
                "recommended_action": "REQUIRE_GROUND_TRUTH",
                "reasoning": "Gemini API Key is not configured. Escalated for human ground truth.",
                "mitre_technique": "NONE",
                "execution_time_seconds": 0.0,
                "status": "ERROR_NO_API_KEY",
            }

        prompt = self.build_prompt(incident)
        url = f"{self.endpoint_url}?key={self.api_key}"

        payload = {
            "contents": [
                {
                    "parts": [{"text": prompt}]
                }
            ],
            "generationConfig": {
                "response_mime_type": "application/json",
                "temperature": 0.1,
                "maxOutputTokens": 2048,
            },
        }

        models_to_try = [self.model]
        last_error = None

        for current_model in models_to_try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{current_model}:generateContent?key={self.api_key}"
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )

            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    raw_data = json.loads(resp.read().decode("utf-8"))
                    elapsed = time.time() - t0

                    # Extract response text
                    candidates = raw_data.get("candidates", [])
                    if not candidates:
                        raise ValueError("No candidates returned from Gemini API.")
                    content_parts = candidates[0].get("content", {}).get("parts", [])
                    resp_text = content_parts[0].get("text", "").strip()

                    # Parse JSON
                    parsed = json.loads(resp_text)
                    verdict_raw = str(parsed.get("verdict", "UNCERTAIN")).strip().upper()
                    verdict = "THREAT" if "THREAT" in verdict_raw else "BENIGN"
                    conf = float(parsed.get("confidence", 50.0))
                    conf = max(0.0, min(100.0, round(conf, 2)))
                    reasoning = parsed.get("reasoning", "Evaluated by Google Gemini Cloud LLM.")
                    mitre_tech = parsed.get("mitre_technique", "NONE")

                    # Cascading Decision Logic:
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
                        "model_tier": "Cloud LLM (Gemini)",
                        "model_name": current_model,
                        "verdict": verdict,
                        "confidence": conf,
                        "decision": decision,
                        "recommended_action": rec_action,
                        "reasoning": f"Gemini ({current_model}): {reasoning}",
                        "mitre_technique": mitre_tech,
                        "execution_time_seconds": round(elapsed, 2),
                        "status": "SUCCESS",
                    }

                    self._persist_evaluation(inc_id, result)
                    return result

            except Exception as e:
                last_error = e
                logger.warning(f"[CloudLLM] Model {current_model} failed ({e}). Trying fallback...")
                continue

        logger.error(f"[CloudLLM] All Gemini models failed for {inc_id}: {last_error}")
        return {
            "incident_id": inc_id,
            "model_tier": "Cloud LLM (Gemini)",
            "model_name": self.model,
            "verdict": "UNCERTAIN",
            "confidence": 0.0,
            "decision": "REQUIRE_GROUND_TRUTH",
            "recommended_action": "REQUIRE_GROUND_TRUTH",
            "reasoning": f"Gemini evaluation failed ({last_error}). Escalated for human ground truth.",
            "mitre_technique": "NONE",
            "execution_time_seconds": round(time.time() - t0, 2),
            "status": "ERROR",
        }

    def _persist_evaluation(self, incident_id: str, eval_result: Dict[str, Any]) -> None:
        """Save Cloud LLM verdict and confidence into PostgreSQL ground_truth_dataset."""
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

            db_verdict = "TRUE_POSITIVE" if eval_result["verdict"] == "THREAT" else "FALSE_POSITIVE"
            conf = eval_result["confidence"]
            notes = eval_result["reasoning"]

            cur.execute(
                """
                UPDATE soc_ops.ground_truth_dataset
                SET cloud_llm_verdict = %s,
                    cloud_llm_confidence = %s,
                    analyst_notes = COALESCE(analyst_notes || ' | ', '') || %s
                WHERE incident_id = %s;
                """,
                (db_verdict, conf, notes, incident_id),
            )
            conn.commit()
            cur.close()
            conn.close()
            logger.info(f"[CloudLLM] Persisted Gemini evaluation for {incident_id}: {db_verdict} ({conf}%)")
        except Exception as e:
            logger.warning(f"[CloudLLM] Could not persist evaluation to DB for {incident_id}: {e}")
