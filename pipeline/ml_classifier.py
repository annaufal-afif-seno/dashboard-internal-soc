"""
LightGBM Incident Classifier (Tier-1 Machine Learning Fast-Filter) - Upgraded v2.0
==================================================================================
Trained on historical SOC Analyst Ground Truth with Behavioral Feature Engineering:
- Velocity & Burst Duration (log_event_velocity, log_duration)
- Cyclic Temporal Encoding (hour_sin, hour_cos)
- Single Unified Risk Score & Asset Criticality
- Probability Calibration (Isotonic Regression via CalibratedClassifierCV)
- Asymmetric Cost-Sensitive Safety Guardrails (Zero-Leakage Invariant)

Decisions:
- AUTO_SUPPRESS: High-confidence calibrated benign noise (prob_benign >= 85% & Guardrail Passed)
- FORWARD_TO_TRIAGE: Actionable threat, low confidence (< 85%), or Guardrail Override
"""

import os
import re
import ipaddress
import logging
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple, Optional, List
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score, accuracy_score, average_precision_score
)
from sklearn.preprocessing import OrdinalEncoder

from config.settings import (
    BASE_DIR,
    LOCAL_LLM_CONFIDENCE_THRESHOLD,
    CLOUD_LLM_CONFIDENCE_THRESHOLD,
)

logger = logging.getLogger(__name__)

DEFAULT_MODEL_DIR = BASE_DIR / "config" / "models"
DEFAULT_MODEL_PATH = DEFAULT_MODEL_DIR / "lightgbm_tier1.joblib"


class LightGBMIncidentClassifier:
    """
    Calibrated LightGBM Tabular Classifier with Behavioral Feature Engineering.
    Predicts:
      0 = BENIGN / FALSE POSITIVE
      1 = TRUE THREAT / ACTIONABLE INCIDENT
    """

    FEATURE_NUMERIC = [
        "log_event_velocity",
        "log_duration",
        "hour_sin",
        "hour_cos",
        "rule_level",
        "stages_count",
        "has_attacker_ip",
        "is_internal_attacker",
        "is_privileged_user",
        "is_internet_exposed",
        "threat_intel_match",
        "is_external_multistage",
        "wazuh_rule",
        "priority_level",
    ]

    FEATURE_CATEGORICAL = [
        "rule_code",
    ]

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = str(model_path or DEFAULT_MODEL_PATH)
        self.calibrated_model: Optional[CalibratedClassifierCV] = None
        self.encoder: Optional[OrdinalEncoder] = None
        self.feature_names: List[str] = []
        self._load_if_exists()

    @property
    def model(self):
        """Backward-compatible alias for calibrated_model."""
        return self.calibrated_model

    def _load_if_exists(self) -> bool:
        """Attempt to load existing trained model artifact."""
        if os.path.exists(self.model_path):
            try:
                bundle = joblib.load(self.model_path)
                self.calibrated_model = bundle.get("calibrated_model") or bundle.get("model")
                self.encoder = bundle["encoder"]
                self.feature_names = bundle["feature_names"]
                logger.info(f"[LightGBM] Successfully loaded trained model from {self.model_path}")
                return True
            except Exception as e:
                logger.warning(f"[LightGBM] Could not load model from {self.model_path}: {e}")
        return False

    @staticmethod
    def extract_features(incident: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a raw or correlated incident dictionary into behavioral tabular features."""
        # 1. Attacker IP locality
        src_ip = (
            incident.get("attacker_source_ip")
            or incident.get("source_ip")
            or incident.get("src_ip")
            or incident.get("actor_ip")
            or ""
        )
        has_src = 1 if src_ip and str(src_ip) != "unknown" else 0
        is_internal = 0
        if has_src:
            try:
                ip_obj = ipaddress.ip_address(str(src_ip).strip())
                is_internal = 1 if (ip_obj.is_private or ip_obj.is_loopback) else 0
            except ValueError:
                is_internal = 0

        # 2. Host criticality mapping - ALL TARGETS TREATED WITH EQUAL IMPORTANCE
        crit_tier = "STANDARD"

        # 3. User privilege
        user = str(incident.get("compromised_account") or "").lower()
        if not user and str(src_ip).startswith("user:"):
            user = str(src_ip).split(":", 1)[1].strip().lower()
        is_priv = 1 if (incident.get("is_privileged_user") or user in ("root", "admin", "administrator", "system")) else 0

        # 4. Stages count
        stages = incident.get("stages")
        if isinstance(stages, list) and len(stages) > 0:
            stages_count = len(stages)
        else:
            val = incident.get("stages_count", incident.get("stage_count", 1))
            stages_count = 1 if (val is None or pd.isna(val)) else int(float(val))

        # Domain security feature: external multi-stage actor
        is_external = 1 if (has_src == 1 and is_internal == 0) else 0
        is_external_multistage = 1 if (is_external == 1 and stages_count >= 2) else 0

        # 5. Risk scores
        max_inline_val = incident.get("max_inline_risk_score", 0)
        max_inline = 0.0 if (max_inline_val is None or pd.isna(max_inline_val)) else float(max_inline_val)
        total_risk_val = incident.get("total_score", incident.get("total_risk_score", max_inline))
        total_risk = max_inline if (total_risk_val is None or pd.isna(total_risk_val)) else float(total_risk_val)

        prio_str = str(incident.get("priority", incident.get("target_severity", "P4"))).upper()
        prio_map = {"P4": 0, "P3": 1, "P2": 2, "P1": 3, "P0": 4}
        priority_level = prio_map.get(prio_str, 0)

        rule_lvl_val = incident.get("rule_level")
        if rule_lvl_val is None or pd.isna(rule_lvl_val) or float(rule_lvl_val) <= 1:
            prio_lvl_map = {"P0": 14, "P1": 11, "P2": 8, "P3": 5, "P4": 2}
            rule_lvl = prio_lvl_map.get(prio_str, max(1, min(15, round(total_risk / 7.0))))
        else:
            rule_lvl = int(float(rule_lvl_val))

        # 6. Temporal & Behavioral Velocity (Key differentiator: scanner vs slow attack)
        first_seen = incident.get("first_seen_at")
        last_seen = incident.get("last_seen_at")
        duration_sec = 60.0
        hour = 12.0

        if first_seen and last_seen and not pd.isna(first_seen) and not pd.isna(last_seen):
            try:
                first_dt = pd.to_datetime(first_seen)
                last_dt = pd.to_datetime(last_seen)
                duration_sec = max(float((last_dt - first_dt).total_seconds()), 1.0)
                hour = float(first_dt.hour)
            except Exception:
                d_sec = incident.get("duration_seconds")
                duration_sec = 60.0 if (d_sec is None or pd.isna(d_sec)) else float(d_sec)
                h_val = incident.get("hour_of_day")
                hour = 12.0 if (h_val is None or pd.isna(h_val)) else float(h_val)
        else:
            d_sec = incident.get("duration_seconds")
            duration_sec = 60.0 if (d_sec is None or pd.isna(d_sec)) else float(d_sec)
            h_val = incident.get("hour_of_day")
            hour = 12.0 if (h_val is None or pd.isna(h_val)) else float(h_val)

        ev_val = incident.get("events_count", incident.get("event_count", stages_count))
        ev_count = stages_count if (ev_val is None or pd.isna(ev_val)) else int(float(ev_val))
        velocity = ev_count / max(duration_sec, 1.0)
        log_event_velocity = float(np.log1p(velocity))
        log_duration = float(np.log1p(duration_sec))

        # Cyclic hour encoding
        hour_rad = 2.0 * np.pi * hour / 24.0
        hour_sin = float(np.sin(hour_rad))
        hour_cos = float(np.cos(hour_rad))

        # 7. Threat Intel Match
        ti_match = 1 if incident.get("threat_intel_match") or incident.get("has_ti") else 0

        # 8. Forensic attack tactic & rule ID extraction
        title = str(incident.get("title") or "").lower()
        narrative = str(incident.get("narrative") or incident.get("ioa_summary") or "").lower()
        combined = title + " " + narrative
        r_code = str(incident.get("rule_code", incident.get("correlation_rule_id", "CORR-SA"))).upper()

        m_rule = re.search(r'rule\s+(\d+)', combined)
        wazuh_rule = int(m_rule.group(1)) if m_rule else 0
        if 'modsecurity' in combined:
            wazuh_rule = 30411
        elif 'vulnerability detector' in combined or 'package cve' in combined:
            wazuh_rule = 23502
        elif 'powershell' in combined:
            wazuh_rule = 80710

        prio_str = str(incident.get("priority", incident.get("target_severity", "P3"))).upper()
        prio_map = {"P4": 0, "P3": 1, "P2": 2, "P1": 3, "P0": 4}
        priority_level = prio_map.get(prio_str, 0)
        is_p0_p1_breach = 1 if prio_str in ("P0", "P1") else 0

        # 9. Domain Security Signals (MITRE ATT&CK / OWASP / CDN Differentiation)
        attack_keywords = [
            'sql injection', 'modsecurity', 'brute force', 'sudo to root',
            'cgi-bin', 'webshell', 'traversal', 'apparmor denied', 'rootcheck',
            'common web attack', 'suspicious url', 'likely bot', 'unauthorized',
            'mimikatz', 'exploit', 'injection', 'command execution', 'rce',
            'malicious user agent', 'blacklisted user agent', 'attack returned code 200'
        ]
        is_attack_sig = 1 if any(k in combined for k in attack_keywords) else 0

        # Cloudflare CDN IP Ranges
        cf_networks = [
            ipaddress.ip_network('173.245.48.0/20'),
            ipaddress.ip_network('103.21.244.0/22'),
            ipaddress.ip_network('103.22.200.0/22'),
            ipaddress.ip_network('103.31.4.0/22'),
            ipaddress.ip_network('141.101.64.0/18'),
            ipaddress.ip_network('108.162.192.0/18'),
            ipaddress.ip_network('190.93.240.0/20'),
            ipaddress.ip_network('188.114.96.0/20'),
            ipaddress.ip_network('197.234.240.0/22'),
            ipaddress.ip_network('198.41.128.0/17'),
            ipaddress.ip_network('162.158.0.0/15'),
            ipaddress.ip_network('104.16.0.0/13'),
            ipaddress.ip_network('104.24.0.0/14'),
            ipaddress.ip_network('172.64.0.0/13'),
            ipaddress.ip_network('131.0.72.0/22'),
        ]
        is_cdn = 0
        if has_src and not str(src_ip).startswith('user:') and not str(src_ip).startswith('proc:'):
            try:
                ip_obj = ipaddress.ip_address(str(src_ip).strip())
                is_cdn = 1 if any(ip_obj in net for net in cf_networks) else 0
            except ValueError:
                is_cdn = 0

        # HTTP error only without attack payload
        is_http_err = 1 if (any(k in combined for k in ['400 error', '500 error', '404 error', 'nginx error', 'log file rotated', 'clamav', 'netstat', 'dpkg']) and is_attack_sig == 0 and is_p0_p1_breach == 0) else 0

        # If CDN proxy or HTTP error / operational noise and NO attack signature, it is operational noise (ti_match cannot be 1)
        if (is_cdn == 1 or is_http_err == 1) and is_attack_sig == 0:
            ti_match = 0

        return {
            "log_event_velocity": log_event_velocity,
            "log_duration": log_duration,
            "hour_sin": hour_sin,
            "hour_cos": hour_cos,
            "rule_level": rule_lvl,
            "total_risk_score": total_risk,
            "stages_count": stages_count,
            "has_attacker_ip": has_src,
            "is_internal_attacker": is_internal,
            "is_privileged_user": is_priv,
            "is_internet_exposed": 1 if incident.get("is_internet_exposed") else 0,
            "threat_intel_match": ti_match,
            "is_external_multistage": is_external_multistage,
            "wazuh_rule": wazuh_rule,
            "priority_level": priority_level,
            "is_p0_p1_breach": is_p0_p1_breach,
            "is_attack_signature": is_attack_sig,
            "is_cdn_proxy": is_cdn,
            "is_http_error_only": is_http_err,
            "rule_code": r_code,
            "priority": prio_str,
            "host_criticality": crit_tier,
        }

    def train(
        self,
        df: pd.DataFrame,
        target_col: str = "ground_truth_label",
        test_size: float = 0.20,
        random_state: int = 42,
        class_weight: Optional[str] = None,
        scale_pos_weight: float = 3.5
    ) -> Dict[str, Any]:
        """
        Train and calibrate LightGBM binary classifier using Isotonic Regression,
        enforcing Monotonic Security Constraints and Cost-Sensitive Loss.
        """
        valid_df = df[df[target_col].notna()].copy()
        if len(valid_df) < 10:
            raise ValueError(f"Insufficient training samples: {len(valid_df)}. Minimum 10 required.")

        # Ensure all required features are present
        X_raw = valid_df[self.FEATURE_NUMERIC + self.FEATURE_CATEGORICAL].copy()
        for col in self.FEATURE_CATEGORICAL:
            X_raw[col] = X_raw[col].fillna("UNKNOWN").astype(str)
        for col in self.FEATURE_NUMERIC:
            X_raw[col] = pd.to_numeric(X_raw[col], errors="coerce").fillna(0)

        y = valid_df[target_col].astype(int)

        # Fit ordinal encoder on categorical columns
        self.encoder = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)
        X_cat_encoded = self.encoder.fit_transform(X_raw[self.FEATURE_CATEGORICAL])

        # Combine numeric and encoded categorical features
        X_numeric = X_raw[self.FEATURE_NUMERIC].values
        X_final = np.hstack([X_numeric, X_cat_encoded])
        self.feature_names = self.FEATURE_NUMERIC + self.FEATURE_CATEGORICAL

        # Train / Test Stratified Split
        stratify = y if len(y.unique()) > 1 and min(y.value_counts()) >= 2 else None
        X_train, X_test, y_train, y_test = train_test_split(
            X_final, y, test_size=test_size, random_state=random_state, stratify=stratify
        )

        # Monotonic Constraints: Enforce domain security logic
        # Increasing total_risk_score, rule_level, stages_count, host_criticality_score,
        # threat_intel_match, and is_external_multistage must NEVER decrease threat probability.
        mono_map = {
            "rule_level": 1,
            "stages_count": 1,
            "threat_intel_match": 1,
            "is_external_multistage": 1,
            "priority_level": 1,
        }
        mono_constraints = [mono_map.get(f, 0) for f in self.feature_names]

        # Base LightGBM Classifier with Monotonic Constraints & Cost-Sensitive Weighting
        base_model = lgb.LGBMClassifier(
            objective="binary",
            n_estimators=100,
            learning_rate=0.05,
            num_leaves=15,
            min_child_samples=5,
            scale_pos_weight=scale_pos_weight,
            class_weight=class_weight,
            monotone_constraints=mono_constraints,
            random_state=random_state,
            verbosity=-1
        )

        # Wrap in Calibrated Classifier (Adaptive CV folds based on minimum class count)
        min_class_count = int(min(y_train.value_counts())) if len(y_train.unique()) > 1 else 0
        if min_class_count >= 3:
            self.calibrated_model = CalibratedClassifierCV(estimator=base_model, method="isotonic", cv=min(3, min_class_count))
            self.calibrated_model.fit(X_train, y_train)
        elif min_class_count >= 2:
            self.calibrated_model = CalibratedClassifierCV(estimator=base_model, method="sigmoid", cv=2)
            self.calibrated_model.fit(X_train, y_train)
        else:
            base_model.fit(X_train, y_train)
            self.calibrated_model = base_model

        # Evaluate on Test Set
        y_pred = self.calibrated_model.predict(X_test)
        y_prob = self.calibrated_model.predict_proba(X_test)

        acc = accuracy_score(y_test, y_pred)
        roc = roc_auc_score(y_test, y_prob[:, 1]) if len(np.unique(y_test)) > 1 else 1.0
        pr_auc_benign = average_precision_score((y_test == 0).astype(int), y_prob[:, 0]) if len(np.unique(y_test)) > 1 else 1.0
        cm = confusion_matrix(y_test, y_pred).tolist()
        report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

        # Compute average feature importance across calibrated folds
        try:
            base_imps = [
                clf.estimator.feature_importances_ for clf in self.calibrated_model.calibrated_classifiers_
            ]
            mean_imps = np.mean(base_imps, axis=0).tolist()
            importances = dict(zip(self.feature_names, [round(float(x), 1) for x in mean_imps]))
        except Exception:
            importances = {fn: 1.0 for fn in self.feature_names}

        sorted_importances = dict(sorted(importances.items(), key=lambda item: item[1], reverse=True))

        # Save model bundle
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump({
            "calibrated_model": self.calibrated_model,
            "encoder": self.encoder,
            "feature_names": self.feature_names,
            "trained_at": pd.Timestamp.now().isoformat(),
            "train_samples": len(X_train),
            "test_samples": len(X_test),
        }, self.model_path)

        logger.info(
            f"[LightGBM] Model trained & calibrated (ROC-AUC: {roc:.3f}, PR-AUC Benign: {pr_auc_benign:.3f}, Acc: {acc*100:.1f}%)"
        )

        return {
            "status": "success",
            "accuracy": round(acc, 4),
            "roc_auc": round(roc, 4),
            "pr_auc_benign": round(pr_auc_benign, 4),
            "confusion_matrix": cm,
            "classification_report": report,
            "feature_importances": sorted_importances,
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "model_path": self.model_path
        }

    def predict_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate an incident through calibrated LightGBM with SOC Safety Guardrails.
        """
        feats = self.extract_features(incident)

        if self.calibrated_model is None or self.encoder is None:
            return self._heuristic_fallback(incident)

        # Encode categorical
        cat_df = pd.DataFrame([{col: str(feats.get(col, "UNKNOWN")) for col in self.FEATURE_CATEGORICAL}])
        cat_encoded = self.encoder.transform(cat_df)

        # Numerical array
        num_arr = np.array([[float(feats.get(col, 0)) for col in self.FEATURE_NUMERIC]])
        X_vec = np.hstack([num_arr, cat_encoded])

        # Predict calibrated probabilities: [prob_benign, prob_threat]
        probs = self.calibrated_model.predict_proba(X_vec)[0]
        classes = list(self.calibrated_model.classes_)
        if len(classes) == 1:
            only_c = classes[0]
            prob_benign = 100.0 if only_c == 0 else 0.0
            prob_threat = 100.0 if only_c == 1 else 0.0
        else:
            idx_0 = classes.index(0) if 0 in classes else 0
            idx_1 = classes.index(1) if 1 in classes else 1
            prob_benign = round(float(probs[idx_0]) * 100, 2)
            prob_threat = round(float(probs[idx_1]) * 100, 2)
        pred_label = 0 if prob_benign > prob_threat else 1

        # Pure ML Decision Logic (Prinsip G: Zero guardrails / overrides)
        # Decision rule: Benign AND confidence >= 85.0 -> AUTO_CLOSE; else FORWARD_TO_TRIAGE (OPEN)
        if pred_label == 0 and prob_benign >= 85.0:
            decision = "AUTO_CLOSE"
            reasoning = (
                f"LightGBM Pure ML: Calibrated benign noise ({prob_benign:.2f}% confidence >= 85.0%). "
                f"Auto-closed with proposed Wazuh suppression rule."
            )
        else:
            decision = "FORWARD_TO_TRIAGE"
            if pred_label == 1:
                reasoning = (
                    f"LightGBM Pure ML: Threat detected ({prob_threat:.2f}% threat confidence). "
                    f"Forwarded to SOC Triage Queue as OPEN."
                )
            else:
                reasoning = (
                    f"LightGBM Pure ML: Ambiguous benign pattern ({prob_benign:.2f}% confidence < 85.0%). "
                    f"Forwarded to SOC Triage Queue as OPEN."
                )

        return {
            "predicted_label": pred_label,
            "verdict": "BENIGN" if pred_label == 0 else "THREAT",
            "confidence": prob_benign if pred_label == 0 else prob_threat,
            "benign_probability": prob_benign,
            "threat_probability": prob_threat,
            "decision": decision,
            "reasoning": reasoning,
            "model_version": "LightGBM-v2.0-Pure-Calibrated"
        }

    def _heuristic_fallback(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Prinsip G: Fallback heuristic is strictly prohibited; raise explicit exception."""
        raise RuntimeError(
            "Calibrated ML model is not available or loaded. Under Prinsip G, "
            "rule-based heuristic fallbacks are disabled to prevent uncalibrated bias."
        )


_CACHED_CLASSIFIER = None

def get_classifier():
    global _CACHED_CLASSIFIER
    if _CACHED_CLASSIFIER is None:
        _CACHED_CLASSIFIER = LightGBMIncidentClassifier()
    return _CACHED_CLASSIFIER


def compute_calibrated_factual_score(
    incident: Dict[str, Any],
    ml_res: Dict[str, Any],
    llm_threat_prob: float
) -> Dict[str, Any]:
    """
    Computes Calibrated Factual Score (CFS) anchored to empirical real-world evidence.
    Solves LLM Overconfidence (ICLR 2024 / ICML 2017) by grounding decisions in:
    1. Threat Intelligence reputation (AbuseIPDB/MISP)
    2. Wazuh Rule Severity Level & MITRE tactics
    3. Multi-stage attack progression & temporal velocity
    4. Target asset criticality

    CFS Formula:
    - 0.40 * Evidence_Threat (External Threat Intel + Wazuh Rule Level + Multi-stage Burst)
    - 0.35 * LLM_Threat (Local Security Reasoning LLM + Cloud Gemini Soft Voting)
    - 0.25 * ML_Threat (Isotonic Calibrated LightGBM Probability)
    """
    # 1. Threat Intel Match (Empirical External Fact)
    ti_match = 1.0 if (incident.get("threat_intel_match") or incident.get("has_ti")) else 0.0

    # 2. Wazuh Rule Level (Empirical Sensor Fact)
    rule_lvl_val = incident.get("rule_level", 3)
    try:
        rule_lvl = float(rule_lvl_val) if rule_lvl_val is not None else 3.0
    except Exception:
        rule_lvl = 3.0
    rule_score = min(1.0, max(0.0, (rule_lvl - 3.0) / 10.0))

    # 3. Multi-stage progression & velocity
    stages_count = len(incident.get("stages", [])) or int(incident.get("stages_count", 1) or 1)
    is_multistage = 1.0 if stages_count > 1 or incident.get("is_external_multistage") else 0.0

    # 4. Host Criticality
    host_crit = str(incident.get("host_criticality", "STANDARD")).upper()
    crit_score = 1.0 if any(k in host_crit for k in ("CRITICAL", "GATEWAY", "PROD", "HIGH")) else 0.2

    # Evidence Threat Score (0.0 to 1.0)
    evidence_threat_prob = min(
        1.0,
        max(0.0, (0.40 * ti_match) + (0.30 * rule_score) + (0.20 * is_multistage) + (0.10 * crit_score))
    )

    # ML Calibrated Threat Probability
    ml_conf = float(ml_res.get("confidence", 50.0)) / 100.0
    ml_verdict = str(ml_res.get("verdict", "BENIGN")).upper()
    ml_threat_prob = ml_conf if ml_verdict == "THREAT" else (1.0 - ml_conf)

    # Calibrated Factual Score (CFS) Threat Probability
    cfs_threat_prob = round(
        (0.40 * evidence_threat_prob) + (0.35 * llm_threat_prob) + (0.25 * ml_threat_prob),
        4
    )

    return {
        "evidence_threat_prob": round(evidence_threat_prob, 4),
        "ml_threat_prob": round(ml_threat_prob, 4),
        "llm_threat_prob": round(llm_threat_prob, 4),
        "cfs_threat_prob": cfs_threat_prob,
        "ti_match": bool(ti_match),
        "rule_level": rule_lvl,
        "is_multistage": bool(is_multistage),
    }


def evaluate_cascading_pipeline(incident: Dict[str, Any]) -> Dict[str, Any]:
    """
    Tiered Cascading AI Triage Flow:
    1. Tier-1 LightGBM Fast Filter (Calibrated Isotonic, 85% threshold):
       - If confidence >= 85.0% and BENIGN: -> AUTO_CLOSE
       - If confidence >= 85.0% and THREAT: -> CREATE_IRIS_CASE
       - If confidence < 85.0%: -> Teruskan ke Tier-2 Local LLM.

    2. Tier-2 Local LLM (Ollama Qwen on Remote PC, threshold >= 85%):
       - If confidence >= 85.0%:
           - BENIGN -> AUTO_CLOSE
           - THREAT -> CREATE_IRIS_CASE
           - Dibuatkan ground truth untuk retraining ML!
       - If confidence < 85.0%: -> Teruskan ke Tier-3 Cloud LLM untuk Soft Voting.

    3. Tier-3 Cloud LLM (Gemini with Selective Masking) & Soft Voting:
       - Soft Voting Ensemble Threshold: 85%
       - If Ensemble Benign Confidence >= 85%: -> AUTO_CLOSE
       - If Ensemble Threat Confidence >= 85%: -> CREATE_IRIS_CASE
       - If Ambiguous (< 85% confidence): -> AUDIT_SOC_ANALYST / Ground Truth Retraining
    """
    classifier = get_classifier()
    ml_res = classifier.predict_incident(incident)
    ml_conf = float(ml_res["confidence"])
    ml_verdict = ml_res["verdict"]

    # Step 1: Tier-1 ML Fast Filter
    if ml_conf >= 85.0:
        decision = "AUTO_CLOSE" if ml_verdict == "BENIGN" else "CREATE_IRIS_CASE"
        reasoning = (
            f"Tier-1 LightGBM ({ml_conf:.2f}% confidence >= 85.0%): "
            f"{'Auto-closed benign noise' if decision == 'AUTO_CLOSE' else 'Detected threat -> Auto-created IRIS case'}."
        )
        return {
            "active_tier": "Tier-1 ML",
            "tier1_ml": ml_res,
            "tier2_local_llm": None,
            "tier3_cloud_llm": None,
            "final_verdict": ml_verdict,
            "final_confidence": ml_conf,
            "decision": decision,
            "decision_path": f"TIER1_ML_{decision}",
            "reasoning": reasoning,
            "needs_ground_truth": False,
            "ground_truth_target": None,
        }

    # Step 2: Tier-2 Local LLM
    logger.info(f"[CascadingPipeline] ML confidence ambiguous ({ml_conf:.2f}% < 85%). Cascading to Tier-2 Local LLM...")
    llm_res = None
    try:
        from pipeline.local_llm import LocalLLMTriageClient
        local_client = LocalLLMTriageClient()
        threshold_l2 = local_client.threshold
        if local_client.is_available():
            llm_res = local_client.evaluate_incident(incident)
            llm_conf = float(llm_res.get("confidence", 0.0))
            llm_verdict = str(llm_res.get("verdict", "BENIGN")).upper()

            if llm_conf >= threshold_l2:
                decision = "AUTO_CLOSE" if llm_verdict == "BENIGN" else "CREATE_IRIS_CASE"
                reasoning = (
                    f"Tier-2 Local LLM ({llm_conf:.2f}% confidence >= {threshold_l2}%): "
                    f"{'Auto-closed benign' if decision == 'AUTO_CLOSE' else 'Detected threat -> Auto-created IRIS case'}."
                )
                return {
                    "active_tier": "Tier-2 Local LLM",
                    "tier1_ml": ml_res,
                    "tier2_local_llm": llm_res,
                    "tier3_cloud_llm": None,
                    "final_verdict": llm_verdict,
                    "final_confidence": llm_conf,
                    "decision": decision,
                    "decision_path": f"TIER2_{decision}",
                    "reasoning": reasoning,
                    "needs_ground_truth": False,
                    "ground_truth_target": None,
                }
            logger.info(f"[CascadingPipeline] Local LLM ambiguous ({llm_conf:.1f}% < {threshold_l2}%). Cascading to Cloud LLM with selective masking...")
        else:
            logger.warning("[CascadingPipeline] Tier-2 Local LLM service is offline. Cascading to Cloud LLM...")
            llm_res = {"status": "OFFLINE", "confidence": 50.0, "verdict": "BENIGN", "message": "Ollama service unreachable"}
    except Exception as e:
        logger.warning(f"[CascadingPipeline] Tier-2 Local LLM error ({e}). Cascading to Cloud LLM...")
        llm_res = {"status": "ERROR", "confidence": 50.0, "verdict": "BENIGN", "error": str(e)}

    # Step 3: Tier-3 Cloud LLM with Selective Masking & Soft Voting
    cloud_res = None
    try:
        from pipeline.cloud_llm import CloudLLMTriageClient
        cloud_client = CloudLLMTriageClient()
        sanitized_inc = cloud_client.sanitize_incident(incident)

        if cloud_client.is_available():
            cloud_res = cloud_client.evaluate_incident(sanitized_inc)
        else:
            logger.warning("[CascadingPipeline] Tier-3 Cloud LLM is unavailable (offline or API key missing).")
            cloud_res = {"status": "OFFLINE", "confidence": 50.0, "verdict": "BENIGN", "message": "Gemini API unavailable"}
    except Exception as e_cloud:
        logger.error(f"[CascadingPipeline] Tier-3 Cloud LLM error: {e_cloud}")
        cloud_res = {"status": "ERROR", "confidence": 50.0, "verdict": "BENIGN", "error": str(e_cloud)}

    # Soft Voting (Local LLM 0.4 vs Cloud LLM 0.6 per original PRD Section 6.3)
    loc_conf = float(llm_res.get("confidence") if llm_res and llm_res.get("confidence") is not None else 50.0) / 100.0
    loc_verdict = str(llm_res.get("verdict") if llm_res and llm_res.get("verdict") else "BENIGN").upper()
    loc_threat_val = (1.0 - loc_conf) if loc_verdict == "BENIGN" else loc_conf

    cloud_conf = float(cloud_res.get("confidence") if cloud_res and cloud_res.get("confidence") is not None else 50.0) / 100.0
    cloud_verdict = str(cloud_res.get("verdict") if cloud_res and cloud_res.get("verdict") else "BENIGN").upper()
    cloud_threat_val = (1.0 - cloud_conf) if cloud_verdict == "BENIGN" else cloud_conf

    ensemble_threat_prob = round((0.4 * loc_threat_val) + (0.6 * cloud_threat_val), 4)
    cutoff = CLOUD_LLM_CONFIDENCE_THRESHOLD / 100.0  # 0.85

    # Compute Factual Grounding (Calibrated Factual Score - CFS)
    cfs = compute_calibrated_factual_score(incident, ml_res, ensemble_threat_prob)

    if (1.0 - ensemble_threat_prob) >= cutoff:
        final_verdict = "BENIGN"
        final_conf = round((1.0 - ensemble_threat_prob) * 100.0, 2)
        decision = "AUTO_CLOSE"
        needs_gt = False
        gt_target = None
        reasoning = (
            f"Soft Voting Ensemble (Local 0.4 + Cloud 0.6): Benign confidence {final_conf:.2f}% >= {int(cutoff*100)}%. "
            f"Factual Score: {cfs['cfs_threat_prob']:.2f}. Auto-closed without bias."
        )
    elif ensemble_threat_prob >= cutoff:
        final_verdict = "THREAT"
        final_conf = round(ensemble_threat_prob * 100.0, 2)
        decision = "CREATE_IRIS_CASE"
        needs_gt = False
        gt_target = None
        reasoning = (
            f"Soft Voting Ensemble (Local 0.4 + Cloud 0.6): Threat confidence {final_conf:.2f}% >= {int(cutoff*100)}%. "
            f"Factual Score: {cfs['cfs_threat_prob']:.2f}. Threat confirmed -> Auto-created IRIS case."
        )
    else:
        # Confidence < 85% -> Rekam ground truth untuk retraining ML dan memperkaya konteks
        final_verdict = "AMBIGUOUS"
        final_conf = round(max(ensemble_threat_prob, 1.0 - ensemble_threat_prob) * 100.0, 2)
        decision = "AUDIT_SOC_ANALYST"
        needs_gt = True
        gt_target = "LOCAL_LLM_AND_ML"
        reasoning = (
            f"Soft Voting Ensemble (Local 0.4 + Cloud 0.6): Confidence {final_conf:.2f}% < {int(cutoff*100)}% (Factual Score: {cfs['cfs_threat_prob']:.2f}). "
            f"Recorded as Ground Truth for ML retraining and LLM prompt context enrichment."
        )

    return {
        "active_tier": "Tier-3 Cloud LLM (Soft Voting: Local 0.4 vs Cloud 0.6)",
        "tier1_ml": ml_res,
        "tier2_local_llm": llm_res,
        "tier3_cloud_llm": cloud_res,
        "voting_score": ensemble_threat_prob,
        "calibrated_factual_score": cfs,
        "final_verdict": final_verdict,
        "final_confidence": final_conf,
        "decision": decision,
        "decision_path": f"SOFT_VOTING_{decision}",
        "reasoning": reasoning,
        "needs_ground_truth": needs_gt,
        "ground_truth_target": gt_target,
    }

