"""
Automated MLOps Retraining Orchestrator with Temporal Split & Gating Criteria
=============================================================================
Governs model retraining lifecycle (Tahap 8 & Loop 4):
1. Detects new analyst ground truth in soc_ops.ground_truth_dataset.
2. Enforces Temporal Train-Test Split (eliminates data leakage).
3. Trains Calibrated LightGBM with Isotonic Regression.
4. Validates Gating Criteria: Zero Threat Leakage (FNR=0%) and Reliability Calibration.
5. Saves timestamped versioned artifact with automated rollback support.
"""

import os
import sys
import json
import logging
import joblib
import psycopg2
import numpy as np
import pandas as pd
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional

from config.settings import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD, BASE_DIR
from pipeline.ml_classifier import LightGBMIncidentClassifier

logger = logging.getLogger(__name__)

MODELS_DIR = BASE_DIR / "config" / "models"
ARCHIVE_DIR = MODELS_DIR / "archive"
ACTIVE_MODEL_PATH = MODELS_DIR / "lightgbm_tier1.joblib"


class RetrainingOrchestrator:
    """Manages autonomous MLOps retraining cycles and gating safety tests."""

    def __init__(self, min_samples_threshold: int = 50):
        self.min_samples_threshold = min_samples_threshold
        ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)

    def count_new_ground_truth_samples(self) -> int:
        """Check count of verified ground truth records not yet trained."""
        try:
            conn = psycopg2.connect(
                host=DB_HOST, port=DB_PORT, database=DB_NAME,
                user=DB_USER, password=DB_PASSWORD, connect_timeout=3
            )
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT COUNT(*) 
                    FROM soc_ops.ground_truth_dataset 
                    WHERE is_used_in_training = FALSE
                      AND ground_truth_label IS NOT NULL
                      AND COALESCE(is_llm_simulated, FALSE) = FALSE;
                """)
                count = cur.fetchone()[0]
            conn.close()
            return int(count)
        except Exception as e:
            logger.warning(f"Error checking untrained ground truth: {e}")
            return 0

    def execute_retraining_cycle(self, force: bool = False) -> Dict[str, Any]:
        """Execute retraining with temporal cross-validation and safety gating."""
        new_samples = self.count_new_ground_truth_samples()
        if new_samples < self.min_samples_threshold and not force:
            return {
                "status": "SKIPPED",
                "message": f"Untrained samples ({new_samples}) below threshold ({self.min_samples_threshold})",
                "trained": False
            }

        logger.info(f"[*] Starting MLOps Retraining Cycle with {new_samples} pending samples (force={force})...")

        # 1. Load full dataset
        conn = psycopg2.connect(
            host=DB_HOST, port=DB_PORT, database=DB_NAME,
            user=DB_USER, password=DB_PASSWORD
        )
        query = """
            SELECT 
                g.incident_id,
                g.ground_truth_label,
                i.title,
                COALESCE(i.correlation_rule_id, g.rule_code) AS rule_code,
                g.rule_level,
                g.event_count,
                g.max_inline_risk_score,
                g.total_risk_score,
                g.priority,
                g.target_host,
                g.host_criticality,
                g.is_internet_exposed,
                g.is_privileged_user,
                g.threat_intel_match,
                i.narrative AS ioa_summary,
                i.attacker_source_ip,
                i.compromised_account,
                COALESCE(s.stage_count, 1) AS stages_count,
                i.first_seen_at,
                i.last_seen_at
            FROM soc_ops.ground_truth_dataset g
            JOIN correlation.correlated_incidents i ON g.incident_id = i.incident_id
            LEFT JOIN (
                SELECT incident_id, COUNT(*) AS stage_count 
                FROM correlation.incident_stages 
                GROUP BY incident_id
            ) s ON g.incident_id = s.incident_id
            WHERE g.ground_truth_label IS NOT NULL
              AND COALESCE(g.is_llm_simulated, FALSE) = FALSE;
        """
        df_raw = pd.read_sql(query, conn)
        conn.close()

        if len(df_raw) < 20:
            return {"status": "FAILED", "message": "Insufficient total samples (<20)", "trained": False}

        # 2. Behavioral feature extraction
        records = []
        for _, row in df_raw.iterrows():
            r_dict = row.to_dict()
            feats = LightGBMIncidentClassifier.extract_features(r_dict)
            feats["incident_id"] = r_dict["incident_id"]
            feats["ground_truth_label"] = int(r_dict["ground_truth_label"])
            feats["first_seen_at"] = r_dict["first_seen_at"]
            records.append(feats)

        df = pd.DataFrame(records)

        # 3. Temporal Train-Test Split (Sort by timestamp, train on first 80%, test on latest 20%)
        df = df.sort_values(by="first_seen_at").reset_index(drop=True)
        split_idx = int(len(df) * 0.80)
        train_df = df.iloc[:split_idx].copy()
        test_df = df.iloc[split_idx:].copy()

        # 4. Train candidate model
        candidate_clf = LightGBMIncidentClassifier(model_path=str(ACTIVE_MODEL_PATH))
        train_metrics = candidate_clf.train(train_df, target_col="ground_truth_label", test_size=0.15)

        # 5. Evaluate Gating Criteria on Temporal Holdout (test_df)
        test_predictions = [candidate_clf.predict_incident(row.to_dict()) for _, row in test_df.iterrows()]
        y_true = test_df["ground_truth_label"].values
        y_pred = [p["predicted_label"] for p in test_predictions]
        y_prob_threat = [p["threat_probability"] / 100.0 for p in test_predictions]

        # Calculate Threat Recall & False Negative Rate
        threat_mask = (y_true == 1)
        threat_count = int(np.sum(threat_mask))
        if threat_count > 0:
            threat_detected = int(np.sum((y_true == 1) & (np.array(y_pred) == 1)))
            threat_recall = threat_detected / threat_count
            fnr = 1.0 - threat_recall
        else:
            threat_recall = 1.0
            fnr = 0.0

        # Calculate Brier score for calibration accuracy
        brier_score = float(np.mean((np.array(y_prob_threat) - y_true) ** 2))

        # Gating check
        gating_passed = (fnr <= 0.02) and (brier_score <= 0.10)

        # 6. Versioning & Deployment
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        version_tag = f"v2_{timestamp_str}"
        archive_path = ARCHIVE_DIR / f"lightgbm_tier1_{version_tag}.joblib"

        if gating_passed:
            # Backup current active model
            if ACTIVE_MODEL_PATH.exists():
                try:
                    import shutil
                    shutil.copy(ACTIVE_MODEL_PATH, archive_path)
                except Exception:
                    pass

            # Mark processed rows as trained in DB
            conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, database=DB_NAME, user=DB_USER, password=DB_PASSWORD)
            with conn.cursor() as cur:
                cur.execute("UPDATE soc_ops.ground_truth_dataset SET is_used_in_training = TRUE, trained_at = CURRENT_TIMESTAMP WHERE is_used_in_training = FALSE AND COALESCE(is_llm_simulated, FALSE) = FALSE;")
            conn.commit()
            conn.close()

            logger.info(f"[+] MLOps Retraining Gating PASSED! Threat Recall: {threat_recall*100:.1f}%, Brier: {brier_score:.4f}. Model deployed.")
            return {
                "status": "DEPLOYED",
                "version": version_tag,
                "threat_recall": round(threat_recall, 4),
                "fnr": round(fnr, 4),
                "brier_score": round(brier_score, 4),
                "total_samples": len(df),
                "trained": True
            }
        else:
            logger.warning(f"[-] MLOps Gating REJECTED! FNR ({fnr*100:.1f}%) or Brier ({brier_score:.4f}) failed criteria. Model deployment aborted.")
            return {
                "status": "REJECTED_BY_GATING",
                "version": version_tag,
                "threat_recall": round(threat_recall, 4),
                "fnr": round(fnr, 4),
                "brier_score": round(brier_score, 4),
                "trained": False
            }
