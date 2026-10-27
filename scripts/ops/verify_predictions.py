import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pandas as pd
from pipeline.ml_classifier import get_classifier

clf = get_classifier()

test_cases = [
    {"title": "[P2] SQL injection attempt on web-prod-01 by 45.33.32.156", "priority": "P2", "threat_intel_match": 0, "source_ip": "45.33.32.156", "target_host": "web-prod-01"},
    {"title": "[P4] Web server 400 error code. on ELSA by 172.69.150.1", "priority": "P4", "threat_intel_match": 0, "source_ip": "172.69.150.1", "target_host": "ELSA"},
    {"title": "[P2] Terdeteksi Brute Force (SSH) on srv-01 by 194.26.29.112", "priority": "P2", "threat_intel_match": 0, "source_ip": "194.26.29.112", "target_host": "srv-01"},
    {"title": "[P0] Successful sudo to ROOT executed. on prod-db by user:dimas", "priority": "P0", "threat_intel_match": 0, "source_ip": "user:dimas", "target_host": "prod-db"},
    {"title": "[P0] PAM: Login session opened. on prod-app-01 by user:deploy", "priority": "P0", "threat_intel_match": 0, "source_ip": "user:deploy", "target_host": "prod-app-01"},
    {"title": "[P1] sshd: authentication success. on srv-web by 103.111.20.5", "priority": "P1", "threat_intel_match": 0, "source_ip": "103.111.20.5", "target_host": "srv-web"},
    {"title": "[P2] Multiple web server 400 error codes from same source ip. on web by 203.175.125.250", "priority": "P2", "threat_intel_match": 0, "source_ip": "203.175.125.250", "target_host": "web"},
    {"title": "[P4] Web server 400 error code. on web by 192.168.1.50", "priority": "P4", "threat_intel_match": 0, "source_ip": "192.168.1.50", "target_host": "web"},
]

print("=== CRITICAL CASES PREDICTION VERIFICATION ===")
for d in test_cases:
    d["rule_code"] = "CORR-ENTITY"
    d["stages_count"] = 1
    feats = clf.extract_features(d)
    df_f = pd.DataFrame([feats])
    for col in clf.FEATURE_CATEGORICAL:
        df_f[col] = df_f[col].fillna("UNKNOWN").astype(str)
    for col in clf.FEATURE_NUMERIC:
        df_f[col] = pd.to_numeric(df_f[col], errors="coerce").fillna(0)
    X_cat = clf.encoder.transform(df_f[clf.FEATURE_CATEGORICAL])
    X_num = df_f[clf.FEATURE_NUMERIC].values
    X = np.hstack([X_num, X_cat])
    probs = clf.calibrated_model.predict_proba(X)[0]
    pred = "THREAT" if probs[1] >= probs[0] else "BENIGN"
    conf = max(probs) * 100
    print(f"{d['title'][:55]:<55} -> {pred:<6} ({conf:.1f}%)")
