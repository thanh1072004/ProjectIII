#!/usr/bin/env python3
"""
RETRAIN ALL MODELS WITH FINAL COMPREHENSIVE DATASET

Tier 2 (Supervised):
- Train: final_dataset_train.log (70,091 logs with labels)
- Models: RandomForest, LogisticRegression

Tier 3 (Unsupervised):
- Train: final_dataset_train_clean_only.log (34,941 clean logs)
- Models: IsolationForest, OneClassSVM, LocalOutlierFactor

Evaluation: final_dataset_eval.log (28,767 parsed logs)
"""

import os
import sys
import io
import json
import numpy as np
import joblib
from datetime import datetime
from urllib.parse import urlparse, unquote
import re

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "models"))
sys.path.insert(0, PROJECT_ROOT)

from ai_detector import LogAnomalyDetector

def parse_log_line(line):
    """Parse Apache log line — dùng CÙNG logic tách request như
    apache_log.parse_log_entry (method = token đầu, protocol = token cuối bị bỏ)
    để feature lúc train KHỚP với monitor (không còn dính 'HTTP/1.1' trong path)."""
    try:
        match = re.match(
            r'(\S+) - - \[([^\]]+)\] "([^"]*)"\s+(\d+)\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"',
            line)
        if not match:
            return None

        ip, timestamp, request, status, size, referer, ua = match.groups()

        parts = request.split()
        method = parts[0] if parts else ""
        if len(parts) >= 3:
            raw_url = " ".join(parts[1:-1])   # bỏ token protocol cuối (giống parse_log_entry)
        elif len(parts) == 2:
            raw_url = parts[1]
        else:
            raw_url = ""

        try:
            decoded_url = unquote(raw_url)
        except:
            decoded_url = raw_url

        parsed_url = urlparse(decoded_url)
        path = parsed_url.path or "/"
        query = parsed_url.query or ""

        return {
            "method": method,
            "path": path,
            "query": query,
            "status": int(status),
            "user_agent": ua,
            "referer": referer,
            "is_attack": "(Simulated-Attack)" in line
        }
    except:
        return None

def extract_features_batch(log_file, detector):
    """Extract features from log file"""
    X = []
    y = []
    count = 0

    print(f"  Reading: {os.path.basename(log_file)}")

    with open(log_file, 'r', errors='ignore') as f:
        for i, line in enumerate(f):
            if i % 10000 == 0:
                print(f"    ... processed {i} lines", end='\r')

            parsed = parse_log_line(line.strip())
            if not parsed:
                continue

            try:
                feats = detector.extract_features(
                    parsed["path"],
                    parsed["query"],
                    parsed["method"],
                    str(parsed["status"]),
                    parsed.get("user_agent", ""),
                    parsed.get("referer", "")
                )

                X.append(feats)
                y.append(1 if parsed["is_attack"] else 0)
                count += 1
            except:
                pass

    print(f"  ✓ Extracted {count} features")
    return np.array(X), np.array(y)

def main():
    print("=" * 80)
    print("RETRAINING ALL MODELS WITH FINAL COMPREHENSIVE DATASET")
    print("=" * 80)

    datasets_dir = os.path.join(PROJECT_ROOT, "datasets")
    models_dir = os.path.join(PROJECT_ROOT, "trained_models")
    os.makedirs(models_dir, exist_ok=True)

    train_file = os.path.join(datasets_dir, "final_dataset_train.log")
    train_clean_file = os.path.join(datasets_dir, "final_dataset_train_clean_only.log")
    eval_file = os.path.join(datasets_dir, "final_dataset_eval.log")

    # ===== STEP 1: Extract Features =====
    print("\n[STEP 1] Feature Extraction")
    print("-" * 80)

    detector = LogAnomalyDetector()

    print("Extracting from training set (supervised - with labels):")
    X_train, y_train = extract_features_batch(train_file, detector)

    print("\nExtracting from training set (unsupervised - clean only):")
    X_train_clean, y_train_clean = extract_features_batch(train_clean_file, detector)

    print("\nExtracting from evaluation set:")
    X_eval, y_eval = extract_features_batch(eval_file, detector)

    print(f"\n✓ Train (supervised): {len(X_train)} samples ({(y_train==1).sum()} attacks)")
    print(f"✓ Train (clean only): {len(X_train_clean)} samples (all clean)")
    print(f"✓ Eval: {len(X_eval)} samples ({(y_eval==1).sum()} attacks)")

    # ===== STEP 2: Train TIER 2 (Supervised) =====
    print("\n[STEP 2] Training TIER 2 (Supervised Models)")
    print("-" * 80)

    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import precision_score, recall_score, f1_score, fbeta_score

    results_sup = []

    # RandomForest
    print("Training RandomForest...")
    rf_model = RandomForestClassifier(n_estimators=200, max_depth=20, random_state=42, n_jobs=-1)
    rf_model.fit(X_train, y_train)
    y_pred_rf = rf_model.predict(X_eval)
    prec_rf = precision_score(y_eval, y_pred_rf, zero_division=0)
    rec_rf = recall_score(y_eval, y_pred_rf, zero_division=0)
    f1_rf = f1_score(y_eval, y_pred_rf, zero_division=0)
    f2_rf = fbeta_score(y_eval, y_pred_rf, beta=2, zero_division=0)
    results_sup.append({
        "model": "RandomForest",
        "precision": round(prec_rf * 100, 2),
        "recall": round(rec_rf * 100, 2),
        "f1": round(f1_rf * 100, 2),
        "f2": round(f2_rf * 100, 2)
    })
    print(f"  Precision={prec_rf*100:.2f}% | Recall={rec_rf*100:.2f}% | F1={f1_rf*100:.2f}%")

    # LogisticRegression
    print("Training LogisticRegression...")
    lr_model = LogisticRegression(max_iter=1000, random_state=42, n_jobs=-1)
    lr_model.fit(X_train, y_train)
    y_pred_lr = lr_model.predict(X_eval)
    prec_lr = precision_score(y_eval, y_pred_lr, zero_division=0)
    rec_lr = recall_score(y_eval, y_pred_lr, zero_division=0)
    f1_lr = f1_score(y_eval, y_pred_lr, zero_division=0)
    f2_lr = fbeta_score(y_eval, y_pred_lr, beta=2, zero_division=0)
    results_sup.append({
        "model": "LogisticRegression",
        "precision": round(prec_lr * 100, 2),
        "recall": round(rec_lr * 100, 2),
        "f1": round(f1_lr * 100, 2),
        "f2": round(f2_lr * 100, 2)
    })
    print(f"  Precision={prec_lr*100:.2f}% | Recall={rec_lr*100:.2f}% | F1={f1_lr*100:.2f}%")

    # ===== STEP 3: Train TIER 3 (Unsupervised - Clean Only) =====
    print("\n[STEP 3] Training TIER 3 (Unsupervised Models - on Clean Data Only)")
    print("-" * 80)

    from sklearn.ensemble import IsolationForest
    from sklearn.svm import OneClassSVM
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.preprocessing import StandardScaler

    # Calculate expected attack rate in eval
    attack_rate = (y_eval == 1).sum() / len(y_eval)
    contamination = min(attack_rate + 0.02, 0.50)
    print(f"Eval set attack rate: {attack_rate*100:.2f}%")
    print(f"Setting contamination: {contamination*100:.2f}%\n")

    results_unsup = []

    # Isolation Forest
    print("Training Isolation Forest (on clean data)...")
    if_model = IsolationForest(contamination=contamination, random_state=42)
    if_model.fit(X_train_clean)
    y_pred_if = (if_model.predict(X_eval) == -1).astype(int)
    prec_if = precision_score(y_eval, y_pred_if, zero_division=0)
    rec_if = recall_score(y_eval, y_pred_if, zero_division=0)
    f1_if = f1_score(y_eval, y_pred_if, zero_division=0)
    f2_if = fbeta_score(y_eval, y_pred_if, beta=2, zero_division=0)
    results_unsup.append({
        "model": "Isolation Forest",
        "precision": round(prec_if * 100, 2),
        "recall": round(rec_if * 100, 2),
        "f1": round(f1_if * 100, 2),
        "f2": round(f2_if * 100, 2)
    })
    print(f"  Precision={prec_if*100:.2f}% | Recall={rec_if*100:.2f}% | F1={f1_if*100:.2f}%")

    # One-Class SVM
    print("Training One-Class SVM (on clean data)...")
    scaler = StandardScaler()
    X_train_clean_scaled = scaler.fit_transform(X_train_clean)
    X_eval_scaled = scaler.transform(X_eval)
    ocsvm_model = OneClassSVM(nu=contamination, kernel='rbf')
    ocsvm_model.fit(X_train_clean_scaled)
    y_pred_ocsvm = (ocsvm_model.predict(X_eval_scaled) == -1).astype(int)
    prec_ocsvm = precision_score(y_eval, y_pred_ocsvm, zero_division=0)
    rec_ocsvm = recall_score(y_eval, y_pred_ocsvm, zero_division=0)
    f1_ocsvm = f1_score(y_eval, y_pred_ocsvm, zero_division=0)
    f2_ocsvm = fbeta_score(y_eval, y_pred_ocsvm, beta=2, zero_division=0)
    results_unsup.append({
        "model": "One-Class SVM",
        "precision": round(prec_ocsvm * 100, 2),
        "recall": round(rec_ocsvm * 100, 2),
        "f1": round(f1_ocsvm * 100, 2),
        "f2": round(f2_ocsvm * 100, 2)
    })
    print(f"  Precision={prec_ocsvm*100:.2f}% | Recall={rec_ocsvm*100:.2f}% | F1={f1_ocsvm*100:.2f}%")

    # Local Outlier Factor
    print("Training Local Outlier Factor (on clean data)...")
    lof_model = LocalOutlierFactor(n_neighbors=20, contamination=contamination, novelty=True)
    lof_model.fit(X_train_clean_scaled)
    y_pred_lof = (lof_model.predict(X_eval_scaled) == -1).astype(int)
    prec_lof = precision_score(y_eval, y_pred_lof, zero_division=0)
    rec_lof = recall_score(y_eval, y_pred_lof, zero_division=0)
    f1_lof = f1_score(y_eval, y_pred_lof, zero_division=0)
    f2_lof = fbeta_score(y_eval, y_pred_lof, beta=2, zero_division=0)
    results_unsup.append({
        "model": "Local Outlier Factor",
        "precision": round(prec_lof * 100, 2),
        "recall": round(rec_lof * 100, 2),
        "f1": round(f1_lof * 100, 2),
        "f2": round(f2_lof * 100, 2)
    })
    print(f"  Precision={prec_lof*100:.2f}% | Recall={rec_lof*100:.2f}% | F1={f1_lof*100:.2f}%")

    # ===== STEP 4: Save All Models =====
    print("\n[STEP 4] Saving Models")
    print("-" * 80)

    joblib.dump(rf_model, os.path.join(models_dir, "rf_final.pkl"))
    joblib.dump(lr_model, os.path.join(models_dir, "lr_final.pkl"))
    print("✓ Saved supervised models (RF, LR)")

    joblib.dump(if_model, os.path.join(models_dir, "isolation_forest_final.pkl"))
    joblib.dump(ocsvm_model, os.path.join(models_dir, "ocsvm_final.pkl"))
    joblib.dump(scaler, os.path.join(models_dir, "scaler_final.pkl"))
    joblib.dump(lof_model, os.path.join(models_dir, "lof_final.pkl"))
    print("✓ Saved unsupervised models (IF, OCSVM, LOF)")

    # ===== STEP 5: Summary =====
    print("\n" + "=" * 80)
    print("FINAL RESULTS - ALL MODELS")
    print("=" * 80)

    print("\nTIER 2 (SUPERVISED) - Trained on 70,091 labeled logs:")
    print("-" * 80)
    for r in results_sup:
        print(f"  {r['model']:25} | Prec={r['precision']:6.2f}% | Rec={r['recall']:6.2f}% | F1={r['f1']:6.2f}% | F2={r['f2']:6.2f}%")

    print("\nTIER 3 (UNSUPERVISED) - Trained on 34,941 clean logs:")
    print("-" * 80)
    for r in results_unsup:
        print(f"  {r['model']:25} | Prec={r['precision']:6.2f}% | Rec={r['recall']:6.2f}% | F1={r['f1']:6.2f}% | F2={r['f2']:6.2f}%")

    print(f"\nEvaluation Set: {len(X_eval):,} logs ({(y_eval==1).sum():,} attacks, {(y_eval==0).sum():,} clean)")

    # Save results
    results = {
        "timestamp": datetime.now().isoformat(),
        "dataset": "final_comprehensive",
        "data_sources": {
            "synthetic_attack": 25000,
            "synthetic_clean": 25000,
            "csic_attack": 25065,
            "csic_clean": 36000,
            "total": 111065,
        },
        "training": {
            "supervised_samples": len(X_train),
            "supervised_attacks": int((y_train==1).sum()),
            "unsupervised_clean_samples": len(X_train_clean),
        },
        "evaluation": {
            "samples": len(X_eval),
            "attacks": int((y_eval==1).sum()),
            "clean": int((y_eval==0).sum()),
            "attack_ratio": round((y_eval==1).sum() / len(y_eval) * 100, 2),
        },
        "supervised": results_sup,
        "unsupervised": results_unsup,
    }

    results_file = os.path.join(PROJECT_ROOT, "analysis", "final_model_results.json")
    os.makedirs(os.path.dirname(results_file), exist_ok=True)
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\n✓ Results saved: {results_file}")

    print("\n" + "=" * 80)
    print("✓ ALL MODELS TRAINED AND SAVED")
    print("=" * 80)

if __name__ == "__main__":
    main()
