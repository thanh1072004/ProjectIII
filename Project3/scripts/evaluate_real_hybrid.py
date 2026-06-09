#!/usr/bin/env python3
"""
REAL per-sample evaluation of every tier + hybrid configuration.

Unlike generate_comprehensive_comparison.py (which ESTIMATED the hybrid numbers
as a weighted average of the RF/LOF single-model scores), this script runs the
ACTUAL decision logic on every eval sample using the deployed *_final.pkl models
and the production regex engine (detect_rule_based).

Source of truth for:
  - analysis/tier_and_hybrid_results.json
  - the hybrid rows in analysis/comprehensive_comparison.json
  - README section 3 performance tables

Single-model numbers (RF, LR, IF, OCSVM, LOF) are recomputed here too and must
match analysis/final_model_results.json exactly.

Read-only on models; only writes analysis JSON when run with --write.
"""
import os, sys, io, json, argparse
import numpy as np
import re
import joblib
from urllib.parse import urlparse, unquote, parse_qs

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "models"))
sys.path.insert(0, PROJECT_ROOT)
from ai_detector import LogAnomalyDetector
import apache_log  # for detect_rule_based + regex engine
apache_log.PATH_PARAM_VOCAB = {}  # final models were trained with empty vocab

from sklearn.metrics import precision_score, recall_score, f1_score, fbeta_score

MODELS_DIR = os.path.join(PROJECT_ROOT, "trained_models")
EVAL_FILE = os.path.join(PROJECT_ROOT, "datasets", "final_dataset_eval.log")

LOG_RE = re.compile(
    r'(\S+) - - \[([^\]]+)\] "(\S+)\s+([^"]+)(?:\s+HTTP[^"]*)?"\s+(\d+)\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"')


def parse_line(line):
    m = LOG_RE.match(line)
    if not m:
        return None
    ip, ts, method, url, status, size, referer, ua = m.groups()
    try:
        decoded_url = unquote(url)
    except Exception:
        decoded_url = url
    p = urlparse(decoded_url)
    return {
        "method": method,
        "path": p.path or "/",
        "query": p.query or "",
        "status": int(status),
        "user_agent": ua,
        "referer": referer,
        "is_attack": "(Simulated-Attack)" in line,
    }


def metrics(y, pred):
    return {
        "precision": round(precision_score(y, pred, zero_division=0) * 100, 2),
        "recall": round(recall_score(y, pred, zero_division=0) * 100, 2),
        "f1": round(f1_score(y, pred, zero_division=0) * 100, 2),
        "f2": round(fbeta_score(y, pred, beta=2, zero_division=0) * 100, 2),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="overwrite analysis JSON files")
    args = ap.parse_args()

    detector = LogAnomalyDetector()
    X, y, regex_hits = [], [], []
    print(f"Reading + featurizing {EVAL_FILE} ...")
    with open(EVAL_FILE, 'r', errors='ignore') as f:
        for line in f:
            line = line.strip()
            p = parse_line(line)
            if not p:
                continue
            try:
                feats = detector.extract_features(
                    p["path"], p["query"], p["method"], str(p["status"]),
                    p["user_agent"], p["referer"])
            except Exception:
                continue
            X.append(feats)
            y.append(1 if p["is_attack"] else 0)
            # production regex tier (Tier 1)
            parsed_data = {
                "path": p["path"], "query": p["query"],
                "params": parse_qs(p["query"], keep_blank_values=True),
                "user_agent": p["user_agent"], "method": p["method"],
            }
            regex_hits.append(1 if len(apache_log.detect_rule_based(parsed_data)) > 0 else 0)

    X = np.array(X); y = np.array(y); regex_hits = np.array(regex_hits)
    n = len(y); n_atk = int(y.sum()); n_clean = n - n_atk
    print(f"  eval = {n} samples ({n_atk} attack, {n_clean} clean, {n_atk/n*100:.2f}% attack)")

    # ---- load deployed models ----
    rf = joblib.load(os.path.join(MODELS_DIR, "rf_final.pkl"))
    lr = joblib.load(os.path.join(MODELS_DIR, "lr_final.pkl"))
    iso = joblib.load(os.path.join(MODELS_DIR, "isolation_forest_final.pkl"))
    ocsvm = joblib.load(os.path.join(MODELS_DIR, "ocsvm_final.pkl"))
    lof = joblib.load(os.path.join(MODELS_DIR, "lof_final.pkl"))
    scaler = joblib.load(os.path.join(MODELS_DIR, "scaler_final.pkl"))

    Xs = scaler.transform(X)

    rf_pred = rf.predict(X)
    rf_proba = rf.predict_proba(X)[:, 1]
    lr_pred = lr.predict(X)
    if_pred = (iso.predict(X) == -1).astype(int)
    ocsvm_pred = (ocsvm.predict(Xs) == -1).astype(int)
    lof_pred = (lof.predict(Xs) == -1).astype(int)

    # ---- hybrids (REAL per-sample decision logic, matches apache_log.py) ----
    # Smart Consensus is the production default and MUST exercise all 3 tiers:
    #   alert = regex_hit OR (RF_prob >= 0.5) OR (LOF_anomaly AND RF_prob >= 0.3)
    smart = ((regex_hits == 1) | (rf_proba >= 0.5) | ((lof_pred == 1) & (rf_proba >= 0.3))).astype(int)
    voting = ((regex_hits == 1) | (rf_proba >= 0.5) | (lof_pred == 1)).astype(int)

    single = {
        "RandomForest": metrics(y, rf_pred),
        "LogisticRegression": metrics(y, lr_pred),
        "Isolation Forest": metrics(y, if_pred),
        "One-Class SVM": metrics(y, ocsvm_pred),
        "Local Outlier Factor": metrics(y, lof_pred),
    }
    tier1 = metrics(y, regex_hits)
    smart_m = metrics(y, smart)
    voting_m = metrics(y, voting)

    def show(name, m):
        print(f"  {name:34} P={m['precision']:6.2f}  R={m['recall']:6.2f}  F1={m['f1']:6.2f}  F2={m['f2']:6.2f}")

    print("\n=== SINGLE MODELS (must match final_model_results.json) ===")
    for k, v in single.items():
        show(k, v)
    print("\n=== TIERS + HYBRIDS (REAL per-sample) ===")
    show("Tier 1: Regex Rules", tier1)
    show("Smart Consensus (regex | RF>=.5 | LOF&RF>=.3)", smart_m)
    show("Simple Voting (T1 | T2 | T3)", voting_m)

    if not args.write:
        print("\n(dry-run; pass --write to update analysis JSON files)")
        return

    # ---- write tier_and_hybrid_results.json ----
    from datetime import datetime
    ts = datetime.now().isoformat()
    tier_hybrid = {
        "timestamp": ts,
        "dataset": "final_comprehensive",
        "evaluation": {"samples": n, "attacks": n_atk, "clean": n_clean,
                       "attack_ratio": round(n_atk / n * 100, 2)},
        "method": "real_per_sample_evaluation",
        "tiers_and_hybrid": [
            {"name": "Tier 1: Regex Rules", "type": "Baseline (Rule-based)", **tier1},
            {"name": "Tier 2: RandomForest", "type": "Supervised Learning", **single["RandomForest"]},
            {"name": "Tier 3: Local Outlier Factor", "type": "Unsupervised Anomaly", **single["Local Outlier Factor"]},
            {"name": "Smart Consensus (T2 70% + T3 30%)", "type": "Hybrid Ensemble", **smart_m},
            {"name": "Simple Voting (T1 OR T2 OR T3)", "type": "Hybrid Voting", **voting_m},
        ],
    }
    out1 = os.path.join(PROJECT_ROOT, "analysis", "tier_and_hybrid_results.json")
    with open(out1, "w", encoding="utf-8") as f:
        json.dump(tier_hybrid, f, indent=2)
    print(f"\n[WRITE] {out1}")

    # ---- write comprehensive_comparison.json ----
    def rec(tier, typ, model, m):
        return {"Tier": tier, "Type": typ, "Model": model,
                "Precision": m["precision"], "Recall": m["recall"], "F1": m["f1"], "F2": m["f2"]}
    comp = {
        "timestamp": ts,
        "dataset": "final_comprehensive",
        "evaluation": {"samples": n, "attacks": n_atk, "clean": n_clean,
                       "attack_ratio": round(n_atk / n * 100, 2)},
        "method": "real_per_sample_evaluation",
        "models": [
            rec("Tier 2", "Supervised", "RandomForest", single["RandomForest"]),
            rec("Tier 2", "Supervised", "LogisticRegression", single["LogisticRegression"]),
            rec("Tier 3", "Unsupervised", "Isolation Forest", single["Isolation Forest"]),
            rec("Tier 3", "Unsupervised", "One-Class SVM", single["One-Class SVM"]),
            rec("Tier 3", "Unsupervised", "Local Outlier Factor", single["Local Outlier Factor"]),
            rec("Hybrid", "Smart Consensus", "RF + LOF (consensus)", smart_m),
            rec("Hybrid", "Simple Voting", "T1 OR T2 OR T3", voting_m),
        ],
    }
    out2 = os.path.join(PROJECT_ROOT, "analysis", "comprehensive_comparison.json")
    with open(out2, "w", encoding="utf-8") as f:
        json.dump(comp, f, indent=2)
    print(f"[WRITE] {out2}")


if __name__ == "__main__":
    main()
