#!/usr/bin/env python3
"""
Regenerate analysis/charts/confusion_matrices.png on the SAME 28,767-line
evaluation set used by every other chart, so the confusion matrices are
consistent with tier_and_hybrid_results.json / comprehensive_comparison.json.

It reuses the exact model-loading and featurization logic of
scripts/evaluate_real_hybrid.py (deployed *_final.pkl models + production
regex tier) and renders one confusion matrix per configuration:

    Tier 1: Regex Rules
    Tier 2: RandomForest
    Tier 2: LogisticRegression
    Tier 3: Isolation Forest
    Tier 3: One-Class SVM
    Tier 3: Local Outlier Factor
    Smart Consensus  (regex | RF>=0.5 | LOF&RF>=0.3)
    Simple Voting    (regex | RF>=0.5 | LOF)

Read-only on models; writes only the PNG.
"""
import os, sys, io
import numpy as np
import re
import joblib
from urllib.parse import urlparse, unquote, parse_qs

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import (confusion_matrix, precision_score, recall_score,
                             f1_score, fbeta_score)

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "models"))
sys.path.insert(0, PROJECT_ROOT)
from ai_detector import LogAnomalyDetector
import apache_log
apache_log.PATH_PARAM_VOCAB = {}  # final models were trained with empty vocab

MODELS_DIR = os.path.join(PROJECT_ROOT, "trained_models")
EVAL_FILE = os.path.join(PROJECT_ROOT, "datasets", "final_dataset_eval.log")
OUT_PNG = os.path.join(PROJECT_ROOT, "analysis", "charts", "confusion_matrices.png")

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
        "method": method, "path": p.path or "/", "query": p.query or "",
        "status": int(status), "user_agent": ua, "referer": referer,
        "is_attack": "(Simulated-Attack)" in line,
    }


def main():
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
            parsed_data = {
                "path": p["path"], "query": p["query"],
                "params": parse_qs(p["query"], keep_blank_values=True),
                "user_agent": p["user_agent"], "method": p["method"],
            }
            regex_hits.append(1 if len(apache_log.detect_rule_based(parsed_data)) > 0 else 0)

    X = np.array(X); y = np.array(y); regex_hits = np.array(regex_hits)
    n = len(y); n_atk = int(y.sum()); n_clean = n - n_atk
    print(f"  eval = {n} samples ({n_atk} attack, {n_clean} clean, {n_atk/n*100:.2f}% attack)")

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

    smart = ((regex_hits == 1) | (rf_proba >= 0.5) | ((lof_pred == 1) & (rf_proba >= 0.3))).astype(int)
    voting = ((regex_hits == 1) | (rf_proba >= 0.5) | (lof_pred == 1)).astype(int)

    # (title, predictions) in display order — matches the other 28,767 charts
    panels = [
        ("Tier 1: Regex Rules", regex_hits),
        ("Tier 2: RandomForest", rf_pred),
        ("Tier 2: LogisticRegression", lr_pred),
        ("Tier 3: Isolation Forest", if_pred),
        ("Tier 3: One-Class SVM", ocsvm_pred),
        ("Tier 3: Local Outlier Factor", lof_pred),
        ("Smart Consensus", smart),
        ("Simple Voting", voting),
    ]

    cols = 4
    rows = (len(panels) + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(4 * cols, 3.4 * rows))
    axes = axes.flatten()

    for i, (name, pred) in enumerate(panels):
        cm = confusion_matrix(y, pred, labels=[0, 1])  # [[TN,FP],[FN,TP]]
        f1 = f1_score(y, pred, zero_division=0) * 100
        f2 = fbeta_score(y, pred, beta=2, zero_division=0) * 100
        ax = axes[i]
        ax.imshow(cm, cmap='Blues')
        ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
        ax.set_xticklabels(['Pred Clean', 'Pred Attack'], fontsize=9)
        ax.set_yticklabels(['True Clean', 'True Attack'], fontsize=9)
        ax.set_title(f"{name}\nF1={f1:.1f}  F2={f2:.1f}", fontsize=10)
        vmax = cm.max()
        for r in range(2):
            for c in range(2):
                txt_color = 'white' if cm[r, c] > vmax * 0.5 else 'black'
                ax.text(c, r, f"{cm[r, c]}", ha='center', va='center',
                        color=txt_color, fontsize=12, fontweight='bold')
        p = precision_score(y, pred, zero_division=0) * 100
        rcl = recall_score(y, pred, zero_division=0) * 100
        print(f"  {name:30} TN={cm[0,0]:5d} FP={cm[0,1]:5d} FN={cm[1,0]:5d} TP={cm[1,1]:5d}"
              f"  P={p:5.2f} R={rcl:5.2f} F1={f1:5.2f} F2={f2:5.2f}")

    for j in range(len(panels), len(axes)):
        axes[j].axis('off')

    fig.suptitle(f"Confusion Matrices on the Evaluation Set "
                 f"({n:,} logs, {n_atk/n*100:.2f}% attack)",
                 fontsize=14, fontweight='bold')
    plt.tight_layout(rect=[0, 0, 1, 0.97])
    plt.savefig(OUT_PNG, dpi=150, bbox_inches='tight')
    print(f"\n[WRITE] {OUT_PNG}")


if __name__ == "__main__":
    main()
