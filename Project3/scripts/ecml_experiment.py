#!/usr/bin/env python3
"""
ECML/PKDD 2007 cross-dataset EXPERIMENT (self-contained, isolated).

Goal: demonstrate that the same 3-tier methodology works on a second,
independent dataset. This script does NOT touch the main CSIC artifacts:
it reads only datasets/ecml/*.log, trains fresh models, and writes every
output under datasets/ecml/ (models/ and charts/). The production CSIC
models in trained_models/ and the reports in analysis/ are left untouched.

Pipeline:
  - Pool ecml_train_clean.log (clean) + ecml_test.log (labelled) and split
    70/30 stratified (seed 42) into train / eval.
  - Tier 2 (supervised): RandomForest + LogisticRegression on the train split.
  - Tier 3 (unsupervised, one-class): IsolationForest, One-Class SVM, LOF
    trained on the CLEAN subset of the train split only.
  - Tier 1 (regex): no training; evaluated as-is.
  - Hybrids: Simple Voting and the production Smart Consensus.
  - Same 22-feature space and same hyperparameters as the main system.

Outputs (all under datasets/ecml/):
  models/  rf_ecml.pkl, lr_ecml.pkl, scaler_lr_ecml.pkl,
           isolation_forest_ecml.pkl, ocsvm_ecml.pkl, lof_ecml.pkl,
           scaler_unsup_ecml.pkl
  charts/  ecml_comprehensive_metrics.png, ecml_confusion_matrices.png,
           ecml_model_comparison.png, ecml_results.json
"""
import os, sys, io, re, json
import numpy as np
import joblib
from urllib.parse import urlparse, unquote, parse_qs
from datetime import datetime

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (confusion_matrix, precision_score, recall_score,
                             f1_score, fbeta_score)

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "models"))
sys.path.insert(0, PROJECT_ROOT)
from ai_detector import LogAnomalyDetector
import apache_log
apache_log.PATH_PARAM_VOCAB = {}          # keep consistent with deployed eval

ECML_DIR   = os.path.join(PROJECT_ROOT, "datasets", "ecml")
MODELS_DIR = os.path.join(ECML_DIR, "models")
CHARTS_DIR = os.path.join(ECML_DIR, "charts")
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(CHARTS_DIR, exist_ok=True)

LOG_RE = re.compile(
    r'(\S+) - - \[([^\]]+)\] "(\S+)\s+([^"]+)(?:\s+HTTP[^"]*)?"\s+(\d+)\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"')

_detector = LogAnomalyDetector()          # used only as a feature extractor
_detector.path_param_vocab = {}


def load_log(path):
    """Return (X features, y labels, regex_hit flags)."""
    X, y, regex = [], [], []
    with open(path, 'r', errors='ignore') as f:
        for line in f:
            line = line.strip()
            m = LOG_RE.match(line)
            if not m:
                continue
            ip, ts, method, url, status, size, referer, ua = m.groups()
            try:
                decoded = unquote(url)
            except Exception:
                decoded = url
            p = urlparse(decoded)
            path_, query = p.path or "/", p.query or ""
            try:
                feats = _detector.extract_features(path_, query, method, status, ua, referer)
            except Exception:
                continue
            X.append(feats)
            y.append(1 if "(Simulated-Attack)" in line else 0)
            parsed_data = {"path": path_, "query": query,
                           "params": parse_qs(query, keep_blank_values=True),
                           "user_agent": ua, "method": method}
            regex.append(1 if len(apache_log.detect_rule_based(parsed_data)) > 0 else 0)
    return X, y, regex


def metrics(y, pred):
    return {
        "precision": round(precision_score(y, pred, zero_division=0) * 100, 2),
        "recall":    round(recall_score(y, pred, zero_division=0) * 100, 2),
        "f1":        round(f1_score(y, pred, zero_division=0) * 100, 2),
        "f2":        round(fbeta_score(y, pred, beta=2, zero_division=0) * 100, 2),
    }


def main():
    print("Loading ECML logs ...")
    Xa, ya, ra = load_log(os.path.join(ECML_DIR, "ecml_train_clean.log"))
    Xb, yb, rb = load_log(os.path.join(ECML_DIR, "ecml_test.log"))
    X = np.array(Xa + Xb, dtype=float)
    y = np.array(ya + yb, dtype=int)
    regex = np.array(ra + rb, dtype=int)
    print(f"  pooled = {len(y)} samples ({int(y.sum())} attack, {len(y)-int(y.sum())} clean)")

    idx = np.arange(len(y))
    tr, ev = train_test_split(idx, test_size=0.30, random_state=42, stratify=y)
    Xtr, ytr = X[tr], y[tr]
    Xev, yev, rev = X[ev], y[ev], regex[ev]
    print(f"  train = {len(tr)} ({int(ytr.sum())} atk) | eval = {len(ev)} "
          f"({int(yev.sum())} atk, {len(ev)-int(yev.sum())} clean)")

    # ---------- Tier 2: supervised ----------
    print("Training Tier 2 (RandomForest, LogisticRegression) ...")
    rf = RandomForestClassifier(n_estimators=200, class_weight="balanced",
                                n_jobs=-1, random_state=42).fit(Xtr, ytr)
    scaler_lr = StandardScaler().fit(Xtr)
    lr = LogisticRegression(max_iter=2000, class_weight="balanced",
                            solver="lbfgs", random_state=42).fit(scaler_lr.transform(Xtr), ytr)

    # ---------- Tier 3: one-class on CLEAN train only ----------
    print("Training Tier 3 (IsolationForest, One-Class SVM, LOF) on clean only ...")
    Xc = Xtr[ytr == 0]
    scaler_un = StandardScaler().fit(Xc)
    Xc_s = scaler_un.transform(Xc)
    iso = IsolationForest(contamination=0.50, n_estimators=200,
                          n_jobs=-1, random_state=42).fit(Xc_s)
    ocsvm = OneClassSVM(nu=0.60, kernel="rbf", gamma="scale").fit(Xc_s)
    lof = LocalOutlierFactor(n_neighbors=20, contamination=0.50, novelty=True).fit(Xc_s)

    # ---------- predictions on eval ----------
    Xev_s = scaler_un.transform(Xev)
    rf_pred = rf.predict(Xev)
    rf_proba = rf.predict_proba(Xev)[:, 1]
    lr_pred = lr.predict(scaler_lr.transform(Xev))
    if_pred = (iso.predict(Xev_s) == -1).astype(int)
    oc_pred = (ocsvm.predict(Xev_s) == -1).astype(int)
    lof_pred = (lof.predict(Xev_s) == -1).astype(int)

    smart = ((rev == 1) | (rf_proba >= 0.5) | ((lof_pred == 1) & (rf_proba >= 0.3))).astype(int)
    voting = ((rev == 1) | (rf_proba >= 0.5) | (lof_pred == 1)).astype(int)

    # ---------- metrics ----------
    panels = [
        ("Tier 1: Regex Rules", rev),
        ("Tier 2: RandomForest", rf_pred),
        ("Tier 2: LogisticRegression", lr_pred),
        ("Tier 3: Isolation Forest", if_pred),
        ("Tier 3: One-Class SVM", oc_pred),
        ("Tier 3: Local Outlier Factor", lof_pred),
        ("Smart Consensus", smart),
        ("Simple Voting", voting),
    ]
    results = {name: metrics(yev, pred) for name, pred in panels}

    print("\n=== ECML/PKDD 2007 — results on eval split ===")
    print(f"  {'Configuration':32} {'Prec':>7} {'Recall':>7} {'F1':>7} {'F2':>7}")
    for name, m in results.items():
        print(f"  {name:32} {m['precision']:7.2f} {m['recall']:7.2f} {m['f1']:7.2f} {m['f2']:7.2f}")

    # ---------- save models ----------
    joblib.dump(rf,        os.path.join(MODELS_DIR, "rf_ecml.pkl"))
    joblib.dump(lr,        os.path.join(MODELS_DIR, "lr_ecml.pkl"))
    joblib.dump(scaler_lr, os.path.join(MODELS_DIR, "scaler_lr_ecml.pkl"))
    joblib.dump(iso,       os.path.join(MODELS_DIR, "isolation_forest_ecml.pkl"))
    joblib.dump(ocsvm,     os.path.join(MODELS_DIR, "ocsvm_ecml.pkl"))
    joblib.dump(lof,       os.path.join(MODELS_DIR, "lof_ecml.pkl"))
    joblib.dump(scaler_un, os.path.join(MODELS_DIR, "scaler_unsup_ecml.pkl"))
    print(f"\n[models] saved 7 .pkl files to {MODELS_DIR}")

    # ---------- save results json ----------
    n_atk = int(yev.sum()); n_cln = len(yev) - n_atk
    out = {
        "timestamp": datetime.now().isoformat(),
        "dataset": "ECML/PKDD 2007",
        "note": "Pooled train_clean + test, 70/30 stratified split; "
                "Tier 3 trained on clean subset of train only.",
        "evaluation": {"samples": len(yev), "attacks": n_atk, "clean": n_cln,
                       "attack_ratio": round(n_atk / len(yev) * 100, 2)},
        "results": [{"model": k, **v} for k, v in results.items()],
    }
    with open(os.path.join(CHARTS_DIR, "ecml_results.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print(f"[json]   saved ecml_results.json to {CHARTS_DIR}")

    # ---------- chart 1: grouped metric bars ----------
    names = list(results.keys())
    P = [results[n]["precision"] for n in names]
    R = [results[n]["recall"] for n in names]
    F1 = [results[n]["f1"] for n in names]
    F2 = [results[n]["f2"] for n in names]
    short = [n.replace("Tier 1: ", "").replace("Tier 2: ", "").replace("Tier 3: ", "")
             for n in names]
    xx = np.arange(len(names)); w = 0.2
    fig, ax = plt.subplots(figsize=(15, 7))
    ax.bar(xx - 1.5*w, P, w, label="Precision")
    ax.bar(xx - 0.5*w, R, w, label="Recall")
    ax.bar(xx + 0.5*w, F1, w, label="F1")
    ax.bar(xx + 1.5*w, F2, w, label="F2")
    ax.set_xticks(xx); ax.set_xticklabels(short, rotation=20, ha="right", fontsize=9)
    ax.set_ylabel("%"); ax.set_ylim(0, 109)
    ax.set_title("ECML/PKDD 2007 — Performance of tiers and hybrids", fontweight="bold")
    ax.legend(ncol=4, loc="lower center")
    ax.grid(axis="y", ls="--", alpha=.4)
    for arr, off in [(P,-1.5*w),(R,-0.5*w),(F1,0.5*w),(F2,1.5*w)]:
        for i,v in enumerate(arr):
            ax.text(xx[i]+off, v+1, f"{v:.0f}", ha="center", fontsize=7)
    plt.tight_layout()
    plt.savefig(os.path.join(CHARTS_DIR, "ecml_comprehensive_metrics.png"), dpi=150, bbox_inches="tight")
    plt.close()

    # ---------- chart 2: confusion matrices ----------
    cols = 4; rows = (len(panels) + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(4*cols, 3.4*rows))
    axes = axes.flatten()
    for i, (name, pred) in enumerate(panels):
        cm = confusion_matrix(yev, pred, labels=[0, 1])
        m = results[name]
        ax = axes[i]; ax.imshow(cm, cmap="Blues")
        ax.set_xticks([0,1]); ax.set_yticks([0,1])
        ax.set_xticklabels(["Pred Clean","Pred Attack"], fontsize=9)
        ax.set_yticklabels(["True Clean","True Attack"], fontsize=9)
        ax.set_title(f"{name}\nF1={m['f1']:.1f}  F2={m['f2']:.1f}", fontsize=10)
        vmax = cm.max()
        for r in range(2):
            for c in range(2):
                ax.text(c, r, f"{cm[r,c]}", ha="center", va="center",
                        color="white" if cm[r,c] > vmax*0.5 else "black",
                        fontsize=12, fontweight="bold")
    for j in range(len(panels), len(axes)):
        axes[j].axis("off")
    fig.suptitle(f"ECML/PKDD 2007 — Confusion Matrices "
                 f"({len(yev):,} eval, {n_atk/len(yev)*100:.1f}% attack)",
                 fontsize=14, fontweight="bold")
    plt.tight_layout(rect=[0,0,1,0.97])
    plt.savefig(os.path.join(CHARTS_DIR, "ecml_confusion_matrices.png"), dpi=150, bbox_inches="tight")
    plt.close()

    # ---------- chart 3: tier vs hybrid comparison ----------
    sel = ["Tier 1: Regex Rules", "Tier 2: RandomForest", "Tier 3: Local Outlier Factor",
           "Simple Voting", "Smart Consensus"]
    P = [results[n]["precision"] for n in sel]; R = [results[n]["recall"] for n in sel]
    F1 = [results[n]["f1"] for n in sel]; F2 = [results[n]["f2"] for n in sel]
    short = [s.replace("Tier 1: ","T1 ").replace("Tier 2: ","T2 ").replace("Tier 3: ","T3 ") for s in sel]
    xx = np.arange(len(sel)); w = 0.2
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.bar(xx - 1.5*w, P, w, label="Precision")
    ax.bar(xx - 0.5*w, R, w, label="Recall")
    ax.bar(xx + 0.5*w, F1, w, label="F1")
    ax.bar(xx + 1.5*w, F2, w, label="F2")
    ax.axhline(90, ls="--", color="gray", alpha=.6)
    ax.set_xticks(xx); ax.set_xticklabels(short, rotation=15, ha="right")
    ax.set_ylabel("%"); ax.set_ylim(0, 109)
    ax.set_title("ECML/PKDD 2007 — Tier & Hybrid comparison", fontweight="bold")
    ax.legend(ncol=4, loc="lower center"); ax.grid(axis="y", ls="--", alpha=.4)
    for arr, off in [(P,-1.5*w),(R,-0.5*w),(F1,0.5*w),(F2,1.5*w)]:
        for i,v in enumerate(arr):
            ax.text(xx[i]+off, v+1, f"{v:.1f}", ha="center", fontsize=7)
    plt.tight_layout()
    plt.savefig(os.path.join(CHARTS_DIR, "ecml_model_comparison.png"), dpi=150, bbox_inches="tight")
    plt.close()

    print(f"[charts] saved 3 PNG charts to {CHARTS_DIR}")
    print("\nDone. All ECML artifacts are under datasets/ecml/ (models/ + charts/).")


if __name__ == "__main__":
    main()
