#!/usr/bin/env python3
"""
HttpParams 2015 cross-dataset EXPERIMENT (self-contained, isolated).

Same methodology as scripts/ecml_experiment.py, applied to the HttpParams
dataset (Morzeux/HttpParamsDataset). The CSV holds HTTP *parameter values*
labelled norm/anom, so each payload is wrapped as a query parameter of a
synthetic request (GET /?q=<url-encoded payload>) before the shared 22-feature
extractor and the production regex tier are applied.

Nothing outside datasets/httpparams/ is touched; the main CSIC models in
trained_models/ are left intact.

Pipeline:
  - Read payload_full.csv -> build features + labels (+ a record log file).
  - 70/30 stratified split.
  - Tier 2 (supervised): RandomForest + LogisticRegression on the train split.
  - Tier 3 (one-class): IsolationForest, One-Class SVM, LOF on the CLEAN
    subset of the train split only.
  - Tier 1 (regex), plus Smart Consensus and Simple Voting fusions.
  - Same hyperparameters as the main system.

Outputs (under datasets/httpparams/):
  httpparams_all.log
  models/  rf_hp.pkl, lr_hp.pkl, scaler_lr_hp.pkl,
           isolation_forest_hp.pkl, ocsvm_hp.pkl, lof_hp.pkl, scaler_unsup_hp.pkl
  charts/  httpparams_comprehensive_metrics.png,
           httpparams_confusion_matrices.png,
           httpparams_model_comparison.png, httpparams_results.json
"""
import os, sys, io, csv, json
import numpy as np
import joblib
import urllib.parse
from urllib.parse import parse_qs
from datetime import datetime, timedelta
import random

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
csv.field_size_limit(10**7)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "models"))
sys.path.insert(0, PROJECT_ROOT)
from ai_detector import LogAnomalyDetector
import apache_log
apache_log.PATH_PARAM_VOCAB = {}

HP_DIR     = os.path.join(PROJECT_ROOT, "datasets", "httpparams")
CSV_FILE   = os.path.join(HP_DIR, "payload_full.csv")
LOG_FILE   = os.path.join(HP_DIR, "httpparams_all.log")
MODELS_DIR = os.path.join(HP_DIR, "models")
CHARTS_DIR = os.path.join(HP_DIR, "charts")
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(CHARTS_DIR, exist_ok=True)

_detector = LogAnomalyDetector()
_detector.path_param_vocab = {}


def metrics(y, pred):
    return {
        "precision": round(precision_score(y, pred, zero_division=0) * 100, 2),
        "recall":    round(recall_score(y, pred, zero_division=0) * 100, 2),
        "f1":        round(f1_score(y, pred, zero_division=0) * 100, 2),
        "f2":        round(fbeta_score(y, pred, beta=2, zero_division=0) * 100, 2),
    }


def main():
    print(f"Reading {CSV_FILE} ...")
    X, y, regex = [], [], []
    random.seed(42)
    start_time = datetime(2026, 1, 1)
    n_norm = n_anom = 0

    with open(CSV_FILE, "r", encoding="utf-8", errors="replace") as f, \
         open(LOG_FILE, "w", encoding="utf-8") as flog:
        reader = csv.DictReader(f)
        for row in reader:
            label_raw = (row.get("label") or "").strip().lower()
            if label_raw not in ("norm", "anom"):
                continue
            payload = row.get("payload", "") or ""
            is_attack = 1 if label_raw == "anom" else 0

            # Wrap the raw parameter value as a query parameter of a request.
            enc = urllib.parse.quote(payload, safe="")
            path, query, method = "/", f"q={enc}", "GET"
            ua, ref = "Mozilla/5.0", "-"

            try:
                feats = _detector.extract_features(path, query, method, "200", ua, ref)
            except Exception:
                continue
            X.append(feats)
            y.append(is_attack)
            pd = {"path": path, "query": query,
                  "params": parse_qs(query, keep_blank_values=True),
                  "user_agent": ua, "method": method}
            regex.append(1 if len(apache_log.detect_rule_based(pd)) > 0 else 0)

            # record log line (faithful Apache combined format)
            ua_line = ua + (" (Simulated-Attack)" if is_attack else "")
            ip = f"{random.randint(10,192)}.{random.randint(0,255)}." \
                 f"{random.randint(0,255)}.{random.randint(1,254)}"
            dt = start_time.strftime("%d/%b/%Y:%H:%M:%S +0700")
            start_time += timedelta(seconds=1)
            flog.write(f'{ip} - - [{dt}] "GET /?{query} HTTP/1.1" 200 '
                       f'{random.randint(500,5000)} "{ref}" "{ua_line}"\n')
            n_norm += (is_attack == 0); n_anom += (is_attack == 1)

    X = np.array(X, dtype=float); y = np.array(y); regex = np.array(regex)
    print(f"  total = {len(y)} (norm={n_norm}, anom={n_anom}, "
          f"{n_anom/len(y)*100:.2f}% attack)")
    print(f"  record log written -> {LOG_FILE}")

    idx = np.arange(len(y))
    tr, ev = train_test_split(idx, test_size=0.30, random_state=42, stratify=y)
    Xtr, ytr = X[tr], y[tr]
    Xev, yev, rev = X[ev], y[ev], regex[ev]
    print(f"  train={len(tr)} ({int(ytr.sum())} atk) | "
          f"eval={len(ev)} ({int(yev.sum())} atk, {len(ev)-int(yev.sum())} clean)")

    # ---------- Tier 2 ----------
    print("Training Tier 2 (RandomForest, LogisticRegression) ...")
    rf = RandomForestClassifier(n_estimators=200, class_weight="balanced",
                                n_jobs=-1, random_state=42).fit(Xtr, ytr)
    scaler_lr = StandardScaler().fit(Xtr)
    lr = LogisticRegression(max_iter=2000, class_weight="balanced",
                            solver="lbfgs", random_state=42).fit(scaler_lr.transform(Xtr), ytr)

    # ---------- Tier 3 (clean-only) ----------
    print("Training Tier 3 (IsolationForest, One-Class SVM, LOF) on clean only ...")
    Xc = Xtr[ytr == 0]
    scaler_un = StandardScaler().fit(Xc)
    Xc_s = scaler_un.transform(Xc)
    iso = IsolationForest(contamination=0.50, n_estimators=200,
                          n_jobs=-1, random_state=42).fit(Xc_s)
    ocsvm = OneClassSVM(nu=0.60, kernel="rbf", gamma="scale").fit(Xc_s)
    lof = LocalOutlierFactor(n_neighbors=20, contamination=0.50, novelty=True).fit(Xc_s)

    # ---------- predictions ----------
    Xev_s = scaler_un.transform(Xev)
    rf_pred = rf.predict(Xev); rf_proba = rf.predict_proba(Xev)[:, 1]
    lr_pred = lr.predict(scaler_lr.transform(Xev))
    if_pred = (iso.predict(Xev_s) == -1).astype(int)
    oc_pred = (ocsvm.predict(Xev_s) == -1).astype(int)
    lof_pred = (lof.predict(Xev_s) == -1).astype(int)
    smart = ((rev == 1) | (rf_proba >= 0.5) | ((lof_pred == 1) & (rf_proba >= 0.3))).astype(int)
    voting = ((rev == 1) | (rf_proba >= 0.5) | (lof_pred == 1)).astype(int)

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

    print("\n=== HttpParams 2015 — results on eval split ===")
    print(f"  {'Configuration':32} {'Prec':>7} {'Recall':>7} {'F1':>7} {'F2':>7}")
    for name, m in results.items():
        print(f"  {name:32} {m['precision']:7.2f} {m['recall']:7.2f} {m['f1']:7.2f} {m['f2']:7.2f}")

    # ---------- save models ----------
    joblib.dump(rf,        os.path.join(MODELS_DIR, "rf_hp.pkl"))
    joblib.dump(lr,        os.path.join(MODELS_DIR, "lr_hp.pkl"))
    joblib.dump(scaler_lr, os.path.join(MODELS_DIR, "scaler_lr_hp.pkl"))
    joblib.dump(iso,       os.path.join(MODELS_DIR, "isolation_forest_hp.pkl"))
    joblib.dump(ocsvm,     os.path.join(MODELS_DIR, "ocsvm_hp.pkl"))
    joblib.dump(lof,       os.path.join(MODELS_DIR, "lof_hp.pkl"))
    joblib.dump(scaler_un, os.path.join(MODELS_DIR, "scaler_unsup_hp.pkl"))
    print(f"\n[models] saved 7 .pkl files to {MODELS_DIR}")

    # ---------- json ----------
    n_atk = int(yev.sum()); n_cln = len(yev) - n_atk
    out = {
        "timestamp": datetime.now().isoformat(),
        "dataset": "HttpParams 2015 (Morzeux/HttpParamsDataset)",
        "note": "Parameter values wrapped as GET /?q=<payload>; 70/30 stratified "
                "split; Tier 3 trained on clean subset of train only. NOTE: the "
                "benign (norm) class of HttpParams is sourced from CSIC 2010.",
        "evaluation": {"samples": len(yev), "attacks": n_atk, "clean": n_cln,
                       "attack_ratio": round(n_atk / len(yev) * 100, 2)},
        "results": [{"model": k, **v} for k, v in results.items()],
    }
    with open(os.path.join(CHARTS_DIR, "httpparams_results.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print(f"[json] saved httpparams_results.json to {CHARTS_DIR}")

    # ---------- chart 1: metric bars ----------
    names = list(results.keys())
    P=[results[n]["precision"] for n in names]; R=[results[n]["recall"] for n in names]
    F1=[results[n]["f1"] for n in names]; F2=[results[n]["f2"] for n in names]
    short=[n.replace("Tier 1: ","").replace("Tier 2: ","").replace("Tier 3: ","") for n in names]
    xx=np.arange(len(names)); w=0.2
    fig, ax = plt.subplots(figsize=(15,7))
    ax.bar(xx-1.5*w,P,w,label="Precision"); ax.bar(xx-0.5*w,R,w,label="Recall")
    ax.bar(xx+0.5*w,F1,w,label="F1"); ax.bar(xx+1.5*w,F2,w,label="F2")
    ax.set_xticks(xx); ax.set_xticklabels(short,rotation=20,ha="right",fontsize=9)
    ax.set_ylabel("%"); ax.set_ylim(0,109)
    ax.set_title("HttpParams 2015 — Performance of tiers and hybrids", fontweight="bold")
    ax.legend(ncol=4,loc="lower center"); ax.grid(axis="y",ls="--",alpha=.4)
    for arr,off in [(P,-1.5*w),(R,-0.5*w),(F1,0.5*w),(F2,1.5*w)]:
        for i,v in enumerate(arr): ax.text(xx[i]+off,v+1,f"{v:.0f}",ha="center",fontsize=7)
    plt.tight_layout()
    plt.savefig(os.path.join(CHARTS_DIR,"httpparams_comprehensive_metrics.png"),dpi=150,bbox_inches="tight")
    plt.close()

    # ---------- chart 2: confusion matrices ----------
    cols=4; rows=(len(panels)+cols-1)//cols
    fig, axes = plt.subplots(rows,cols,figsize=(4*cols,3.4*rows)); axes=axes.flatten()
    for i,(name,pred) in enumerate(panels):
        cm=confusion_matrix(yev,pred,labels=[0,1]); m=results[name]
        ax=axes[i]; ax.imshow(cm,cmap="Blues")
        ax.set_xticks([0,1]); ax.set_yticks([0,1])
        ax.set_xticklabels(["Pred Clean","Pred Attack"],fontsize=9)
        ax.set_yticklabels(["True Clean","True Attack"],fontsize=9)
        ax.set_title(f"{name}\nF1={m['f1']:.1f}  F2={m['f2']:.1f}",fontsize=10)
        vmax=cm.max()
        for r in range(2):
            for c in range(2):
                ax.text(c,r,f"{cm[r,c]}",ha="center",va="center",
                        color="white" if cm[r,c]>vmax*0.5 else "black",fontsize=12,fontweight="bold")
    for j in range(len(panels),len(axes)): axes[j].axis("off")
    fig.suptitle(f"HttpParams 2015 — Confusion Matrices "
                 f"({len(yev):,} eval, {n_atk/len(yev)*100:.1f}% attack)",fontsize=14,fontweight="bold")
    plt.tight_layout(rect=[0,0,1,0.97])
    plt.savefig(os.path.join(CHARTS_DIR,"httpparams_confusion_matrices.png"),dpi=150,bbox_inches="tight")
    plt.close()

    # ---------- chart 3: tier vs hybrid ----------
    sel=["Tier 1: Regex Rules","Tier 2: RandomForest","Tier 3: Local Outlier Factor",
         "Simple Voting","Smart Consensus"]
    P=[results[n]["precision"] for n in sel]; R=[results[n]["recall"] for n in sel]
    F1=[results[n]["f1"] for n in sel]; F2=[results[n]["f2"] for n in sel]
    short=[s.replace("Tier 1: ","T1 ").replace("Tier 2: ","T2 ").replace("Tier 3: ","T3 ") for s in sel]
    xx=np.arange(len(sel)); w=0.2
    fig, ax = plt.subplots(figsize=(12,6))
    ax.bar(xx-1.5*w,P,w,label="Precision"); ax.bar(xx-0.5*w,R,w,label="Recall")
    ax.bar(xx+0.5*w,F1,w,label="F1"); ax.bar(xx+1.5*w,F2,w,label="F2")
    ax.axhline(90,ls="--",color="gray",alpha=.6)
    ax.set_xticks(xx); ax.set_xticklabels(short,rotation=15,ha="right")
    ax.set_ylabel("%"); ax.set_ylim(0,109)
    ax.set_title("HttpParams 2015 — Tier & Hybrid comparison", fontweight="bold")
    ax.legend(ncol=4,loc="lower center"); ax.grid(axis="y",ls="--",alpha=.4)
    for arr,off in [(P,-1.5*w),(R,-0.5*w),(F1,0.5*w),(F2,1.5*w)]:
        for i,v in enumerate(arr): ax.text(xx[i]+off,v+1,f"{v:.1f}",ha="center",fontsize=7)
    plt.tight_layout()
    plt.savefig(os.path.join(CHARTS_DIR,"httpparams_model_comparison.png"),dpi=150,bbox_inches="tight")
    plt.close()

    print(f"[charts] saved 3 PNG charts to {CHARTS_DIR}")
    print("\nDone. All HttpParams artifacts are under datasets/httpparams/ (models/ + charts/).")


if __name__ == "__main__":
    main()
