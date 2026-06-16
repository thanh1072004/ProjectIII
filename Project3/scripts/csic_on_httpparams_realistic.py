#!/usr/bin/env python3
"""
Realistic cross-test: inject HttpParams payloads into REAL CSIC-style request
templates (real path + real parameter names, payload placed inside ONE
parameter value -- exactly how a real web attack looks), then evaluate the
CSIC-trained models with NO retraining.

Goal: show that the Tier-3 one-class collapse seen with the bare "/?q=<value>"
wrapping was an artifact of request STRUCTURE, not of content -- with a
realistic request shape the one-class tier recovers on the benign class.

Read-only on models. Writes datasets/httpparams/charts/csic_on_hp_realistic_*.
"""
import os, sys, io, re, json, random, csv
import numpy as np, joblib
import urllib.parse
from urllib.parse import urlparse, unquote, parse_qs
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import (confusion_matrix, precision_score, recall_score,
                             f1_score, fbeta_score)

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
csv.field_size_limit(10**7)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "models"))
sys.path.insert(0, PROJECT_ROOT)
from ai_detector import LogAnomalyDetector
import apache_log
apache_log.PATH_PARAM_VOCAB = {}

MODELS_DIR = os.path.join(PROJECT_ROOT, "trained_models")
CSIC_CLEAN = os.path.join(PROJECT_ROOT, "datasets", "csic_clean.log")
HP_CSV     = os.path.join(PROJECT_ROOT, "datasets", "httpparams", "payload_full.csv")
CHARTS_DIR = os.path.join(PROJECT_ROOT, "datasets", "httpparams", "charts")
LOG_RE = re.compile(
    r'(\S+) - - \[([^\]]+)\] "(\S+)\s+([^"]+)(?:\s+HTTP[^"]*)?"\s+(\d+)\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"')
_det = LogAnomalyDetector()
_det.path_param_vocab = {}
random.seed(42)


def metrics(y, pred):
    return {"precision": round(precision_score(y, pred, zero_division=0) * 100, 2),
            "recall":    round(recall_score(y, pred, zero_division=0) * 100, 2),
            "f1":        round(f1_score(y, pred, zero_division=0) * 100, 2),
            "f2":        round(fbeta_score(y, pred, beta=2, zero_division=0) * 100, 2)}


def main():
    # 1) Build realistic CSIC templates: (method, path_raw, [[name, value], ...])
    templates = []
    with open(CSIC_CLEAN, "r", errors="ignore") as f:
        for line in f:
            m = LOG_RE.match(line.strip())
            if not m:
                continue
            method, url = m.group(3), m.group(4)
            if "?" not in url:
                continue
            path_raw, query_raw = url.split("?", 1)
            pairs = [kv.split("=", 1) for kv in query_raw.split("&") if "=" in kv]
            if pairs:
                templates.append((method, path_raw, pairs))
            if len(templates) >= 20000:
                break
    print(f"Loaded {len(templates)} CSIC request templates")

    # 2) Inject each HttpParams payload into a template (payload -> ONE param value)
    X, y, regex = [], [], []
    n_norm = n_anom = 0
    with open(HP_CSV, "r", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            lab = (row.get("label") or "").strip().lower()
            if lab not in ("norm", "anom"):
                continue
            payload = row.get("payload", "") or ""
            is_atk = 1 if lab == "anom" else 0
            method, path_raw, pairs = random.choice(templates)
            pairs = [list(p) for p in pairs]
            j = random.randrange(len(pairs))
            pairs[j][1] = urllib.parse.quote(payload, safe="")
            new_q = "&".join(f"{k}={v}" for k, v in pairs)
            full = f"{path_raw}?{new_q}"
            try:
                dec = unquote(full)
            except Exception:
                dec = full
            p = urlparse(dec)
            try:
                feats = _det.extract_features(p.path or "/", p.query or "", method,
                                              "200", "Mozilla/5.0", "-")
            except Exception:
                continue
            X.append(feats); y.append(is_atk)
            pd = {"path": p.path or "/", "query": p.query or "",
                  "params": parse_qs(p.query or "", keep_blank_values=True),
                  "user_agent": "Mozilla/5.0", "method": method}
            regex.append(1 if len(apache_log.detect_rule_based(pd)) > 0 else 0)
            n_norm += (is_atk == 0); n_anom += (is_atk == 1)

    X = np.array(X, dtype=float); y = np.array(y); regex = np.array(regex)
    n = len(y); n_atk = int(y.sum())
    print(f"Built {n} realistic requests (norm={n_norm}, anom={n_anom}, "
          f"{n_atk/n*100:.2f}% attack)")

    # 3) CSIC models (mirror evaluate_real_hybrid)
    rf     = joblib.load(os.path.join(MODELS_DIR, "rf_final.pkl"))
    lr     = joblib.load(os.path.join(MODELS_DIR, "lr_final.pkl"))
    iso    = joblib.load(os.path.join(MODELS_DIR, "isolation_forest_final.pkl"))
    ocsvm  = joblib.load(os.path.join(MODELS_DIR, "ocsvm_final.pkl"))
    lof    = joblib.load(os.path.join(MODELS_DIR, "lof_final.pkl"))
    scaler = joblib.load(os.path.join(MODELS_DIR, "scaler_final.pkl"))
    Xs = scaler.transform(X)
    rf_pred = rf.predict(X); rf_proba = rf.predict_proba(X)[:, 1]; lr_pred = lr.predict(X)
    if_pred = (iso.predict(X) == -1).astype(int)
    oc_pred = (ocsvm.predict(Xs) == -1).astype(int)
    lof_pred = (lof.predict(Xs) == -1).astype(int)
    smart = ((regex == 1) | (rf_proba >= 0.5) | ((lof_pred == 1) & (rf_proba >= 0.3))).astype(int)
    voting = ((regex == 1) | (rf_proba >= 0.5) | (lof_pred == 1)).astype(int)
    panels = [("Tier 1: Regex Rules", regex), ("Tier 2: RandomForest", rf_pred),
              ("Tier 2: LogisticRegression", lr_pred), ("Tier 3: Isolation Forest", if_pred),
              ("Tier 3: One-Class SVM", oc_pred), ("Tier 3: Local Outlier Factor", lof_pred),
              ("Smart Consensus", smart), ("Simple Voting", voting)]
    results = {name: metrics(y, pred) for name, pred in panels}

    print("\n=== CSIC models on HttpParams payloads in REALISTIC CSIC-style requests ===")
    print(f"  {'Configuration':32} {'Prec':>7} {'Recall':>7} {'F1':>7} {'F2':>7}  (TN, FP)")
    for name, pred in panels:
        cm = confusion_matrix(y, pred, labels=[0, 1]); mt = results[name]
        print(f"  {name:32} {mt['precision']:7.2f} {mt['recall']:7.2f} {mt['f1']:7.2f} "
              f"{mt['f2']:7.2f}  (TN={cm[0,0]}, FP={cm[0,1]})")

    with open(os.path.join(CHARTS_DIR, "csic_on_hp_realistic_results.json"), "w", encoding="utf-8") as f:
        json.dump({"experiment": "CSIC models -> HttpParams payloads in realistic CSIC-style requests",
                   "evaluation": {"samples": n, "attacks": n_atk, "clean": n - n_atk,
                                  "attack_ratio": round(n_atk / n * 100, 2)},
                   "results": [{"model": k, **v} for k, v in results.items()]}, f, indent=2)

    # chart: metric bars
    names = list(results.keys())
    P = [results[k]["precision"] for k in names]; R = [results[k]["recall"] for k in names]
    F1 = [results[k]["f1"] for k in names]; F2 = [results[k]["f2"] for k in names]
    short = [k.replace("Tier 1: ", "").replace("Tier 2: ", "").replace("Tier 3: ", "") for k in names]
    xx = np.arange(len(names)); w = 0.2
    fig, ax = plt.subplots(figsize=(15, 7))
    ax.bar(xx-1.5*w, P, w, label="Precision"); ax.bar(xx-0.5*w, R, w, label="Recall")
    ax.bar(xx+0.5*w, F1, w, label="F1"); ax.bar(xx+1.5*w, F2, w, label="F2")
    ax.set_xticks(xx); ax.set_xticklabels(short, rotation=20, ha="right", fontsize=9)
    ax.set_ylabel("%"); ax.set_ylim(0, 109)
    ax.set_title("CSIC models on HttpParams payloads in REALISTIC requests (no retraining)", fontweight="bold")
    ax.legend(ncol=4, loc="lower center"); ax.grid(axis="y", ls="--", alpha=.4)
    for arr, off in [(P,-1.5*w),(R,-0.5*w),(F1,0.5*w),(F2,1.5*w)]:
        for i, v in enumerate(arr):
            ax.text(xx[i]+off, v+1, f"{v:.0f}", ha="center", fontsize=7)
    plt.tight_layout(); plt.savefig(os.path.join(CHARTS_DIR, "csic_on_hp_realistic_metrics.png"), dpi=150, bbox_inches="tight"); plt.close()

    # confusion grid
    fig, axes = plt.subplots(2, 4, figsize=(16, 7)); axes = axes.flatten()
    for i, (name, pred) in enumerate(panels):
        cm = confusion_matrix(y, pred, labels=[0, 1]); mt = results[name]
        ax = axes[i]; ax.imshow(cm, cmap="Blues"); ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
        ax.set_xticklabels(["Pred Clean", "Pred Attack"], fontsize=8)
        ax.set_yticklabels(["True Clean", "True Attack"], fontsize=8)
        ax.set_title(f"{name}\nF1={mt['f1']:.1f} F2={mt['f2']:.1f}", fontsize=9)
        vmax = cm.max()
        for r in range(2):
            for c in range(2):
                ax.text(c, r, f"{cm[r,c]}", ha="center", va="center",
                        color="white" if cm[r, c] > vmax*0.5 else "black", fontsize=11, fontweight="bold")
    fig.suptitle(f"CSIC models on HttpParams (realistic requests) — {n:,} samples, {n_atk/n*100:.1f}% attack",
                 fontsize=13, fontweight="bold")
    plt.tight_layout(rect=[0, 0, 1, 0.96]); plt.savefig(os.path.join(CHARTS_DIR, "csic_on_hp_realistic_confusion.png"), dpi=150, bbox_inches="tight"); plt.close()
    print(f"\n[saved] csic_on_hp_realistic_* in {CHARTS_DIR}")


if __name__ == "__main__":
    main()
