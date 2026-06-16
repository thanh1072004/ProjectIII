#!/usr/bin/env python3
"""
CROSS-DATASET test: CSIC-trained main models (trained_models/*_final.pkl),
WITHOUT retraining, evaluated on the HttpParams 2015 dataset.

Mirrors scripts/csic_models_on_ecml.py exactly, only the eval file changes.
Reads datasets/httpparams/httpparams_all.log (already in Apache format with
the (Simulated-Attack) label marker). Read-only on models; writes only
datasets/httpparams/charts/csic_on_hp_*.
"""
import os, sys, io, re, json
import numpy as np
import joblib
from urllib.parse import urlparse, unquote, parse_qs
from datetime import datetime
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import (confusion_matrix, precision_score, recall_score,
                             f1_score, fbeta_score)

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "models")); sys.path.insert(0, PROJECT_ROOT)
from ai_detector import LogAnomalyDetector
import apache_log
apache_log.PATH_PARAM_VOCAB = {}

MODELS_DIR = os.path.join(PROJECT_ROOT, "trained_models")
EVAL_FILE  = os.path.join(PROJECT_ROOT, "datasets", "httpparams", "httpparams_all.log")
CHARTS_DIR = os.path.join(PROJECT_ROOT, "datasets", "httpparams", "charts")
os.makedirs(CHARTS_DIR, exist_ok=True)

LOG_RE = re.compile(
    r'(\S+) - - \[([^\]]+)\] "(\S+)\s+([^"]+)(?:\s+HTTP[^"]*)?"\s+(\d+)\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"')
_detector = LogAnomalyDetector(); _detector.path_param_vocab = {}

def metrics(y, pred):
    return {"precision": round(precision_score(y,pred,zero_division=0)*100,2),
            "recall": round(recall_score(y,pred,zero_division=0)*100,2),
            "f1": round(f1_score(y,pred,zero_division=0)*100,2),
            "f2": round(fbeta_score(y,pred,beta=2,zero_division=0)*100,2)}

def main():
    X,y,regex=[],[],[]
    print(f"Reading + featurizing {EVAL_FILE} ...")
    with open(EVAL_FILE,'r',errors='ignore') as f:
        for line in f:
            line=line.strip(); m=LOG_RE.match(line)
            if not m: continue
            ip,ts,method,url,status,size,referer,ua=m.groups()
            try: decoded=unquote(url)
            except Exception: decoded=url
            p=urlparse(decoded)
            try:
                feats=_detector.extract_features(p.path or "/", p.query or "", method, status, ua, referer)
            except Exception: continue
            X.append(feats); y.append(1 if "(Simulated-Attack)" in line else 0)
            pd={"path":p.path or "/","query":p.query or "",
                "params":parse_qs(p.query or "",keep_blank_values=True),
                "user_agent":ua,"method":method}
            regex.append(1 if len(apache_log.detect_rule_based(pd))>0 else 0)
    X=np.array(X,dtype=float); y=np.array(y); regex=np.array(regex)
    n=len(y); n_atk=int(y.sum()); n_cln=n-n_atk
    print(f"  HttpParams = {n} samples ({n_atk} attack, {n_cln} clean, {n_atk/n*100:.2f}% attack)")

    rf=joblib.load(os.path.join(MODELS_DIR,"rf_final.pkl"))
    lr=joblib.load(os.path.join(MODELS_DIR,"lr_final.pkl"))
    iso=joblib.load(os.path.join(MODELS_DIR,"isolation_forest_final.pkl"))
    ocsvm=joblib.load(os.path.join(MODELS_DIR,"ocsvm_final.pkl"))
    lof=joblib.load(os.path.join(MODELS_DIR,"lof_final.pkl"))
    scaler=joblib.load(os.path.join(MODELS_DIR,"scaler_final.pkl"))

    Xs=scaler.transform(X)
    rf_pred=rf.predict(X); rf_proba=rf.predict_proba(X)[:,1]
    lr_pred=lr.predict(X)
    if_pred=(iso.predict(X)==-1).astype(int)
    oc_pred=(ocsvm.predict(Xs)==-1).astype(int)
    lof_pred=(lof.predict(Xs)==-1).astype(int)
    smart=((regex==1)|(rf_proba>=0.5)|((lof_pred==1)&(rf_proba>=0.3))).astype(int)
    voting=((regex==1)|(rf_proba>=0.5)|(lof_pred==1)).astype(int)

    panels=[("Tier 1: Regex Rules",regex),("Tier 2: RandomForest",rf_pred),
            ("Tier 2: LogisticRegression",lr_pred),("Tier 3: Isolation Forest",if_pred),
            ("Tier 3: One-Class SVM",oc_pred),("Tier 3: Local Outlier Factor",lof_pred),
            ("Smart Consensus",smart),("Simple Voting",voting)]
    results={name:metrics(y,pred) for name,pred in panels}
    print("\n=== CSIC-trained models tested on HttpParams 2015 (no retraining) ===")
    print(f"  {'Configuration':32} {'Prec':>7} {'Recall':>7} {'F1':>7} {'F2':>7}")
    for name,mt in results.items():
        print(f"  {name:32} {mt['precision']:7.2f} {mt['recall']:7.2f} {mt['f1']:7.2f} {mt['f2']:7.2f}")

    out={"timestamp":datetime.now().isoformat(),
         "experiment":"CSIC-trained models -> HttpParams 2015 (cross-dataset, no retraining)",
         "models_source":"trained_models/*_final.pkl (CSIC)",
         "evaluation":{"file":"datasets/httpparams/httpparams_all.log","samples":n,
                       "attacks":n_atk,"clean":n_cln,"attack_ratio":round(n_atk/n*100,2)},
         "results":[{"model":k,**v} for k,v in results.items()]}
    with open(os.path.join(CHARTS_DIR,"csic_on_hp_results.json"),"w",encoding="utf-8") as f:
        json.dump(out,f,indent=2)
    print(f"\n[json] saved csic_on_hp_results.json")

    names=list(results.keys())
    P=[results[k]["precision"] for k in names]; R=[results[k]["recall"] for k in names]
    F1=[results[k]["f1"] for k in names]; F2=[results[k]["f2"] for k in names]
    short=[k.replace("Tier 1: ","").replace("Tier 2: ","").replace("Tier 3: ","") for k in names]
    xx=np.arange(len(names)); w=0.2
    fig,ax=plt.subplots(figsize=(15,7))
    ax.bar(xx-1.5*w,P,w,label="Precision"); ax.bar(xx-0.5*w,R,w,label="Recall")
    ax.bar(xx+0.5*w,F1,w,label="F1"); ax.bar(xx+1.5*w,F2,w,label="F2")
    ax.set_xticks(xx); ax.set_xticklabels(short,rotation=20,ha="right",fontsize=9)
    ax.set_ylabel("%"); ax.set_ylim(0,109)
    ax.set_title("CSIC-trained models tested on HttpParams 2015 (no retraining)",fontweight="bold")
    ax.legend(ncol=4,loc="lower center"); ax.grid(axis="y",ls="--",alpha=.4)
    for arr,off in [(P,-1.5*w),(R,-0.5*w),(F1,0.5*w),(F2,1.5*w)]:
        for i,v in enumerate(arr): ax.text(xx[i]+off,v+1,f"{v:.0f}",ha="center",fontsize=7)
    plt.tight_layout(); plt.savefig(os.path.join(CHARTS_DIR,"csic_on_hp_metrics.png"),dpi=150,bbox_inches="tight"); plt.close()

    cols=4; rows=(len(panels)+cols-1)//cols
    fig,axes=plt.subplots(rows,cols,figsize=(4*cols,3.4*rows)); axes=axes.flatten()
    for i,(name,pred) in enumerate(panels):
        cm=confusion_matrix(y,pred,labels=[0,1]); mt=results[name]
        ax=axes[i]; ax.imshow(cm,cmap="Blues"); ax.set_xticks([0,1]); ax.set_yticks([0,1])
        ax.set_xticklabels(["Pred Clean","Pred Attack"],fontsize=9)
        ax.set_yticklabels(["True Clean","True Attack"],fontsize=9)
        ax.set_title(f"{name}\nF1={mt['f1']:.1f}  F2={mt['f2']:.1f}",fontsize=10)
        vmax=cm.max()
        for r in range(2):
            for c in range(2):
                ax.text(c,r,f"{cm[r,c]}",ha="center",va="center",
                        color="white" if cm[r,c]>vmax*0.5 else "black",fontsize=12,fontweight="bold")
    for j in range(len(panels),len(axes)): axes[j].axis("off")
    fig.suptitle(f"CSIC models on HttpParams — Confusion Matrices ({n:,} samples, {n_atk/n*100:.1f}% attack)",
                 fontsize=14,fontweight="bold")
    plt.tight_layout(rect=[0,0,1,0.97]); plt.savefig(os.path.join(CHARTS_DIR,"csic_on_hp_confusion.png"),dpi=150,bbox_inches="tight"); plt.close()
    print(f"[charts] saved csic_on_hp_metrics.png + csic_on_hp_confusion.png")
    print("\nDone. CSIC models untouched; results under datasets/httpparams/charts/.")

if __name__=="__main__":
    main()
