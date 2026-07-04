# Installation & Run Guide — Hybrid 3-Tier Web IDS

A web intrusion detection system based on Apache logs, combining 3 tiers:
**Tier 1** (regex/signature rules) · **Tier 2** (Random Forest, supervised learning) ·
**Tier 3** (Local Outlier Factor, one-class learning) + the **Smart Consensus** mechanism.

---

## 1. System Requirements

- **Python 3.10+** (recommended; 3.8/3.9 still work).
- `pip` and `venv`.
- (Optional, for real-time use) **Apache2** writing access logs, and **tmux**.
- OS: Linux (recommended, to monitor `access.log`) — Windows can still run `scan` mode.

---

## 2. Minimal Directory Structure

After extracting, the directory must contain exactly the following files:

```
├── apache_log.py                 # main entry point: scan | monitor | evaluate
├── dashboard.py                  # Streamlit dashboard (optional)
├── requirements.txt              # required libraries
├── setup.sh   ids.sh             # environment setup & launch scripts (optional)
├── demo_ids.sh  demo_clean.sh    # demo scripts (optional)
├── models/
│   ├── ai_detector.py            # Tier 1 vocab + Tier 3 + 22-feature extraction
│   └── supervised_detector.py    # Tier 2
└── trained_models/               # trained MODELS
    ├── rf_final.pkl
    ├── lr_final.pkl
    ├── lof_final.pkl
    ├── isolation_forest_final.pkl
    ├── ocsvm_final.pkl
    └── scaler_final.pkl
```

## 3. Installation

### Option A — Automatic (Linux, recommended)
```bash
chmod +x setup.sh ids.sh
./setup.sh
```
`setup.sh` will: check Python, create `.venv`, install `requirements.txt`, check
the models in `trained_models/`, and check the Apache log read permission.

### Option B — Manual (any OS)
```bash
cd Project3
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## 4. Running the System

> `source .venv/bin/activate`.

### 4.1. Real-time monitor on Apache access.log
Watch the real Apache log and print an alert the moment an attack occurs:
```bash
tail -F /var/log/apache2/access.log | python3 apache_log.py monitor /dev/null lof
```
- `lof` = the Tier 3 tripwire model (can be changed to `if` or `ocsvm`).
- Alerts are written to `runtime/monitor_alerts.jsonl` (auto-created).


### 4.2. Scan a static log file
```bash
python apache_log.py scan duong_dan_toi_file_log lof
```
Results are written to `runtime/scan_results.jsonl` (every line) and `runtime/alerts.jsonl` (attacks only).

### 4.4. Visual dashboard (optional)
Open another terminal (with venv activated):
```bash
streamlit run dashboard.py
```
The dashboard reads `runtime/monitor_alerts.jsonl` and auto-refreshes. Open a browser:
`http://localhost:8501`.


### 4.5. Easiest way — run monitor + dashboard together (Linux + tmux)
```bash
./ids.sh start      # start monitor (left) + dashboard (right) in tmux
./ids.sh attach     # view the 2 panes (Ctrl+B then D to detach, keeps running)
./ids.sh status     # show status
./ids.sh stop       # stop everything
```

## 5. Quick check (smoke test)

Run the demo to make sure the system works (requires Apache running on `localhost`):
# Another terminal:
```bash
chmod +x demo_ids.sh
./demo_ids.sh
```

---

## 6. (Optional) Retrain the models

Only needed when you want to regenerate the `*_final.pkl` files. Requires 3 data files
present in `datasets/`:
```
datasets/final_dataset_train.log
datasets/final_dataset_train_clean_only.log
datasets/final_dataset_eval.log
```
Run:
```bash
python scripts/retrain_final_all_models.py
```
The script trains all 5 models (RF, LR, IF, OCSVM, LOF) + scaler and saves them to
`trained_models/` with the exact `*_final.pkl` names that the system loads.
---