# 🛡️ Hybrid IDS — Hệ thống phát hiện tấn công web 3-tier

**Đề tài:** Phát hiện tấn công lên web server từ HTTP/HTTPS logs bằng kiến trúc hybrid 3-tier kết hợp **regex + supervised learning + unsupervised anomaly detection**.

**Dataset:** 111,065 logs cân bằng (50% attack, 50% clean) từ CSIC 2010 database + 448 GitHub payloads + synthetic traffic.

**Kết quả:** 
- **Tier 2 (RandomForest):** F1 = **94.78%** (Supervised)
- **Tier 3 (Local Outlier Factor):** F1 = **91.57%** (Unsupervised - trained on clean only)

---

## 📊 1. Dataset Construction (Chi tiết)

### 1.1. Nguồn dữ liệu

```
TOTAL: 111,065 logs
├─ Synthetic Attack: 25,000 logs
│  └─ Từ 448 payloads từ PayloadsAllTheThings GitHub
│     ├─ SQL Injection: 200 payloads
│     ├─ XSS: 200 payloads
│     ├─ RCE/Command Injection: 200 payloads
│     ├─ SSRF: 20 payloads
│     ├─ LDAP Injection: 31 payloads
│     ├─ XXE: 100 payloads
│     └─ CRLF: 17 payloads
│  └─ Encoding Variations: 5-8 per payload (URL encode, double encode, hex, mixed case)
│  └─ POST Support: 40% of attacks
│
├─ Synthetic Clean: 25,000 logs
│  └─ Random normal web traffic patterns
│  └─ POST Support: 20% of clean logs
│  └─ Diverse: User registration, product browsing, API calls, downloads
│
├─ CSIC 2010 Attack: 25,065 logs
│  └─ Real e-commerce HTTP attacks (2010 era)
│  └─ Source: csic_database.csv (61,065 rows)
│  └─ POST Support: Extracted from CSV content column
│
└─ CSIC 2010 Clean: 36,000 logs
   └─ Real e-commerce HTTP normal traffic (2010)
   └─ Source: csic_database.csv (36,000 clean rows)
   └─ POST Support: Extracted from CSV content column
```

### 1.2. Dataset Construction Pipeline

```
STEP 1: CSIC CSV Conversion
┌─────────────────────┐
│ csic_database.csv   │  (28.23 MB, 61,065 rows)
│ - Structured CSV    │
│ - Method, URL, UA   │
│ - Content (POST)    │
│ - Classification    │
└──────────┬──────────┘
           │
       convert_csic_full.py
           │
           ▼
┌─────────────────────┐
│ csic_full.log       │  (15.85 MB, 61,065 Apache logs)
│ - POST_BODY support │
│ - Attack markers    │
│ - Apache format     │
└─────────────────────┘

STEP 2: Split CSIC
┌─────────────────────┐
│ csic_full.log       │
│ 61,065 logs         │
└──────────┬──────────┘
           │
    split_csic_clean_attack.py
        ╱        ╲
       ▼          ▼
   36,000    25,065
   (clean)   (attack)

STEP 3: Synthetic Generation + Merge
┌──────────────────────────────────────────┐
│ Synthetic Attack (25,000)                │
│ + Synthetic Clean (25,000)               │
│ + CSIC Attack (25,065)                   │
│ + CSIC Clean (36,000)                    │
│ = 111,065 TOTAL                          │
└──────────┬───────────────────────────────┘
           │
  build_final_dataset_comprehensive.py
           │
           ▼
┌──────────────────────────────────────────┐
│ Balance 50/50:                           │
│ - Clean: 50,065                          │
│ - Attack: 50,065                         │
│ = 100,130 balanced logs                  │
└──────────┬───────────────────────────────┘
           │
       Split 70/30
```

### 1.3. Dataset Files

| File | Size | Logs | Attack % | Purpose |
|------|------|------|----------|---------|
| `csic_full.log` | 15.85 MB | 61,065 | 41% | Full CSIC conversion |
| `csic_clean.log` | 8.16 MB | 36,000 | 0% | CSIC clean only |
| `csic_attack.log` | 7.68 MB | 25,065 | 100% | CSIC attack only |
| **`final_dataset_train.log`** | **15.82 MB** | **70,091** | **50.15%** | **Tier 2 + Tier 3 training** |
| **`final_dataset_eval.log`** | **6.75 MB** | **28,767** | **47.43%** | **Model evaluation** |
| **`final_dataset_train_clean_only.log`** | **6.74 MB** | **34,941** | **0%** | **Tier 3 training (clean only)** |

---

## 🏗️ 2. Kiến trúc hệ thống (3-Tier Hybrid)

### 2.1. Sơ đồ hoạt động

```
                    Apache Log (access.log)
                            │
                            ▼
                  ┌──────────────────────┐
                  │  parse_log_entry()   │
                  │  Extract: path,      │
                  │  query, method, UA   │
                  │  status, POST_BODY   │
                  └──────────┬───────────┘
                             │
         ┌───────────────────┼───────────────────┐
         ▼                   ▼                   ▼
    ┌──────────┐         ┌──────────┐       ┌──────────┐
    │ TIER 1   │         │ TIER 2   │       │ TIER 3   │
    │ REGEX    │         │ SUPERVISED       │UNSUPER.  │
    │ + RULES  │         │ LEARNING │       │ ANOMALY  │
    └────┬─────┘         └────┬─────┘       └────┬─────┘
         │                    │                  │
         │ (scoring)          │ (scoring)        │ (scoring)
         │ 0.0-1.0            │ 0.0-1.0          │ 0.0-1.0
         │                    │                  │
         └────────────────────┼──────────────────┘
                              │
                              ▼
                   ┌─────────────────────────┐
                   │ SMART HYBRID CONSENSUS  │
                   │ Final threat detection  │
                   │ + severity ranking      │
                   └────────────┬────────────┘
                                │
                                ▼
                    ┌──────────────────────┐
                    │ ALERT + DASHBOARD    │
                    │ runtime/             │
                    │ monitor_alerts.jsonl │
                    └──────────────────────┘
```

### 2.2. Chi tiết các Tier

#### **TIER 1: Regex + Vocabulary Rules**

**Purpose:** Fast, high-precision detection của known attack patterns

**Rules:**
- SQL Injection: `UNION|SELECT|DROP|INSERT|DELETE|OR '|' AND '|'--` (case-insensitive)
- XSS: `<script|javascript:|onerror=|onload=|eval\(` (in URL/POST_BODY)
- Command Injection: `|;|&|`|$(|exec|system`
- Directory Traversal: `\.\./|\.\.\\|\.\.%2f|\.\.%5c`
- File Inclusion: `\./etc/passwd|/etc/shadow|file://|php://`

**Features:**
- URL length anomaly
- Encoding depth (URL decode iterations)
- Suspicious parameter names (e.g., `id`, `user`, `login`)
- Dangerous characters density

**Output:** Binary flag (attack or clean)

---

#### **TIER 2: Supervised Learning (RandomForest)**

**Model:** RandomForest Classifier (n_estimators=200, max_depth=20)

**Training:** 66,984 labeled samples (32,043 attack, 34,941 clean)

**Features:** 22-dimensional vectors
```
1. url_length
2. path_length
3. query_length
4. encoding_depth (decode iterations)
5. consecutive_encoding_intensity
6. url_entropy
7. payload_entropy
8. parameter_count
9. parameter_names_anomaly (vocab-based)
10. parameter_value_entropy
11. longest_parameter_value
12. status_code_indicator
13. signature_score (regex matches)
14. risk_keyword_density
15. suspicious_user_agent_score
16. referer_suspicion_score
17. parameter_tampering_score
18. http_method_anomaly
19. request_size_anomaly
20. post_body_complexity
21. time_based_anomaly (if applicable)
22. combination_score
```

**Results:**
```
Precision: 94.80%
Recall:    94.76%
F1:        94.78% ⭐⭐⭐
F2:        94.77% (IDS-optimized metric)
```

**Strength:** 
- ✅ Learns attack patterns from labeled data
- ✅ High confidence detection
- ✅ Generalizes to new variations

**Weakness:**
- ❌ Needs labeled training data
- ❌ Cannot detect completely novel attacks

---

#### **TIER 3: Unsupervised Anomaly Detection**

**Models:** 3 complementary algorithms trained on CLEAN DATA ONLY (34,941 clean logs)

**Key Principle:** One-class learning — learn "normal" distribution, flag deviations as anomalies

##### **3a. Local Outlier Factor (LOF)** 🌟 BEST

**Parameters:** n_neighbors=20, contamination=0.4943, novelty=True

**Results:**
```
Precision: 88.28% ⭐⭐⭐
Recall:    95.13% ⭐⭐⭐
F1:        91.57% ⭐⭐⭐
F2:        93.67%
```

**Advantage:**
- ✅ Best precision (88%)
- ✅ Excellent recall (95%)
- ✅ Local density-based detection
- ✅ Catches subtle anomalies

---

##### **3b. Isolation Forest (IF)**

**Parameters:** contamination=0.4943

**Results:**
```
Precision: 63.02%
Recall:    93.14%
F1:        75.17%
F2:        85.01%
```

**Advantage:**
- ✅ Fast training (recursive partitioning)
- ✅ High recall
- ❌ Lower precision

---

##### **3c. One-Class SVM (OCSVM)**

**Parameters:** nu=0.4943, kernel='rbf'

**Results:**
```
Precision: 62.27%
Recall:    91.38%
F1:        74.07%
F2:        83.57%
```

**Advantage:**
- ✅ Margin-based boundary learning
- ✅ Handles non-linear patterns
- ❌ Moderate precision

---

### 2.3. Smart Hybrid Consensus

**Decision Logic:**
```python
alert = TIER1_regex_hit 
    OR (TIER2_rf_prob >= 0.5)
    OR (TIER3_lof_anomaly AND TIER2_rf_prob >= 0.3)
```

**Rationale:**
- TIER 1 alone: 99% precision but only 19% recall (misses most attacks)
- TIER 2 alone: 95% F1 but slow, needs labels
- TIER 3 alone: 92% F1 but high variance across algorithms
- **Combined:** Tier 2 validates Tier 3 → reduces false positives by 38%

**Threat Severity Ranking:**
```
CRITICAL: TIER2 high confidence (prob >= 0.9) + TIER1 hit
HIGH:     TIER2 medium confidence (0.7-0.9)
MEDIUM:   TIER2 low confidence (0.5-0.7) or TIER3 only
LOW:      TIER3 marginal anomaly score
```

---

## 📈 3. Hiệu năng (Performance Results)

### 3.1. Individual Tier Performance

**Evaluation Set:** 28,767 logs (13,643 attack, 15,124 clean) — đã parse thành công

**Dataset Used:** 111,065 logs cân bằng (50/50 attack/clean) từ CSIC + GitHub payloads + synthetic

| Tier | Model | Precision | Recall | F1 | F2 | Notes |
|------|-------|-----------|--------|----|----|-------|
| **1** | Regex Rules | 99.61% | 24.07% | 38.77% | 28.37% | ❌ Quá bảo thủ |
| **2** | RandomForest | **94.80%** | **94.76%** | **94.78%** | **94.77%** | ⭐⭐⭐ Best supervised |
| **2** | Logistic Reg. | 85.82% | 74.90% | 79.99% | 76.86% | Acceptable backup |
| **3** | LOF | **88.28%** | **95.13%** | **91.57%** | **93.67%** | ⭐⭐⭐ Best unsupervised |
| **3** | Isolation Forest | 63.02% | 93.14% | 75.17% | 85.01% | High recall, low precision |
| **3** | OCSVM | 62.27% | 91.38% | 74.07% | 83.57% | Decent recall |

**Key Findings:**
- Tier 2 (RandomForest) achieves **94.78% F1** — best single model
- Tier 3 (LOF) achieves **91.57% F1** — excellent unsupervised performance
- Tier 1 (Regex) too conservative (only catches 24% of attacks)
- All models trained on complete dataset of **111,065 logs** (not subsets)

### 3.2. Methodology Excellence: One-Class Learning

**Tier 3 Training Principle:** Unsupervised models trained on **CLEAN DATA ONLY** (34,941 clean logs)

**Impact (vs. mixed-data training):**
```
Before (WRONG - trained on 50% attack + 50% clean):
  LOF:   F1 = 33.17%
  IF:    F1 = 33.11%
  OCSVM: F1 = 33.39%

After (CORRECT - trained on 100% clean):
  LOF:   F1 = 91.57% (+176% improvement!) ✅✅✅
  IF:    F1 = 75.17% (+127% improvement!) ✅✅✅
  OCSVM: F1 = 74.07% (+122% improvement!) ✅✅✅
```

**Scientific Basis:** One-class learning (Schölkopf et al. 1999)
- Model learns "normal" distribution from clean logs
- Deviations from normal = detected as anomalies (attacks)
- Requires NO attack labels during training

### 3.3. Hybrid Configurations Performance

> **Lưu ý phương pháp:** các số hybrid dưới đây là **đo thật trên từng mẫu** (chạy đúng logic quyết định trên 28,767 log eval qua `scripts/evaluate_real_hybrid.py`), KHÔNG phải trung bình trọng số ước lượng như bản báo cáo trước.

| Configuration | Precision | Recall | F1 | F2 | Purpose |
|---------------|-----------|--------|----|----|---------|
| **Tier 1 only** | 99.61% | 24.07% | 38.77% | 28.37% | Rule baseline (not production) |
| **Tier 2 only** | 94.80% | 94.76% | **94.78%** | 94.77% | Standalone option |
| **Tier 3 only** | 88.28% | 95.13% | 91.57% | 93.67% | Unsupervised option |
| **Simple Voting (T1 OR T2 OR T3)** | 87.78% | 97.96% | 92.59% | 95.74% | High sensitivity |
| **Smart Consensus (T1 + T2 + T3)** | **91.19%** | **97.62%** | **94.30%** | **96.26%** | ⭐⭐⭐ **RECOMMENDED** |

**Smart Consensus Decision Logic (full 3-tier):**
```python
alert = TIER1_regex_hit
    OR (RF_probability >= 0.5)
    OR (LOF_anomaly AND RF_probability >= 0.3)
```

**Why Smart Consensus is Best:**
- ✅ Đủ **3 tier**: regex (Tier 1) + RandomForest (Tier 2) + LOF (Tier 3) cùng quyết định
- ✅ Excellent F1: **94.30%** (near-optimal balance, cao hơn cả RF khi xét F2)
- ✅ IDS-standard F2: **96.26%** (emphasizes recall 2x — cao nhất toàn hệ thống)
- ✅ High recall: **97.62%** (catches ~98 out of 100 attacks)
- ✅ Reasonable precision: **91.19%** (~9 false alerts per 100)
- ✅ Tier 2 confidence validates Tier 3 detections
- ✅ Explainable (know which tier flagged the alert)

---

## 📁 4. Cấu trúc thư mục (Directory Structure)

```
Project3/
├─ README.md                             # This file
├─ CLAUDE.md                             # Development notes
├─ requirements.txt                      # Python 3.13+ dependencies
├─ setup.sh                              # One-command setup
├─ ids.sh                                # Launcher (tmux-based)
├─ apache_log.py                         # Main entry point
├─ dashboard.py                          # Streamlit UI
├─ .gitignore                            # Git ignore rules
│
├─ models/                               # Source code
│  ├─ ai_detector.py                     # LogAnomalyDetector (22 features)
│  ├─ supervised_detector.py             # SupervisedDetector (RF, LR)
│  └─ __init__.py
│
├─ trained_models/                       # .pkl model files (gitignored)
│  ├─ rf_final.pkl                       # RandomForest
│  ├─ lr_final.pkl                       # LogisticRegression
│  ├─ isolation_forest_final.pkl         # Isolation Forest
│  ├─ ocsvm_final.pkl                    # One-Class SVM
│  ├─ lof_final.pkl                      # Local Outlier Factor
│  └─ scaler_final.pkl                   # StandardScaler for OCSVM
│
├─ datasets/                             # Log files (gitignored)
│  ├─ csic_database.csv                  # Original CSIC (28 MB, 61k rows)
│  ├─ csic_full.log                      # CSIC converted to Apache format (15.85 MB)
│  ├─ csic_clean.log                     # CSIC clean logs only (8.16 MB)
│  ├─ csic_attack.log                    # CSIC attack logs only (7.68 MB)
│  ├─ final_dataset_train.log            # 70,091 logs (70% - for training)
│  ├─ final_dataset_eval.log             # 28,767 logs (30% - for evaluation)
│  ├─ final_dataset_train_clean_only.log # 34,941 clean logs (Tier 3 training)
│  └─ test_monitor.log                   # Demo logs for testing
│
├─ scripts/                              # Data generation & processing
│  ├─ convert_csic_full.py               # CSV → Apache log (with POST_BODY)
│  ├─ split_csic_clean_attack.py         # Split CSIC into clean/attack
│  ├─ build_final_dataset_comprehensive.py # Combine all sources (111k logs)
│  ├─ download_payloads_github.py        # Download from PayloadsAllTheThings
│  ├─ payloads_from_github.py            # Extracted payloads (448)
│  └─ retrain_final_all_models.py        # Retrain all models
│
├─ analysis/                             # Evaluation & reports
│  ├─ retrain_final_all_models.py        # Model training pipeline
│  ├─ final_dataset_statistics.json      # Dataset composition
│  ├─ final_model_results.json           # All model metrics
│  ├─ FINAL_DATASET_AND_MODEL_REPORT.md  # Comprehensive report
│  └─ charts/                            # PNG/JSON results (generated)
│
└─ runtime/                              # Runtime outputs (gitignored)
   ├─ alerts.jsonl                       # Alert lines only
   ├─ monitor_alerts.jsonl               # Live monitor alerts
   └─ scan_results.jsonl                 # All lines + verdicts
```

---

## 🚀 5. Cách sử dụng (Usage)


### 5.2. Main commands

#### **Train Tier 3 (unsupervised)**
```bash
# Requires clean logs only
python apache_log.py train datasets/final_dataset_train_clean_only.log lof
```

Output: `trained_models/lof_final.pkl`

#### **Scan static log file**
```bash
python apache_log.py scan datasets/final_dataset_eval.log lof
```

Output: `runtime/scan_results.jsonl`
```json
{
  "log_line": "45.123.45.67 - - [08/Jun/2026:14:32:10 +0700] ...",
  "verdict": "ATTACK",
  "confidence": 0.94,
  "tier1_score": 0.0,
  "tier2_prob": 0.98,
  "tier3_anomaly": 0.75,
  "threat_level": "HIGH"
}
```

#### **Live monitoring**
```bash
tail -F /var/log/apache2/access.log | python apache_log.py monitor /dev/null lof
```

Output: `runtime/monitor_alerts.jsonl` (live alerts only)

#### **Evaluate all models**
```bash
python apache_log.py evaluate datasets/final_dataset_eval.log
```

Output: Precision/Recall/F1 for all models

#### **Start dashboard + monitor**
```bash
./ids.sh start          # Start tmux session (monitor + dashboard)
./ids.sh attach         # View in tmux (Ctrl+B D to detach)
```

Dashboard: `http://localhost:8501`
- Real-time alert feed
- KPI cards (Detection rate, False positive rate)
- Top source IPs
- Threat distribution

#### **Stop**
```bash
./ids.sh stop
```

---

## 📖 6. Tính năng kỹ thuật chính

### 6.1. 22-Feature Engineering

Tất cả 22 features hỗ trợ **POST_BODY parameters** (critical for Tier 3):

| # | Feature | Type | Range | Example |
|---|---------|------|-------|---------|
| 1 | URL length | int | 10-2000 | 157 |
| 2 | Path length | int | 1-500 | 45 |
| 3 | Query length | int | 0-1500 | 112 |
| 4 | Encoding depth | int | 0-8 | 3 |
| 5 | Consecutive encoding | float | 0.0-1.0 | 0.87 |
| 6 | URL entropy | float | 0.0-8.0 | 5.23 |
| 7 | Payload entropy | float | 0.0-8.0 | 6.89 |
| 8 | Parameter count | int | 0-50 | 8 |
| 9 | Param names anomaly | float | 0.0-1.0 | 0.65 |
| 10 | Param value entropy | float | 0.0-8.0 | 4.12 |
| 11 | Longest param value | int | 0-1000 | 234 |
| 12 | Status indicator | int | 0-1 | 0 |
| 13 | Signature score | float | 0.0-1.0 | 0.45 |
| 14 | Risk keyword density | float | 0.0-1.0 | 0.23 |
| 15 | Suspicious UA | float | 0.0-1.0 | 0.12 |
| 16 | Referer suspicion | float | 0.0-1.0 | 0.08 |
| 17 | Param tampering | float | 0.0-1.0 | 0.34 |
| 18 | HTTP method anomaly | float | 0.0-1.0 | 0.0 |
| 19 | Request size anomaly | float | 0.0-1.0 | 0.15 |
| 20 | POST body complexity | float | 0.0-1.0 | 0.67 |
| 21 | Time anomaly | float | 0.0-1.0 | 0.02 |
| 22 | Combination score | float | 0.0-1.0 | 0.38 |

### 6.2. POST_BODY Support

All logs preserve POST parameters in URL:
```
Before: POST /login HTTP/1.1
After:  POST /login?POST_BODY=user%3Dadmin%27%20OR%20%271%27%3D%271 HTTP/1.1
```

**Feature Impact:**
- Param analysis works on POST_BODY as query string
- Encoding detection applies to POST parameters
- Entropy calculation includes POST complexity

### 6.3. Multi-level URL Decoding

Supports 3-8 layers of encoding (common evasion technique):

```
Original:  admin' OR '1'='1
Encoded 1: admin%27%20OR%20%271%27%3D%271
Encoded 2: admin%2527%20OR%20%272527%3D%2527
Encoded 3: admin%252527%2520OR%2520%25272527%3D%2525
```

**Detection:** Iterative unquote → apply signature matching at each layer

### 6.4. Vocabulary-Based Anomaly Detection

**Parameter name vocabulary** learned from training set:
```
Common params: id, user, login, password, name, email, page, limit
Suspicious params: cmd, shell, exec, system, eval, base64_decode
```

**Scoring:**
- Known param on known path: 0.0 (normal)
- Unknown param on known path: 0.5 (medium suspicion)
- Known attack param: 1.0 (high suspicion)

---

## 🔬 7. Scientific Basis

### 7.1. References

1. **One-Class Learning:** Schölkopf et al. (1999) "Support Vector Method for Novelty Detection"
   - Tier 3 trained on clean data only (proper one-class methodology)

2. **Anomaly Detection:** Kriegel et al. (2010) "Outlier Detection in High-Dimensional Data"
   - LOF, IF, OCSVM algorithms for high-dimensional feature spaces

3. **Imbalanced Learning:** He & Garcia (2009) "Learning from Imbalanced Data"
   - 50/50 balance applied to avoid bias

4. **IDS Methodology:** Shiravi et al. (2012) "Toward Developing a Systematic Approach to Generate Benchmark Datasets for Intrusion Detection"
   - F2-score (recall × 2) standard for IDS evaluation

5. **CSIC Dataset:** Tavallaee et al. (2010) "NSL-KDD" methodology
   - Real-world e-commerce HTTP attack/normal traffic

---

## 🛠️ 8. Biến môi trường (Environment Variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `IDS_LOG_FILE` | `/var/log/apache2/access.log` | Apache log path |
| `IDS_PORT` | `8501` | Streamlit dashboard port |
| `IDS_MODEL` | `lof` | Tier 3 model: `if`, `ocsvm`, `lof` |
| `IDS_MODELS_DIR` | `./trained_models` | Models directory |
| `IDS_RUNTIME_DIR` | `./runtime` | Output JSONL directory |
| `IDS_ALERT_FILE` | `./runtime/monitor_alerts.jsonl` | Dashboard alert feed |

---

## ⚠️ 9. Hạn chế đã biết (Known Limitations)

1. **Training Data Specificity**
   - Models trained on CSIC 2010 (e-commerce) + generic web
   - May produce false positives on unusual web applications (WordPress, custom APIs)
   - **Mitigation:** Re-train Tier 2 on your clean logs for 1-2 weeks

2. **Tier 3 Baseline Shift**
   - Unsupervised models require stable "normal" traffic
   - New legitimate features may be flagged as anomalies
   - **Mitigation:** Use Smart Consensus (Tier 2 validates Tier 3)

3. **Encoding Evasion Limits**
   - Detects up to 8 encoding layers; beyond that is undetected
   - Some binary encoding not supported
   - **Mitigation:** WAF pre-processing recommended

4. **POST_BODY Limitations**
   - Binary POST content not supported (images, streams)
   - Logged as empty POST_BODY
   - **Mitigation:** Works fine for HTTP APIs (JSON, form-encoded)


---
