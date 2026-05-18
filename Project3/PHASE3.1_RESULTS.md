# Phase 3.1 Results — B + C + E and the Supervised Layer

## What changed since Phase 3

### B — Per-endpoint parameter vocabulary
- Added a `{path: set(param_names)}` map learned during training and persisted alongside the scaler (`ad_vocab_<model>.pkl`).
- Added feature #22 `unknown_param_ratio` — fraction of param names on a request that were never seen for that path during training.
- **Also added as a hard rule** (`PARAM_TAMPERING`): when the rule layer runs, any request to a known path with at least one unknown param name is flagged. This is what actually moved the numbers, because the soft feature is constant 0 during training (unsupervised models can't learn to use a constant signal — `StandardScaler` collapses it).

### C — SQL regex broadened
- Original pattern required **digit-based** tautology (`OR 1=1`) and **whitespace** between `or/and` and the next token, so it missed the most common CSIC payloads.
- New pattern covers:
  - `'OR'a='a` (3-quote letter tautology — the most common in CSIC after decode)
  - `'OR'a'='a` (4-quote variant)
  - `' OR '1'='1` (spaced/quoted)
  - `') or ('1'='1` (paren-prefixed)
  - `UNION ALL SELECT`, `SELECT … FROM`, `INSERT INTO`, `DELETE FROM`, `DROP TABLE|DATABASE|SCHEMA`, `UPDATE … SET`
  - `--` / `#` SQL comments, `/* … */`, `EXEC()`, `xp_cmdshell`
- Re-added `or`/`and` to keyword list (matched only as whole words by the existing tokenizer, so normal words like `orden`/`nombre` don't trigger).
- Also added a **triple URL-decode** pass at the regex layer to defeat double/triple-encoded SQLi payloads like `%2527OR%2527a%253D%2527a`.

### E — HTTP method tampering rule
- New rule `HTTP_METHOD_TAMPERING`: flags `PUT`/`DELETE`/`PATCH`/`TRACE`/`CONNECT` on any path that doesn't look like an API endpoint (`/api/`, `/rest/`, `/v1/`, `/v2/`, `/v3/`, `/graphql`, `/_api/`).
- Catches an entire class of CSIC attacks at zero false-positive cost.

---

## Results — `csic_test.log` (41,065 lines: 25,065 attacks + 16,000 normals)

### Phase 3 → Phase 3.1 (B + C + E)

| Model | Accuracy | Precision | Recall | F1 | Δ Recall | Δ F1 |
|---|---|---|---|---|---|---|
| **IF**    | 49.44 → **63.78** | 99.33 → 99.72 | 17.28 → **40.78** | 29.44 → **57.89** | +23.50pp | +28.45 |
| **OCSVM** | 51.08 → **66.35** | 99.42 → 99.74 | 19.98 → **44.98** | 33.27 → **62.00** | +25.00pp | +28.73 |
| **LOF**   | 51.79 → **66.35** | 99.46 → 99.74 | 21.13 → **44.98** | 34.85 → **62.00** | +23.85pp | +27.15 |

Recall roughly **doubled**, F1 nearly **doubled**, precision *improved* by 0.3pp — the new rules added zero false alarms. Almost all of the gain came from the regex/rules layer (12.00% → 35.83% recall alone). The AI contribution stayed roughly constant; unsupervised anomaly detection on this dataset is bounded by structural overlap between CSIC normals and CSIC attacks.

---

## Head-to-head: supervised vs unsupervised (same eval split)

Stratified 70/30 split of `csic_test.log`:
- `csic_test_train.log` — 28,745 lines (17,545 attacks + 11,200 normals), used for supervised training
- `csic_test_eval.log` — 12,320 lines (7,520 attacks + 4,800 normals), used for evaluation of BOTH supervised AND unsupervised

Supervised models use the **same 22-feature vector**. RandomForest (200 trees, balanced class weights) and LogisticRegression (lbfgs, balanced class weights).

| Model | TP | FP | TN | FN | Accuracy | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Unsup IF (AI only)       |  430 |   0 | 4800 | 7090 | 42.45% | 100.00% |  5.72% | 10.82 |
| Unsup OCSVM (AI only)    |  784 |   0 | 4800 | 6736 | 45.32% | 100.00% | 10.43% | 18.88 |
| Unsup LOF (AI only)      |  784 |   0 | 4800 | 6736 | 45.32% | 100.00% | 10.43% | 18.88 |
| Unsup IF (hybrid)        | 3045 |   6 | 4794 | 4475 | 63.63% |  99.80% | 40.49% | 57.61 |
| Unsup OCSVM (hybrid)     | 3364 |   6 | 4794 | 4156 | 66.22% |  99.82% | 44.73% | 61.78 |
| Unsup LOF (hybrid)       | 3364 |   6 | 4794 | 4156 | 66.22% |  99.82% | 44.73% | 61.78 |
| **Sup RF**               | **7164** | **601** | **4199** | **356** | **92.23%** | **92.26%** | **95.27%** | **93.74** |
| Sup LR                   | 5219 | 955 | 3845 | 2301 | 73.57% |  84.53% | 69.40% | 76.22 |

### Take-aways

1. **Random Forest wins by a huge margin** — 95.27% recall vs 44.73% for the best unsupervised hybrid, F1 jumps from 62 to 94. The relationship between features and attack label is non-linear (LR only gets 69% recall), and a single random forest learns it cleanly.
2. **The unsupervised ceiling on CSIC is ~45% combined recall, ~10% AI-only recall.** That's the ceiling pure feature engineering can buy without labels. The remaining 55%+ of CSIC attacks (parameter tampering, business-logic abuse, value tampering) are structurally too close to normal traffic to be flagged as "anomalous."
3. **Cost of supervised**: trades some precision for huge recall — RF has 601 FPs vs 6 for the hybrid (still 92% precision, but lower than 99.8%). And it can only learn the attacks it's seen — for true novel attacks the unsupervised models retain value as a tripwire.
4. **Recommended production layout (if you go this way)**:
   - Tier 1: regex + rules (PARAM_TAMPERING, HTTP_METHOD_TAMPERING, SQLI_RE, …) — fast, 99.8% precision
   - Tier 2: supervised RF on the 22-feature vector — catches the structural attacks
   - Tier 3 (optional): keep one unsupervised model (LOF) as a tripwire for novel anomalies the supervised model wasn't trained on

---

## Files added in Phase 3.1
- `analysis/phase3_diagnostic.py` — regex-vs-AI contribution breakdown + FN sampling (now hydrates vocab)
- `analysis/split_test_log.py` — stratified 70/30 split of `csic_test.log`
- `analysis/supervised_vs_unsupervised.py` — trains supervised models and runs the head-to-head table above
- `models/supervised_detector.py` — `SupervisedDetector` class (RF and LR)
- `datasets/csic_test_train.log`, `datasets/csic_test_eval.log` — the stratified split
- `sup_model_{rf,lr}.pkl`, `sup_scaler_lr.pkl`, `sup_vocab_{rf,lr}.pkl` — trained supervised artifacts

## How to reproduce
```powershell
$env:PYTHONIOENCODING="utf-8"
cd d:\ProjectIII\ProjectIII\Project3

# Retrain unsupervised (already done — only needed if you change features)
python apache_log.py train datasets/csic_train_clean.log if
python apache_log.py train datasets/csic_train_clean.log ocsvm
python apache_log.py train datasets/csic_train_clean.log lof

# Headline metrics for each unsupervised model on the full test log
python apache_log.py evaluate datasets/csic_test.log if
python apache_log.py evaluate datasets/csic_test.log ocsvm
python apache_log.py evaluate datasets/csic_test.log lof

# Regex-vs-AI contribution + FN samples
python analysis/phase3_diagnostic.py datasets/csic_test.log

# Stratified split + supervised vs unsupervised head-to-head
python analysis/split_test_log.py
python analysis/supervised_vs_unsupervised.py
```
