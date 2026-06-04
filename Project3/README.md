# Hybrid IDS — Hệ thống phát hiện tấn công web 3-tier

Đồ án: phát hiện tấn công lên web server từ log Apache (`/var/log/apache2/access.log`)
bằng kiến trúc 3 tầng kết hợp **regex + supervised RandomForest + unsupervised LOF**,
đạt **F1 = 90.49 và F2 = 92.84** trên benchmark CSIC + generic web traffic.

---

## 1. Kiến trúc hệ thống

```
                  Log line (Apache access.log)
                              │
                              ▼
              ┌─────────────────────────────────┐
              │  parse_log_entry()              │
              │  → {path, query, method, ...}   │
              └────────────┬────────────────────┘
                           │
       ┌───────────────────┼─────────────────────┐
       ▼                   ▼                     ▼
┌─────────────┐  ┌───────────────────┐  ┌───────────────────┐
│ TIER 1      │  │ TIER 2            │  │ TIER 3            │
│ Regex +     │  │ Supervised        │  │ Unsupervised      │
│ Vocab rules │  │ RandomForest      │  │ LOF tripwire      │
│             │  │ (22 features)     │  │ (22 features)     │
│ Precision   │  │ Trained trên      │  │ Trained trên      │
│ 99.14%      │  │ 60K labeled       │  │ 30K clean         │
└──────┬──────┘  └─────────┬─────────┘  └─────────┬─────────┘
       │ regex_hit         │ sup_prob              │ lof_hit
       │ +0.45             │ +0.40×p               │ +0.20
       └───────────────────┴───────────────────────┘
                           │
                           ▼
        ┌──────────────────────────────────────────┐
        │  Smart Hybrid Consensus fusion           │
        │   alert = regex_hit                      │
        │       OR sup_prob >= 0.5                 │
        │       OR (lof_hit AND sup_prob >= 0.3)   │
        └──────────────────┬───────────────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │ Threat score → bucket   │
              │ CRITICAL/HIGH/MEDIUM/LOW│
              └────────────┬────────────┘
                           │
                ┌──────────┴──────────┐
                ▼                     ▼
      runtime/*.jsonl           dashboard.py (Streamlit)
```

## 2. Hiệu năng các mô hình

Đánh giá trên `datasets/combined_labeled_eval.log` (15,013 dòng — 5,413 attack, 9,600 clean):

| Cấu hình | Acc | Prec | Rec | F1 | F2* |
|---|---:|---:|---:|---:|---:|
| Regex only | 70.76% | **99.14%** | 19.07% | 31.98 | 22.74 |
| Hybrid LOF | 89.33% | 80.04% | 93.79% | 86.37 | 90.68 |
| Supervised RF | 93.29% | 91.29% | 89.99% | **90.63** | 90.24 |
| Full Hybrid (R OR RF OR LOF) | 89.66% | 78.74% | **97.71%** | 87.21 | **93.22** |
| **Smart Hybrid (Consensus)** ⭐ | 92.84% | 86.83% | 94.48% | **90.49** | **92.84** |

*F2 = 5·P·R / (4P + R) — chuẩn IDS, nhân hệ số 2 vào recall.*

→ **Smart Hybrid (Consensus)** là cấu hình production: F1 gần bằng RF (chênh 0.14đ),
F2 vượt RF 2.6 điểm, bỏ lọt attack ít hơn 45% (299 vs 542 FN).

Biểu đồ đầy đủ: [`analysis/charts/model_comparison.png`](analysis/charts/model_comparison.png),
[`confusion_matrices.png`](analysis/charts/confusion_matrices.png).

## 3. Cấu trúc thư mục

```
Project3/
├── apache_log.py             # Entry point: train/scan/evaluate/monitor
├── dashboard.py              # Streamlit UI đọc runtime/monitor_alerts.jsonl
├── setup.sh                  # Cài đặt 1 lệnh (venv + deps + giải nén models)
├── ids.sh                    # Launcher tmux: start/stop/status/attach/logs
├── requirements.txt          # Python dependencies
├── README.md                 # File này
├── .gitignore
│
├── models/                   # Source code các detector
│   ├── ai_detector.py        # Unsupervised: IF/OCSVM/LOF + 22 features + vocab
│   └── supervised_detector.py # Supervised: RandomForest, LogisticRegression
│
├── trained_models/           # 14 file .pkl (gitignored — train lại hoặc transfer)
│   ├── ad_{model,scaler,vocab}_{if,ocsvm,lof}.pkl
│   └── sup_{model,scaler,vocab}_{rf,lr}.pkl
│
├── datasets/                 # Log files (gitignored, build từ scripts/)
│   ├── csic_evaluated.log         # CSIC e-commerce raw (61K, từ CSV)
│   ├── csic_train_clean.log       # 20K clean cho unsupervised
│   ├── csic_test.log              # 41K mixed có label
│   ├── training_clean.log         # 10K generic web clean
│   ├── dataset_evaluated.log      # 4K generic mixed có label
│   ├── combined_train_clean.log   # 30K clean = csic + generic (unsup train)
│   ├── combined_labeled.log       # 75K labeled = clean + attacks (sup train)
│   ├── combined_labeled_{train,eval}.log  # 80/20 split
│   └── test_monitor.log           # 15 dòng demo (committed)
│
├── scripts/                  # Data generation scripts
│   ├── csv_to_apache_log.py       # CSIC CSV → Apache log format
│   ├── split_csic_log.py          # csic_evaluated → train+test split
│   ├── generate_clean_log.py      # Sinh generic web clean traffic
│   └── generate_real_dataset.py   # Sinh generic mixed (download payloads từ GitHub)
│
├── analysis/                 # Evaluation scripts + outputs
│   ├── build_combined_datasets.py # Trộn các dataset thành combined_*
│   ├── train_supervised_combined.py  # Train RF + LR trên combined labeled
│   ├── supervised_vs_unsupervised.py # Head-to-head comparison
│   ├── phase3_diagnostic.py       # Regex vs AI contribution breakdown
│   ├── split_test_log.py          # Stratified 70/30 split
│   └── charts/                    # PNG + JSON (gitignored, generated)
│
└── runtime/                  # Output JSONL (gitignored, truncate mỗi session)
    ├── alerts.jsonl                # Chỉ alerts (từ scan/analyze_log)
    ├── monitor_alerts.jsonl        # Live alerts (monitor mode)
    └── scan_results.jsonl          # Tất cả dòng kèm verdict (scan mode)
```

## 4. Cách dùng

### 4.1. Cài đặt nhanh trên VM Linux

```bash
git clone <repo>.git Project3
cd Project3
chmod +x setup.sh ids.sh
./setup.sh           # tạo .venv, cài deps, giải nén ids_models_for_vm.zip (nếu có)
./ids.sh start       # khởi động monitor + dashboard trong tmux
./ids.sh attach      # vào xem 2 pane (Ctrl+B D để rời)
```

Dashboard live tại `http://<VM-IP>:8501`.

### 4.2. CLI 4 chế độ

```bash
# Train unsupervised (IF/OCSVM/LOF) — cần file log sạch
python apache_log.py train datasets/combined_train_clean.log lof

# Scan log tĩnh, output runtime/scan_results.jsonl (tất cả dòng kèm verdict)
python apache_log.py scan datasets/csic_test.log lof

# Evaluate đa-mô hình + vẽ biểu đồ vào analysis/charts/
python apache_log.py evaluate datasets/combined_labeled_eval.log

# Monitor real-time từ stdin (đọc tail -F access.log)
tail -F /var/log/apache2/access.log | python apache_log.py monitor /dev/null lof
```

### 4.3. Train supervised (RandomForest)

```bash
# Trộn dataset (CSIC + generic) → combined_*
python analysis/build_combined_datasets.py

# Train RF + LR + đánh giá đa-mô hình
python analysis/train_supervised_combined.py
```

## 5. Trên VM cần làm gì?

1. `git pull` lấy code mới nhất.
2. Copy `ids_models_for_vm.zip` (đóng gói từ `trained_models/`) sang VM.
3. `./setup.sh` (tự cài deps + giải nén `.pkl`).
4. `sudo usermod -a -G adm $USER && exit` (cấp quyền đọc Apache log, rồi SSH lại).
5. `./ids.sh start` → mở browser tới `http://<VM-IP>:8501`.

Nếu muốn re-train trên log thực của bạn (recommended cho production):
```bash
# 1. Thu thập log sạch (chạy 1-2 tuần) -> datasets/my_clean.log
# 2. Train lại:
python apache_log.py train datasets/my_clean.log lof
# 3. Tạo attacks bằng sqlmap/nikto -> label -> train supervised
#    (xem analysis/build_combined_datasets.py cho template)
```

## 6. Tính năng kỹ thuật chính

- **22 features**: URL length/entropy, risk char count, encoding depth, signature score, param vocab anomaly, suspicious UA, …
- **PARAM_TAMPERING rule**: học `{path: set(param_names)}` từ training, flag khi gặp param lạ trên path đã biết.
- **HTTP_METHOD_TAMPERING rule**: PUT/DELETE/PATCH/TRACE/CONNECT trên non-API path → flag.
- **Multi-level URL decode** (3 vòng): bắt được payload triple-encoded như `%2527OR%2527a%253D%2527a`.
- **F2-score** chuẩn IDS (recall × 2 trọng số): bỏ lọt attack tệ hơn báo nhầm.
- **Smart Hybrid Consensus**: LOF chỉ được tin khi RF cũng nghi ngờ → giảm 38% FP của LOF.
- **Streamlit dashboard** auto-refresh 2s: KPI cards, alert feed, top-IP, threat distribution.

## 7. Biến môi trường

| Biến | Mặc định | Tác dụng |
|---|---|---|
| `IDS_LOG_FILE` | `/var/log/apache2/access.log` | Đường dẫn Apache log cho `ids.sh start` |
| `IDS_PORT` | `8501` | Port Streamlit dashboard |
| `IDS_MODEL` | `lof` | Unsupervised tripwire: `if`/`ocsvm`/`lof` |
| `IDS_MODELS_DIR` | `<project>/trained_models` | Thư mục chứa `.pkl` |
| `IDS_RUNTIME_DIR` | `<project>/runtime` | Thư mục output JSONL |
| `IDS_ALERT_FILE` | `runtime/monitor_alerts.jsonl` | File dashboard đọc |
| `IDS_NO_APT` | `0` | Set `1` để bỏ qua `apt-get install` |

## 8. Hạn chế đã biết

- Model học pattern CSIC + generic, **gặp web app rất khác** (ví dụ WordPress) có thể báo nhầm
  cho đến khi re-train trên log thật của bạn.
- LOF một mình có precision thấp (80%) — nên đã thiết kế Smart Consensus để LOF chỉ fire
  khi RF cũng nghi ngờ.
- `monitor_alerts.jsonl` truncate mỗi lần `monitor` khởi động (intentional cho dashboard).
  Nếu cần tích luỹ lâu dài, đổi mode `"w"` → `"a"` trong `apache_log.py:monitor_realtime`.

## 9. License

Dự án học thuật — sử dụng tự do cho mục đích nghiên cứu/giáo dục.
