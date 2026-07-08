# Bảng lệnh — Hybrid 3-Tier Web IDS

> Ghi chú chung
> - Các lệnh `python3 ...` chạy thủ công cần **bật virtualenv trước**: `source .venv/bin/activate`
>   (Riêng `./ids.sh` tự dùng `.venv/bin/python`, không cần bật thủ công.)
> - `model_type` cho tripwire không giám sát: **`if` | `ocsvm` | `lof`** (mặc định `if`; monitor tự nâng lên `lof`).
> - **Monitor đọc từ `stdin`** → luôn phải `tail ... | python3 apache_log.py monitor ...`.

---

## 1. Cài đặt môi trường (chạy 1 lần trên VM)

```bash
chmod +x setup.sh ids.sh          # cấp quyền chạy (lần đầu)
./setup.sh                        # tạo .venv, cài deps, giải nén models, check quyền log

# Tuỳ chọn qua biến môi trường:
IDS_LOG_FILE=/path/to/access.log ./setup.sh   # dùng log khác mặc định
IDS_NO_APT=1 ./setup.sh                        # bỏ qua apt-get (khi không có sudo)
```

---

## 2. Train lại toàn bộ model (sinh *_final.pkl)

```bash
source .venv/bin/activate
python3 scripts/retrain_final_all_models.py
```
Sinh ra trong `trained_models/`: `rf_final.pkl`, `lr_final.pkl`, `lr_scaler_final.pkl`,
`isolation_forest_final.pkl`, `ocsvm_final.pkl`, `lof_final.pkl`, `scaler_final.pkl`
và ghi kết quả `analysis/final_model_results.json`.

---

## 3. Chạy IDS (monitor + dashboard) — cách gọn qua `./ids.sh`

```bash
./ids.sh start      # khởi động monitor (pane trái) + dashboard (pane phải) trong tmux
./ids.sh status     # xem trạng thái: session, log, port, số alert
./ids.sh attach     # vào xem 2 pane trực tiếp (Ctrl+B rồi D để rời, vẫn chạy nền)
./ids.sh logs       # tail runtime/monitor_alerts.jsonl
./ids.sh restart    # stop + start
./ids.sh stop       # dừng tất cả
./ids.sh help       # in hướng dẫn

# Tuỳ biến qua biến môi trường:
IDS_PORT=9000 ./ids.sh start                 # đổi port dashboard (mặc định 8501)
IDS_LOG_FILE=~/access.log ./ids.sh start     # đổi file log theo dõi
IDS_MODEL=ocsvm ./ids.sh start               # đổi tripwire (lof|if|ocsvm, mặc định lof)
```

---

## 4. Chạy monitor thủ công qua `apache_log.py` (không dùng tmux)

Monitor đọc từ stdin, nên **pipe `tail` vào**. Tham số file (`/dev/null`) chỉ là placeholder.

```bash
source .venv/bin/activate

# Theo dõi access.log thật của Apache (follow logrotate với -F):
tail -F /var/log/apache2/access.log | python3 apache_log.py monitor /dev/null lof

# Chỉ theo dõi các dòng MỚI kể từ bây giờ (bỏ qua lịch sử):
tail -n0 -f /var/log/apache2/access.log | python3 apache_log.py monitor /dev/stdin lof

# Đổi tripwire sang isolation forest / one-class svm:
tail -F /var/log/apache2/access.log | python3 apache_log.py monitor /dev/null if
tail -F /var/log/apache2/access.log | python3 apache_log.py monitor /dev/null ocsvm
```

---

## 5. Chế độ SCAN — quét 1 file log có sẵn (batch, không realtime)

```bash
source .venv/bin/activate
python3 apache_log.py scan <logfile> [model_type]

# Ví dụ:
python3 apache_log.py scan datasets/final_dataset_eval.log lof
python3 apache_log.py scan datasets/csic_attack.log lof
```
Chạy đủ 3 tier (regex + supervised RF nếu có + unsupervised) trên toàn bộ file.

---

## 6. Chế độ EVALUATE — đo metrics + vẽ biểu đồ so sánh

```bash
source .venv/bin/activate
python3 apache_log.py evaluate <logfile>

# Ví dụ:
python3 apache_log.py evaluate datasets/final_dataset_eval.log
```
Tự nạp tất cả model có sẵn, đánh giá song song, in bảng + vẽ chart so sánh.

---

## 7. Chạy demo traffic (cần một web server trả 200 ở `$BASE`, mặc định http://localhost)

Mở monitor ở **Terminal 1** (mục 3 hoặc 4), rồi bắn traffic ở **Terminal 2**:

```bash
bash demo_ids.sh      # bắn 10 request TẤN CÔNG  -> monitor phải hiện 10 alert
bash demo_clean.sh    # bắn 10 request SẠCH      -> monitor phải im lặng (0 alert)

# Tuỳ biến:
BASE=http://localhost:8080 bash demo_ids.sh    # đổi địa chỉ đích
DELAY=0.3 bash demo_clean.sh                    # đổi khoảng nghỉ giữa các request
```

---

## 8. Dashboard Streamlit (nếu chạy riêng, không qua ids.sh)

```bash
source .venv/bin/activate
streamlit run dashboard.py \
    --server.headless true \
    --server.address 0.0.0.0 \
    --server.port 8501 \
    --browser.gatherUsageStats false
# Mở: http://<VM-IP>:8501  (local: http://localhost:8501)
```

---

## 9. Dựng lại dataset (chỉ khi cần build lại dữ liệu từ nguồn)

```bash
source .venv/bin/activate
python3 scripts/convert_csic_full.py                   # CSIC csv -> datasets/csic_full.log (đã fix double HTTP/1.1)
python3 scripts/split_csic_clean_attack.py             # tách csic_full -> csic_clean.log + csic_attack.log
python3 scripts/build_final_dataset_comprehensive.py   # build final_dataset_train*.log + final_dataset_eval.log
python3 scripts/convert_ecml.py                        # ECML/PKDD csv -> log (thí nghiệm cross-dataset)
```

---

## 10. Sinh lại biểu đồ / số liệu cho báo cáo (analysis/charts)

```bash
source .venv/bin/activate
python3 scripts/evaluate_real_hybrid.py                # số hybrid/consensus -> analysis/tier_and_hybrid_results.json
python3 scripts/generate_confusion_matrices.py         # analysis/charts/confusion_matrices.png
python3 scripts/generate_comprehensive_comparison.py   # biểu đồ so sánh tổng hợp
python3 scripts/generate_feature_importance.py         # biểu đồ feature importance
python3 scripts/create_tier_comparison_chart.py        # biểu đồ so sánh theo tier
```

---

## 11. Thí nghiệm cross-dataset (phần mở rộng — cần dữ liệu ECML/HttpParams)

```bash
source .venv/bin/activate
python3 scripts/ecml_experiment.py                 # train+test trên ECML/PKDD 2007
python3 scripts/httpparams_experiment.py           # train+test trên HttpParams 2015
python3 scripts/csic_models_on_ecml.py             # model CSIC test chéo trên ECML
python3 scripts/csic_models_on_httpparams.py       # model CSIC test chéo trên HttpParams
python3 scripts/csic_on_httpparams_realistic.py    # biến thể realistic
python3 scripts/download_payloads_github.py        # tải payload tấn công từ GitHub
python3 scripts/payloads_from_github.py            # xử lý payload đã tải
```

---

## Thứ tự chạy điển hình (end-to-end trên VM)

```bash
# 1) Cài đặt
./setup.sh

# 2) (nếu chưa có model) train
python3 scripts/retrain_final_all_models.py

# 3) Khởi động IDS
./ids.sh start
./ids.sh status

# 4) Demo (terminal khác)
bash demo_ids.sh
bash demo_clean.sh

# 5) Xem alert / dashboard
./ids.sh logs
#   dashboard: http://<VM-IP>:8501

# 6) Dừng
./ids.sh stop
```
