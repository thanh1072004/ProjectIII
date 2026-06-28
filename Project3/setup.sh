#!/usr/bin/env bash
# ============================================================================
# IDS Setup script — chạy 1 lần trên VM Linux để chuẩn bị môi trường.
#
#   - Kiểm tra Python 3 (>= 3.10)
#   - Tạo virtualenv tại .venv
#   - Cài tất cả dependencies từ requirements.txt
#   - Giải nén ids_models_for_vm.zip (nếu có) để lấy các file .pkl
#   - Kiểm tra quyền đọc /var/log/apache2/access.log
#   - Cài tmux (cần cho ids.sh)
#
# Cách dùng:
#   chmod +x setup.sh
#   ./setup.sh
#
# Biến môi trường tuỳ chọn:
#   IDS_LOG_FILE=/path/to/access.log   (mặc định /var/log/apache2/access.log)
#   IDS_NO_APT=1                       (bỏ qua apt-get install, dùng khi không có sudo)
# ============================================================================

set -e

# ---------- helpers ----------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
say()  { printf "${CYAN}[setup]${NC} %s\n" "$*"; }
ok()   { printf "${GREEN}  ✓${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}  ⚠${NC} %s\n" "$*"; }
err()  { printf "${RED}  ✗${NC} %s\n" "$*" >&2; }
die()  { err "$*"; exit 1; }

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

IDS_LOG_FILE="${IDS_LOG_FILE:-/var/log/apache2/access.log}"
IDS_NO_APT="${IDS_NO_APT:-0}"

echo
say "==================================================="
say "  Hybrid IDS — Setup script"
say "  Project dir: $PROJECT_DIR"
say "==================================================="
echo

# ---------- 1. Python 3 ----------
say "[1/6] Kiểm tra Python 3..."
if ! command -v python3 >/dev/null 2>&1; then
    die "Không tìm thấy python3. Cài bằng: sudo apt install -y python3 python3-venv python3-pip"
fi
PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
ok "Python $PY_VER"
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]; }; then
    warn "Python 3.10+ được khuyến nghị (bạn có $PY_VER). Có thể vẫn chạy được nhưng có thể gặp warning."
fi

# ---------- 2. apt deps (tmux, python3-venv) ----------
say "[2/6] Kiểm tra system packages (tmux, python3-venv, unzip)..."
NEED_APT=""
command -v tmux  >/dev/null 2>&1 || NEED_APT="$NEED_APT tmux"
command -v unzip >/dev/null 2>&1 || NEED_APT="$NEED_APT unzip"
python3 -c "import venv" 2>/dev/null || NEED_APT="$NEED_APT python3-venv"
if [ -n "$NEED_APT" ]; then
    if [ "$IDS_NO_APT" = "1" ]; then
        warn "Thiếu:$NEED_APT — IDS_NO_APT=1, bỏ qua. Bạn tự cài thủ công."
    elif command -v apt-get >/dev/null 2>&1; then
        say "  Cài thêm:$NEED_APT (cần sudo)..."
        sudo apt-get update -qq
        # shellcheck disable=SC2086
        sudo apt-get install -y $NEED_APT
        ok "Đã cài system packages"
    else
        die "Không có apt-get. Tự cài thủ công:$NEED_APT"
    fi
else
    ok "tmux, unzip, python3-venv: đầy đủ"
fi

# ---------- 3. venv ----------
say "[3/6] Tạo virtualenv tại .venv..."
if [ -d ".venv" ]; then
    ok ".venv đã tồn tại — bỏ qua"
else
    python3 -m venv .venv
    ok "Đã tạo .venv"
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip --quiet

# ---------- 4. pip install ----------
say "[4/6] Cài Python dependencies từ requirements.txt..."
if [ ! -f requirements.txt ]; then
    die "Không tìm thấy requirements.txt"
fi
pip install --quiet -r requirements.txt
ok "Đã cài: $(pip list --format=columns 2>/dev/null | awk 'NR>2 {print $1}' | wc -l) packages"

# ---------- 5. models ----------
say "[5/6] Kiểm tra trained models trong trained_models/..."
mkdir -p trained_models
# Hệ thống dùng *_final.pkl (sinh bởi scripts/retrain_final_all_models.py).
# Tối thiểu cho monitor (RF + LOF): rf_final + lof_final + scaler_final.
NEED_MODELS=("rf_final.pkl" "lof_final.pkl" "scaler_final.pkl")
MISSING=()
for f in "${NEED_MODELS[@]}"; do
    [ -f "trained_models/$f" ] || MISSING+=("$f")
done
if [ ${#MISSING[@]} -eq 0 ]; then
    ok "Đã có đầy đủ model files trong trained_models/ (${#NEED_MODELS[@]} files cần thiết)"
elif [ -f "ids_models_for_vm.zip" ]; then
    say "  Tìm thấy ids_models_for_vm.zip — đang giải nén..."
    # Giải nén vào root; zip có thể chứa flat files HOẶC thư mục trained_models/.
    # Sau khi giải nén, nếu .pkl rơi ra root thì move vào trained_models/.
    unzip -o -q ids_models_for_vm.zip
    # shellcheck disable=SC2046
    if ls ./*_final.pkl >/dev/null 2>&1; then
        say "  Phát hiện .pkl ở root — đang dồn vào trained_models/..."
        mv -f ./*_final.pkl trained_models/ 2>/dev/null || true
    fi
    ok "Đã giải nén models"
else
    err "Thiếu model files: ${MISSING[*]}"
    err "  Cách 1: ở MÁY LOCAL chạy:"
    err "          cd Project3 && zip -r ids_models_for_vm.zip trained_models/"
    err "          rồi scp ids_models_for_vm.zip user@<VM>:~/Project3/"
    err "          rồi chạy lại ./setup.sh"
    err "  Cách 2: tự train tất cả model: python3 scripts/retrain_final_all_models.py"
    exit 1
fi

# ---------- 6. Apache log permission ----------
say "[6/6] Kiểm tra quyền đọc Apache log..."
if [ -r "$IDS_LOG_FILE" ]; then
    LINES=$(wc -l < "$IDS_LOG_FILE" 2>/dev/null || echo 0)
    ok "Đọc được $IDS_LOG_FILE ($LINES dòng)"
elif [ ! -e "$IDS_LOG_FILE" ]; then
    warn "$IDS_LOG_FILE chưa tồn tại."
    warn "  → Cài Apache: sudo apt install -y apache2 && sudo systemctl start apache2"
    warn "  → Hoặc đặt biến: export IDS_LOG_FILE=/đường/dẫn/log/khác"
else
    warn "Không đọc được $IDS_LOG_FILE (thiếu quyền)."
    warn "  → Chạy: sudo usermod -a -G adm \$USER  (rồi logout/login lại)"
    warn "  → Hoặc: sudo setfacl -m u:\$USER:r $IDS_LOG_FILE"
fi

# ---------- Done ----------
echo
say "==================================================="
say "  ✅ Setup hoàn tất!"
say "==================================================="
echo
say "Bước tiếp theo:"
echo "  ./ids.sh start     # khởi động monitor + dashboard trong tmux"
echo "  ./ids.sh attach    # vào xem 2 pane"
echo "  ./ids.sh status    # kiểm tra trạng thái"
echo "  ./ids.sh stop      # dừng tất cả"
echo
say "Hoặc bypass tmux, chạy thủ công:"
echo "  source .venv/bin/activate"
echo "  tail -F $IDS_LOG_FILE | python apache_log.py monitor /dev/null lof"
echo "  # terminal khác:"
echo "  streamlit run dashboard.py --server.address 0.0.0.0"
echo
