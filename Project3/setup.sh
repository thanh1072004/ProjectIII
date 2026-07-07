#!/usr/bin/env bash
# ============================================================================
# IDS Setup script — run once on the Linux VM to prepare the environment.
#
#   - Check Python 3 (>= 3.10)
#   - Create a virtualenv at .venv
#   - Install all dependencies from requirements.txt
#   - Extract ids_models_for_vm.zip (if present) to obtain the .pkl files
#   - Check read permission on /var/log/apache2/access.log
#   - Install tmux (required by ids.sh)
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh
#
# Optional environment variables:
#   IDS_LOG_FILE=/path/to/access.log   (default /var/log/apache2/access.log)
#   IDS_NO_APT=1                       (skip apt-get install, use when no sudo)
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
say "[1/6] Checking Python 3..."
if ! command -v python3 >/dev/null 2>&1; then
    die "python3 not found. Install with: sudo apt install -y python3 python3-venv python3-pip"
fi
PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
ok "Python $PY_VER"
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]; }; then
    warn "Python 3.10+ is recommended (you have $PY_VER). It may still run but you might see warnings."
fi

# ---------- 2. apt deps (tmux, python3-venv) ----------
say "[2/6] Checking system packages (tmux, python3-venv, unzip)..."
NEED_APT=""
command -v tmux  >/dev/null 2>&1 || NEED_APT="$NEED_APT tmux"
command -v unzip >/dev/null 2>&1 || NEED_APT="$NEED_APT unzip"
python3 -c "import venv" 2>/dev/null || NEED_APT="$NEED_APT python3-venv"
if [ -n "$NEED_APT" ]; then
    if [ "$IDS_NO_APT" = "1" ]; then
        warn "Missing:$NEED_APT — IDS_NO_APT=1, skipping. Please install them manually."
    elif command -v apt-get >/dev/null 2>&1; then
        say "  Installing:$NEED_APT (requires sudo)..."
        sudo apt-get update -qq
        # shellcheck disable=SC2086
        sudo apt-get install -y $NEED_APT
        ok "System packages installed"
    else
        die "apt-get not available. Install manually:$NEED_APT"
    fi
else
    ok "tmux, unzip, python3-venv: all present"
fi

# ---------- 3. venv ----------
say "[3/6] Creating virtualenv at .venv..."
if [ -d ".venv" ]; then
    ok ".venv already exists — skipping"
else
    python3 -m venv .venv
    ok ".venv created"
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip --quiet

# ---------- 4. pip install ----------
say "[4/6] Installing Python dependencies from requirements.txt..."
if [ ! -f requirements.txt ]; then
    die "requirements.txt not found"
fi
pip install --quiet -r requirements.txt
ok "Installed: $(pip list --format=columns 2>/dev/null | awk 'NR>2 {print $1}' | wc -l) packages"

# ---------- 5. models ----------
say "[5/6] Checking trained models in trained_models/..."
mkdir -p trained_models
# The system uses *_final.pkl (produced by scripts/retrain_final_all_models.py).
# Minimum for the monitor (RF + LOF): rf_final + lof_final + scaler_final.
NEED_MODELS=("rf_final.pkl" "lof_final.pkl" "scaler_final.pkl")
MISSING=()
for f in "${NEED_MODELS[@]}"; do
    [ -f "trained_models/$f" ] || MISSING+=("$f")
done
if [ ${#MISSING[@]} -eq 0 ]; then
    ok "All required model files present in trained_models/ (${#NEED_MODELS[@]} required files)"
elif [ -f "ids_models_for_vm.zip" ]; then
    say "  Found ids_models_for_vm.zip — extracting..."
    # Extract into root; the zip may contain flat files OR a trained_models/ folder.
    # After extraction, if .pkl files land in root, move them into trained_models/.
    unzip -o -q ids_models_for_vm.zip
    # shellcheck disable=SC2046
    if ls ./*_final.pkl >/dev/null 2>&1; then
        say "  Detected .pkl files in root — moving them into trained_models/..."
        mv -f ./*_final.pkl trained_models/ 2>/dev/null || true
    fi
    ok "Models extracted"
else
    err "Missing model files: ${MISSING[*]}"
    err "  Option 1: on your LOCAL machine run:"
    err "          cd Project3 && zip -r ids_models_for_vm.zip trained_models/"
    err "          then scp ids_models_for_vm.zip user@<VM>:~/Project3/"
    err "          then run ./setup.sh again"
    err "  Option 2: train all models yourself: python3 scripts/retrain_final_all_models.py"
    exit 1
fi

# ---------- 6. Apache log permission ----------
say "[6/6] Checking Apache log read permission..."
if [ -r "$IDS_LOG_FILE" ]; then
    LINES=$(wc -l < "$IDS_LOG_FILE" 2>/dev/null || echo 0)
    ok "Can read $IDS_LOG_FILE ($LINES lines)"
elif [ ! -e "$IDS_LOG_FILE" ]; then
    warn "$IDS_LOG_FILE does not exist yet."
    warn "  → Install Apache: sudo apt install -y apache2 && sudo systemctl start apache2"
    warn "  → Or set the variable: export IDS_LOG_FILE=/path/to/other/log"
else
    warn "Cannot read $IDS_LOG_FILE (permission denied)."
    warn "  → Run: sudo usermod -a -G adm \$USER  (then log out/in again)"
    warn "  → Or:  sudo setfacl -m u:\$USER:r $IDS_LOG_FILE"
fi

# ---------- Done ----------
echo
say "==================================================="
say "  ✅ Setup complete!"
say "==================================================="
echo
say "Next steps:"
echo "  ./ids.sh start     # start monitor + dashboard in tmux"
echo "  ./ids.sh attach    # open the 2 panes"
echo "  ./ids.sh status    # check status"
echo "  ./ids.sh stop      # stop everything"
echo
say "Or bypass tmux and run manually:"
echo "  source .venv/bin/activate"
echo "  tail -F $IDS_LOG_FILE | python apache_log.py monitor /dev/null lof"
echo "  # in another terminal:"
echo "  streamlit run dashboard.py --server.address 0.0.0.0"
echo
