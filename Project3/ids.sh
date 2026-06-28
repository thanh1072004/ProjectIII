#!/usr/bin/env bash
# ============================================================================
# IDS launcher — quản lý monitor + dashboard trong một tmux session.
#
# Subcommands:
#   ./ids.sh start    Khởi động monitor (pane trái) + dashboard (pane phải)
#   ./ids.sh stop     Dừng cả 2 (kill tmux session)
#   ./ids.sh restart  stop + start
#   ./ids.sh status   Hiển thị trạng thái + URL dashboard
#   ./ids.sh attach   Vào tmux session để xem live (Ctrl+B sau đó D để thoát)
#   ./ids.sh logs     Tail file alerts JSONL (monitor_alerts.jsonl)
#
# Biến môi trường:
#   IDS_LOG_FILE  — Apache access log (mặc định /var/log/apache2/access.log)
#   IDS_PORT      — Port của Streamlit dashboard (mặc định 8501)
#   IDS_MODEL     — Tripwire unsupervised model (mặc định lof)
# ============================================================================

set -e

# ---------- config ----------
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

SESSION="ids"
LOG_FILE="${IDS_LOG_FILE:-/var/log/apache2/access.log}"
PORT="${IDS_PORT:-8501}"
MODEL="${IDS_MODEL:-lof}"
VENV_PY="$PROJECT_DIR/.venv/bin/python"
VENV_STREAMLIT="$PROJECT_DIR/.venv/bin/streamlit"

# ---------- helpers ----------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
say()  { printf "${CYAN}[ids]${NC} %s\n" "$*"; }
ok()   { printf "${GREEN}  ✓${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}  ⚠${NC} %s\n" "$*"; }
err()  { printf "${RED}  ✗${NC} %s\n" "$*" >&2; }
die()  { err "$*"; exit 1; }

# ---------- preflight ----------
check_env() {
    command -v tmux >/dev/null 2>&1 || die "Chưa cài tmux. Chạy ./setup.sh trước."
    [ -x "$VENV_PY" ] || die "Chưa có .venv/bin/python. Chạy ./setup.sh trước."
    [ -x "$VENV_STREAMLIT" ] || die "Chưa có .venv/bin/streamlit. Chạy ./setup.sh trước."
    [ -f "$PROJECT_DIR/apache_log.py" ] || die "Không tìm thấy apache_log.py"
    [ -f "$PROJECT_DIR/dashboard.py" ]  || die "Không tìm thấy dashboard.py"
    # Hệ thống dùng *_final.pkl trong trained_models/. Map model_type -> tên file:
    case "$MODEL" in
        lof)   UNSUP_PKL="lof_final.pkl" ;;
        if)    UNSUP_PKL="isolation_forest_final.pkl" ;;
        ocsvm) UNSUP_PKL="ocsvm_final.pkl" ;;
        *)     UNSUP_PKL="${MODEL}_final.pkl" ;;
    esac
    [ -f "$PROJECT_DIR/trained_models/rf_final.pkl" ] || warn "trained_models/rf_final.pkl chưa có — Tier 2 sẽ bị disable"
    [ -f "$PROJECT_DIR/trained_models/$UNSUP_PKL" ] || die "trained_models/$UNSUP_PKL chưa có. Chạy ./setup.sh trước hoặc đổi IDS_MODEL."
}

session_running() {
    tmux has-session -t "$SESSION" 2>/dev/null
}

port_in_use() {
    if command -v ss >/dev/null 2>&1; then
        ss -tln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${PORT}$"
    elif command -v lsof >/dev/null 2>&1; then
        lsof -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1
    else
        return 1
    fi
}

# ---------- subcommands ----------
cmd_start() {
    check_env
    if session_running; then
        warn "tmux session '$SESSION' đã chạy. Dùng './ids.sh attach' để xem, hoặc './ids.sh restart' để chạy lại."
        exit 0
    fi
    if port_in_use; then
        warn "Port $PORT đã có process khác lắng nghe. Đổi IDS_PORT hoặc kill process đó."
    fi
    if [ ! -r "$LOG_FILE" ]; then
        die "Không đọc được $LOG_FILE. Kiểm tra quyền (sudo usermod -a -G adm \$USER, rồi logout/login)."
    fi

    say "Khởi động tmux session '$SESSION'..."
    say "  Apache log: $LOG_FILE"
    say "  Dashboard:  http://0.0.0.0:$PORT"
    say "  Tripwire:   $MODEL"

    # Pane trái: monitor (tail -F → python apache_log.py monitor)
    # tail -F để follow logrotate
    MONITOR_CMD="exec tail -F '$LOG_FILE' | '$VENV_PY' apache_log.py monitor /dev/null $MODEL"
    tmux new-session -d -s "$SESSION" -n "ids" \
        "echo '=== TIER 1+2+3 MONITOR ==='; $MONITOR_CMD"

    # Pane phải: dashboard
    DASH_CMD="exec '$VENV_STREAMLIT' run dashboard.py \
        --server.headless true \
        --server.address 0.0.0.0 \
        --server.port $PORT \
        --browser.gatherUsageStats false"
    tmux split-window -h -t "$SESSION:ids" \
        "echo '=== STREAMLIT DASHBOARD ==='; $DASH_CMD"

    tmux select-pane -t "$SESSION:ids.0"

    sleep 1
    if session_running; then
        ok "Đã khởi động!"
        echo
        say "Bước tiếp:"
        echo "  ./ids.sh status   # xem trạng thái"
        echo "  ./ids.sh attach   # vào xem 2 pane trực tiếp (Ctrl+B D để rời, vẫn chạy)"
        echo "  ./ids.sh logs     # tail file alerts"
        echo "  ./ids.sh stop     # dừng"
        echo
        say "Dashboard: http://<VM-IP>:$PORT (nếu chạy local: http://localhost:$PORT)"
    else
        die "Không khởi động được. Chạy './ids.sh attach' để xem lỗi (nếu session tồn tại)."
    fi
}

cmd_stop() {
    if session_running; then
        tmux kill-session -t "$SESSION"
        ok "Đã dừng tmux session '$SESSION'"
    else
        warn "tmux session '$SESSION' không đang chạy"
    fi
}

cmd_restart() {
    cmd_stop || true
    sleep 1
    cmd_start
}

cmd_status() {
    echo
    say "==================================================="
    say "  IDS Status"
    say "==================================================="
    printf "  tmux session   : "
    if session_running; then printf "${GREEN}RUNNING${NC} (%s)\n" "$SESSION"; else printf "${RED}STOPPED${NC}\n"; fi
    printf "  Apache log     : %s " "$LOG_FILE"
    if [ -r "$LOG_FILE" ]; then printf "${GREEN}(readable)${NC}\n"; else printf "${RED}(unreadable)${NC}\n"; fi
    printf "  Dashboard port : %s " "$PORT"
    if port_in_use; then printf "${GREEN}(listening)${NC}\n"; else printf "${YELLOW}(idle)${NC}\n"; fi
    printf "  Alerts file    : runtime/monitor_alerts.jsonl "
    if [ -f "$PROJECT_DIR/runtime/monitor_alerts.jsonl" ]; then
        N=$(wc -l < "$PROJECT_DIR/runtime/monitor_alerts.jsonl" 2>/dev/null || echo 0)
        printf "${GREEN}(%d alerts)${NC}\n" "$N"
    else
        printf "${YELLOW}(not created yet)${NC}\n"
    fi
    printf "  Tripwire model : %s\n" "$MODEL"
    if session_running; then
        echo
        say "Pane uptime:"
        tmux list-panes -t "$SESSION:ids" -F "  #{pane_index}: started #{pane_start_time} | #{pane_current_command}" 2>/dev/null || true
    fi
    echo
}

cmd_attach() {
    session_running || die "tmux session '$SESSION' chưa chạy. Chạy './ids.sh start' trước."
    say "Đang attach vào session '$SESSION'..."
    say "  Phím tắt: Ctrl+B D = rời session (vẫn chạy)"
    say "           Ctrl+B mũi tên = chuyển pane"
    say "           Ctrl+B [ = scroll mode (q để thoát)"
    sleep 1
    exec tmux attach-session -t "$SESSION"
}

cmd_logs() {
    F="$PROJECT_DIR/runtime/monitor_alerts.jsonl"
    [ -f "$F" ] || die "Chưa có $F. Chạy './ids.sh start' trước."
    say "Đang tail $F (Ctrl+C để thoát)..."
    exec tail -F "$F"
}

cmd_help() {
    cat <<EOF
IDS Launcher — quản lý monitor + dashboard

Usage: ./ids.sh <command>

Commands:
  start     Khởi động monitor + dashboard trong tmux session 'ids'
  stop      Dừng tmux session
  restart   stop + start
  status    Hiển thị trạng thái + thông tin
  attach    Vào xem live 2 pane (Ctrl+B D để rời, vẫn chạy nền)
  logs      Tail file runtime/monitor_alerts.jsonl
  help      In hướng dẫn này

Environment:
  IDS_LOG_FILE  Apache access log (default: /var/log/apache2/access.log)
  IDS_PORT      Streamlit dashboard port (default: 8501)
  IDS_MODEL     Unsupervised tripwire: lof|if|ocsvm (default: lof)

Examples:
  ./ids.sh start
  IDS_PORT=9000 ./ids.sh start
  IDS_LOG_FILE=~/access.log ./ids.sh start
  ./ids.sh attach
EOF
}

# ---------- dispatch ----------
case "${1:-}" in
    start)   cmd_start   ;;
    stop)    cmd_stop    ;;
    restart) cmd_restart ;;
    status)  cmd_status  ;;
    attach)  cmd_attach  ;;
    logs)    cmd_logs    ;;
    help|-h|--help|"") cmd_help ;;
    *) err "Unknown command: $1"; cmd_help; exit 1 ;;
esac
