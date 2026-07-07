#!/usr/bin/env bash
# ============================================================================
# IDS launcher — manages the monitor + dashboard in a single tmux session.
#
# Subcommands:
#   ./ids.sh start    Start monitor (left pane) + dashboard (right pane)
#   ./ids.sh stop     Stop both (kill the tmux session)
#   ./ids.sh restart  stop + start
#   ./ids.sh status   Show status + dashboard URL
#   ./ids.sh attach   Attach to the tmux session to watch live (Ctrl+B then D to leave)
#   ./ids.sh logs     Tail the alerts JSONL file (monitor_alerts.jsonl)
#
# Environment variables:
#   IDS_LOG_FILE  — Apache access log (default /var/log/apache2/access.log)
#   IDS_PORT      — Streamlit dashboard port (default 8501)
#   IDS_MODEL     — Unsupervised tripwire model (default lof)
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
    command -v tmux >/dev/null 2>&1 || die "tmux is not installed. Run ./setup.sh first."
    [ -x "$VENV_PY" ] || die ".venv/bin/python is missing. Run ./setup.sh first."
    [ -x "$VENV_STREAMLIT" ] || die ".venv/bin/streamlit is missing. Run ./setup.sh first."
    [ -f "$PROJECT_DIR/apache_log.py" ] || die "apache_log.py not found"
    [ -f "$PROJECT_DIR/dashboard.py" ]  || die "dashboard.py not found"
    # The system uses *_final.pkl in trained_models/. Map model_type -> file name:
    case "$MODEL" in
        lof)   UNSUP_PKL="lof_final.pkl" ;;
        if)    UNSUP_PKL="isolation_forest_final.pkl" ;;
        ocsvm) UNSUP_PKL="ocsvm_final.pkl" ;;
        *)     UNSUP_PKL="${MODEL}_final.pkl" ;;
    esac
    [ -f "$PROJECT_DIR/trained_models/rf_final.pkl" ] || warn "trained_models/rf_final.pkl missing — Tier 2 will be disabled"
    [ -f "$PROJECT_DIR/trained_models/$UNSUP_PKL" ] || die "trained_models/$UNSUP_PKL missing. Run ./setup.sh first or change IDS_MODEL."
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
        warn "tmux session '$SESSION' is already running. Use './ids.sh attach' to view, or './ids.sh restart' to relaunch."
        exit 0
    fi
    if port_in_use; then
        warn "Port $PORT is already in use by another process. Change IDS_PORT or kill that process."
    fi
    if [ ! -r "$LOG_FILE" ]; then
        die "Cannot read $LOG_FILE. Check permissions (sudo usermod -a -G adm \$USER, then log out/in)."
    fi

    say "Starting tmux session '$SESSION'..."
    say "  Apache log: $LOG_FILE"
    say "  Dashboard:  http://0.0.0.0:$PORT"
    say "  Tripwire:   $MODEL"

    # Left pane: monitor (tail -F → python apache_log.py monitor)
    # tail -F to follow logrotate
    MONITOR_CMD="exec tail -F '$LOG_FILE' | '$VENV_PY' apache_log.py monitor /dev/null $MODEL"
    tmux new-session -d -s "$SESSION" -n "ids" \
        "echo '=== TIER 1+2+3 MONITOR ==='; $MONITOR_CMD"

    # Right pane: dashboard
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
        ok "Started!"
        echo
        say "Next steps:"
        echo "  ./ids.sh status   # show status"
        echo "  ./ids.sh attach   # watch the 2 panes live (Ctrl+B D to detach, keeps running)"
        echo "  ./ids.sh logs     # tail the alerts file"
        echo "  ./ids.sh stop     # stop"
        echo
        say "Dashboard: http://<VM-IP>:$PORT (if running locally: http://localhost:$PORT)"
    else
        die "Failed to start. Run './ids.sh attach' to see the error (if the session exists)."
    fi
}

cmd_stop() {
    if session_running; then
        tmux kill-session -t "$SESSION"
        ok "Stopped tmux session '$SESSION'"
    else
        warn "tmux session '$SESSION' is not running"
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
    session_running || die "tmux session '$SESSION' is not running. Run './ids.sh start' first."
    say "Attaching to session '$SESSION'..."
    say "  Shortcuts: Ctrl+B D = detach session (keeps running)"
    say "             Ctrl+B arrow = switch pane"
    say "             Ctrl+B [ = scroll mode (q to exit)"
    sleep 1
    exec tmux attach-session -t "$SESSION"
}

cmd_logs() {
    F="$PROJECT_DIR/runtime/monitor_alerts.jsonl"
    [ -f "$F" ] || die "$F does not exist yet. Run './ids.sh start' first."
    say "Tailing $F (Ctrl+C to exit)..."
    exec tail -F "$F"
}

cmd_help() {
    cat <<EOF
IDS Launcher — manages the monitor + dashboard

Usage: ./ids.sh <command>

Commands:
  start     Start monitor + dashboard in the tmux session 'ids'
  stop      Stop the tmux session
  restart   stop + start
  status    Show status + info
  attach    Watch the 2 panes live (Ctrl+B D to detach, keeps running in background)
  logs      Tail runtime/monitor_alerts.jsonl
  help      Print this help

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
