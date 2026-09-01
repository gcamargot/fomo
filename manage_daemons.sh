#!/usr/bin/env bash
# ==============================================================================
# FOMO Daemon Manager & Fast Restart Script
# ==============================================================================

PROJECT_DIR="/home/nahtao97/fomo"
cd "$PROJECT_DIR" || exit 1

CHAINS="base,arbitrum,ethereum,solana"
INTERVAL_SCANNER=60
INTERVAL_DORMANT=120
INTERVAL_FACTORY="${FACTORY_INTERVAL:-15}"
INTERVAL_LOGS="${LOG_WATCH_INTERVAL:-8}"

_start_one() {
    local name="$1"
    local cmd="$2"
    local log="$3"
    nohup env PYTHONUNBUFFERED=1 $cmd > "$log" 2>&1 &
    echo "  started $name (log: $log)"
}

_stop_all() {
    pkill -f "token_scanner_daemon.py" 2>/dev/null || true
    pkill -f "dormant_monitor_daemon.py" 2>/dev/null || true
    pkill -f "factory_listener.py" 2>/dev/null || true
    pkill -f "event_log_watcher.py" 2>/dev/null || true
}

case "$1" in
    start)
        echo "🚀 Starting FOMO Daemons in background..."
        _start_one scanner "python3 -u token_scanner_daemon.py --daemon --interval $INTERVAL_SCANNER --chains $CHAINS" scanner.log
        _start_one dormant "python3 -u dormant_monitor_daemon.py --daemon --interval $INTERVAL_DORMANT" dormant_watcher.log
        _start_one factory "python3 -u factory_listener.py --daemon --interval $INTERVAL_FACTORY" factory_listener.log
        _start_one logs "python3 -u event_log_watcher.py --daemon --interval $INTERVAL_LOGS" event_log_watcher.log
        sleep 1
        echo "✓ Daemons launched! Use './manage_daemons.sh status' or './manage_daemons.sh logs'"
        ;;
    stop)
        echo "🛑 Stopping all running FOMO daemons..."
        _stop_all
        sleep 1
        echo "✓ Daemons stopped."
        ;;
    restart)
        echo "🔄 Restarting FOMO Daemons with latest code changes..."
        _stop_all
        sleep 1
        "$0" start
        "$0" status
        ;;
    status)
        echo "📊 === DAEMON STATUS ==="
        for spec in "Token Scanner:token_scanner_daemon.py" "Dormant/Watchlist:dormant_monitor_daemon.py" "Factory listener:factory_listener.py" "Log watcher:event_log_watcher.py"; do
            label="${spec%%:*}"
            pat="${spec##*:}"
            pids=$(pgrep -f "$pat" || true)
            if [ -n "$pids" ]; then
                echo "🟢 $label: RUNNING (PID: $pids)"
            else
                echo "🔴 $label: STOPPED"
            fi
        done
        ;;
    logs)
        echo "📋 Following live daemon logs (Ctrl+C to exit)..."
        tail -f scanner.log dormant_watcher.log factory_listener.log event_log_watcher.log
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        exit 1
        ;;
esac
