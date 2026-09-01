#!/usr/bin/env bash
# ==============================================================================
# FOMO Daemon Manager & Fast Restart Script
# ==============================================================================

PROJECT_DIR="/home/nahtao97/fomo"
cd "$PROJECT_DIR" || exit 1

CHAINS="base,arbitrum,ethereum,solana"
INTERVAL_SCANNER=60
INTERVAL_DORMANT=120

case "$1" in
    start)
        echo "🚀 Starting FOMO Daemons in background..."
        nohup python3 -u token_scanner_daemon.py --daemon --interval "$INTERVAL_SCANNER" --chains "$CHAINS" > scanner.log 2>&1 &
        nohup python3 -u dormant_monitor_daemon.py --daemon --interval "$INTERVAL_DORMANT" > dormant_watcher.log 2>&1 &
        sleep 1
        echo "✓ Daemons launched! Use './manage_daemons.sh status' or './manage_daemons.sh logs'"
        ;;
    stop)
        echo "🛑 Stopping all running FOMO daemons..."
        pkill -f "token_scanner_daemon.py"
        pkill -f "dormant_monitor_daemon.py"
        sleep 1
        echo "✓ Daemons stopped."
        ;;
    restart)
        echo "🔄 Restarting FOMO Daemons with latest code changes..."
        pkill -f "token_scanner_daemon.py" 2>/dev/null
        pkill -f "dormant_monitor_daemon.py" 2>/dev/null
        sleep 1
        nohup python3 -u token_scanner_daemon.py --daemon --interval "$INTERVAL_SCANNER" --chains "$CHAINS" > scanner.log 2>&1 &
        nohup python3 -u dormant_monitor_daemon.py --daemon --interval "$INTERVAL_DORMANT" > dormant_watcher.log 2>&1 &
        sleep 1
        echo "✓ Daemons successfully restarted with updated code!"
        $0 status
        ;;
    status)
        echo "📊 === DAEMON STATUS ==="
        PIDS_SCANNER=$(pgrep -f "token_scanner_daemon.py")
        PIDS_DORMANT=$(pgrep -f "dormant_monitor_daemon.py")
        
        if [ -n "$PIDS_SCANNER" ]; then
            echo "🟢 Token Scanner Daemon: RUNNING (PID: $PIDS_SCANNER)"
        else
            echo "🔴 Token Scanner Daemon: STOPPED"
        fi
        
        if [ -n "$PIDS_DORMANT" ]; then
            echo "🟢 Dormant Monitor Daemon: RUNNING (PID: $PIDS_DORMANT)"
        else
            echo "🔴 Dormant Monitor Daemon: STOPPED"
        fi
        ;;
    logs)
        echo "📋 Following live daemon logs (Ctrl+C to exit)..."
        tail -f scanner.log dormant_watcher.log
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        exit 1
        ;;
esac
