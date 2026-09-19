#!/usr/bin/env bash
set -e

# Defaults for daemon parameters if not specified in environment
export SCANNER_INTERVAL="${SCANNER_INTERVAL:-60}"
export SCANNER_CHAINS="${SCANNER_CHAINS:-base,arbitrum,ethereum,solana}"
export DORMANT_INTERVAL="${DORMANT_INTERVAL:-120}"
export FACTORY_INTERVAL="${FACTORY_INTERVAL:-15}"
export LOG_WATCH_INTERVAL="${LOG_WATCH_INTERVAL:-8}"
export FOMO_FACTORY_LISTENER="${FOMO_FACTORY_LISTENER:-1}"
export FOMO_LOG_WATCHER="${FOMO_LOG_WATCHER:-1}"
export FOMO_SOURCE_HOT_GB="${FOMO_SOURCE_HOT_GB:-15}"
export FOMO_SOURCE_MIN_AGE_HOURS="${FOMO_SOURCE_MIN_AGE_HOURS:-24}"
export FOMO_ROTATE_INTERVAL="${FOMO_ROTATE_INTERVAL:-3600}"
# Host .env FOMO_CONTRACTS_DIR is the compose bind source. Inside the
# container the volume is always /app/contracts.
if [ -d /app/contracts ]; then
    export FOMO_CONTRACTS_INNER="/app/contracts"
    export FOMO_CONTRACTS_DIR="/app/contracts"
fi

# Ensure contracts directory structure exists
mkdir -p /app/contracts/triage_queue /app/contracts/triage_archive /var/log/supervisor

# If command is "daemon" or empty, start supervisord running all background daemons
if [ "$#" -eq 0 ] || [ "$1" = "daemon" ]; then
    echo "=========================================================="
    echo "🚀 Starting FOMO Smart Contract Security Suite (Daemon Mode)"
    echo "• Chains: $SCANNER_CHAINS"
    echo "• Scanner Interval: ${SCANNER_INTERVAL}s"
    echo "• Dormant Monitor Interval: ${DORMANT_INTERVAL}s"
    echo "=========================================================="
    exec supervisord -c /app/supervisord.conf
fi

# Otherwise, pass through arguments to allow CLI usage (e.g. `docker run ... python3 contract_extractor.py ...`)
exec "$@"
