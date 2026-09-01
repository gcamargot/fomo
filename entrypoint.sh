#!/usr/bin/env bash
set -e

# Defaults for daemon parameters if not specified in environment
export SCANNER_INTERVAL="${SCANNER_INTERVAL:-60}"
export SCANNER_CHAINS="${SCANNER_CHAINS:-base,arbitrum,ethereum,solana}"
export DORMANT_INTERVAL="${DORMANT_INTERVAL:-120}"

# Ensure contracts directory structure exists
mkdir -p /app/contracts/triage_queue /var/log/supervisor

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
