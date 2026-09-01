"""Swap / liquidation log filtering (no RPC)."""

from event_log_watcher import (
    AAVE_V3_LIQ_TOPIC0,
    SWAP_TOPIC0,
    liquidation_hits,
    tokens_from_swap_logs,
)

PAIR = "0x2222222222222222222222222222222222222222"
TOKEN = "0x1111111111111111111111111111111111111111"
OTHER = "0x3333333333333333333333333333333333333333"
POOL = "0x4444444444444444444444444444444444444444"


def test_swap_on_watched_pair_enqueues_token():
    logs = [{"topics": [SWAP_TOPIC0], "address": PAIR}]
    got = tokens_from_swap_logs(logs, {PAIR: TOKEN})
    assert got == [TOKEN]


def test_unrelated_pair_ignored():
    logs = [{"topics": [SWAP_TOPIC0], "address": OTHER}]
    assert tokens_from_swap_logs(logs, {PAIR: TOKEN}) == []


def test_cursor_independent_empty_logs():
    assert tokens_from_swap_logs([], {PAIR: TOKEN}) == []


def test_liquidation_allowlist_match():
    logs = [{"topics": [AAVE_V3_LIQ_TOPIC0], "address": POOL}]
    assert liquidation_hits(logs, [POOL]) == [POOL.lower()]
    assert liquidation_hits(logs, [OTHER]) == []
