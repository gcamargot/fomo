"""SQLite fixture tests for opportunity watchlist selection (no RPC)."""

from datetime import datetime, timedelta, timezone

from opportunity_watchlist import (
    BUCKET_NEAR_MISS,
    BUCKET_SLEEPING_TAX,
    BUCKET_UNFUNDED_DRAIN,
    backoff_next_check,
    classify_row_bucket,
    fetch_watchlist,
    init_watchlist_schema,
)


def _now():
    return datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)


def _conn():
    import sqlite3
    conn = sqlite3.connect(":memory:")
    init_watchlist_schema(conn)
    return conn


def _insert(conn, address, **kw):
    cols = {
        "address": address.lower(),
        "chain": "ethereum",
        "name": "T",
        "compiler": "0.8.20",
        "category": "CUSTOM_LOGIC",
        "verified": 1,
        "is_user_exploitable": 0,
        "dynamic_status": "CLEAN_NO_EXPLOIT",
        "eth_balance": 0.0,
        "has_zero_slippage": 0,
        "has_unprotected_critical_function": 0,
        "has_unprotected_initializer": 0,
        "has_reentrancy_flaw": 0,
        "has_signature_replay_flaw": 0,
        "has_vault_inflation": 0,
        "has_flash_staking_flaw": 0,
        "has_arbitrary_call": 0,
        "has_fee_on_transfer_flaw": 0,
        "has_spot_oracle_flaw": 0,
        "has_tx_origin_auth": 0,
        "has_unprotected_router_setter": 0,
        "has_permit_no_nonce": 0,
        "has_multicall_msgvalue": 0,
        "has_public_swapback": 0,
        "expected_profit_eth": None,
        "last_checked_at": None,
        "next_check_at": None,
        "watch_bucket": None,
    }
    cols.update(kw)
    keys = ",".join(cols)
    qmarks = ",".join("?" * len(cols))
    conn.execute(f"INSERT INTO tokens ({keys}) VALUES ({qmarks})", list(cols.values()))
    conn.commit()


def test_clean_token_excluded():
    conn = _conn()
    _insert(conn, "0x" + "1" * 40)
    rows = fetch_watchlist(conn, now=_now(), max_targets=50)
    assert rows == []


def test_already_exploitable_excluded():
    conn = _conn()
    _insert(
        conn,
        "0x" + "2" * 40,
        has_unprotected_initializer=1,
        is_user_exploitable=1,
        eth_balance=2.0,
    )
    rows = fetch_watchlist(conn, now=_now(), max_targets=50)
    assert rows == []


def test_unfunded_drain_included_at_zero_eth():
    conn = _conn()
    addr = "0x" + "3" * 40
    _insert(conn, addr, has_unprotected_initializer=1, eth_balance=0.0)
    rows = fetch_watchlist(conn, now=_now(), max_targets=50)
    assert len(rows) == 1
    assert rows[0]["address"] == addr
    assert rows[0]["bucket"] == BUCKET_UNFUNDED_DRAIN


def test_unfunded_drain_included_when_already_has_eth():
    """Watchlist is not 0-ETH-only: funded-but-not-yet-actionable drains stay queued."""
    conn = _conn()
    addr = "0x" + "4" * 40
    _insert(conn, addr, has_arbitrary_call=1, eth_balance=0.5)
    rows = fetch_watchlist(conn, now=_now(), max_targets=50)
    assert len(rows) == 1
    assert rows[0]["bucket"] == BUCKET_UNFUNDED_DRAIN
    assert rows[0]["eth_balance"] == 0.5


def test_sleeping_swapback_dust_included():
    conn = _conn()
    addr = "0x" + "5" * 40
    _insert(
        conn,
        addr,
        has_public_swapback=1,
        dynamic_status="PUBLIC_SWAPBACK_DEAD_OR_DUST_POOL_0.0006ETH",
        eth_balance=0.0,
    )
    rows = fetch_watchlist(conn, now=_now(), max_targets=50)
    assert len(rows) == 1
    assert rows[0]["bucket"] == BUCKET_SLEEPING_TAX


def test_zero_slippage_sleeping_included():
    conn = _conn()
    addr = "0x" + "6" * 40
    _insert(
        conn,
        addr,
        has_zero_slippage=1,
        dynamic_status="ZERO_SLIPPAGE_DORMANT_SWAP_OFF_OWNER_BURNED",
    )
    rows = fetch_watchlist(conn, now=_now(), max_targets=50)
    assert len(rows) == 1
    assert rows[0]["bucket"] == BUCKET_SLEEPING_TAX


def test_near_miss_profit_gate_included():
    conn = _conn()
    addr = "0x" + "7" * 40
    _insert(
        conn,
        addr,
        has_public_swapback=1,
        dynamic_status="PROFIT_BELOW_THRESHOLD_XYK_0.0100ETH",
        expected_profit_eth=0.01,
        eth_balance=0.0,
    )
    rows = fetch_watchlist(conn, now=_now(), max_targets=50)
    assert len(rows) == 1
    assert rows[0]["bucket"] == BUCKET_NEAR_MISS


def test_max_targets_cap():
    conn = _conn()
    for i in range(5):
        _insert(conn, f"0x{i:040x}", has_unprotected_initializer=1)
    rows = fetch_watchlist(conn, now=_now(), max_targets=2)
    assert len(rows) == 2


def test_future_next_check_skipped():
    conn = _conn()
    addr = "0x" + "a" * 40
    future = (_now() + timedelta(hours=2)).isoformat()
    _insert(
        conn,
        addr,
        has_unprotected_initializer=1,
        next_check_at=future,
    )
    rows = fetch_watchlist(conn, now=_now(), max_targets=50)
    assert rows == []


def test_due_next_check_included():
    conn = _conn()
    addr = "0x" + "b" * 40
    past = (_now() - timedelta(minutes=1)).isoformat()
    _insert(
        conn,
        addr,
        has_unprotected_initializer=1,
        next_check_at=past,
    )
    rows = fetch_watchlist(conn, now=_now(), max_targets=50)
    assert len(rows) == 1


def test_backoff_grows():
    t0 = _now()
    n1 = backoff_next_check(t0, failures=0)
    n2 = backoff_next_check(t0, failures=3)
    assert n2 > n1


def test_classify_row_bucket_priority():
    assert classify_row_bucket({
        "has_public_swapback": 1,
        "dynamic_status": "PROFIT_BELOW_THRESHOLD_XYK_0.01ETH",
        "expected_profit_eth": 0.01,
        "has_unprotected_initializer": 1,
    }) == BUCKET_NEAR_MISS
    assert classify_row_bucket({
        "has_zero_slippage": 1,
        "dynamic_status": "ZERO_SLIPPAGE_BELOW_THRESHOLD",
        "has_unprotected_initializer": 0,
    }) == BUCKET_SLEEPING_TAX
    assert classify_row_bucket({
        "has_unprotected_critical_function": 1,
        "dynamic_status": "BROKEN_ACCESS_REVERT_OR_UNKNOWN",
    }) == BUCKET_UNFUNDED_DRAIN
