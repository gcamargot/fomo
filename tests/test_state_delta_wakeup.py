"""State-delta wakeup: skip full audit when on-chain snapshot is unchanged."""

from state_delta import StateSnapshot, should_wakeup, snapshot_from_dict, snapshot_to_dict


def _s(**kw):
    base = dict(eth_balance=0.0, pool_eth=0.0, treasury_tokens=0.0, swap_enabled=None)
    base.update(kw)
    return StateSnapshot(**base)


def test_first_snapshot_always_wakes():
    assert should_wakeup(None, _s(eth_balance=0.0)) is True


def test_unchanged_snapshot_skips():
    prev = _s(eth_balance=0.1, pool_eth=1.0, treasury_tokens=100.0, swap_enabled=True)
    curr = _s(eth_balance=0.1, pool_eth=1.0, treasury_tokens=100.0, swap_enabled=True)
    assert should_wakeup(prev, curr) is False


def test_eth_jump_wakes():
    prev = _s(eth_balance=0.0)
    curr = _s(eth_balance=0.05)
    assert should_wakeup(prev, curr) is True


def test_dust_eth_noise_does_not_wake():
    prev = _s(eth_balance=1.0)
    curr = _s(eth_balance=1.00000001)
    assert should_wakeup(prev, curr) is False


def test_pool_reserve_jump_wakes():
    prev = _s(pool_eth=0.04)
    curr = _s(pool_eth=0.5)
    assert should_wakeup(prev, curr) is True


def test_swap_enabled_flip_wakes():
    prev = _s(swap_enabled=False)
    curr = _s(swap_enabled=True)
    assert should_wakeup(prev, curr) is True


def test_treasury_token_jump_wakes():
    prev = _s(treasury_tokens=10.0)
    curr = _s(treasury_tokens=5000.0)
    assert should_wakeup(prev, curr) is True


def test_run_cycle_skips_full_audit_when_unchanged(monkeypatch):
    import json
    from unittest.mock import MagicMock
    import dormant_monitor_daemon as dmd

    snap = _s(eth_balance=0.2, pool_eth=1.0, treasury_tokens=10.0, swap_enabled=True)
    target = {
        "address": "0x" + "c" * 40,
        "chain": "ethereum",
        "bucket": "unfunded_drain",
        "state_snapshot": json.dumps(snapshot_to_dict(snap)),
    }
    watcher = dmd.DormantBalanceWatcher.__new__(dmd.DormantBalanceWatcher)
    watcher.db = MagicMock()
    watcher.max_targets = 10
    watcher.web3_clients = {}
    monkeypatch.setattr(watcher, "get_watchlist", lambda: [target])
    monkeypatch.setattr(watcher, "capture_snapshot", lambda *a, **k: snap)
    monkeypatch.setattr(dmd, "load_saved_source", lambda *a, **k: "pragma solidity ^0.8.0;")
    check = MagicMock(return_value=False)
    monkeypatch.setattr(watcher, "check_and_update_contract", check)
    tot, act = watcher.run_cycle()
    assert tot == 1
    assert act == 0
    check.assert_not_called()
    watcher.db.update_token_flags.assert_called()


def test_run_cycle_wakes_on_reserve_jump(monkeypatch):
    import json
    from unittest.mock import MagicMock
    import dormant_monitor_daemon as dmd

    prev = _s(pool_eth=0.04)
    curr = _s(pool_eth=0.8)
    target = {
        "address": "0x" + "d" * 40,
        "chain": "base",
        "bucket": "sleeping_tax",
        "state_snapshot": json.dumps(snapshot_to_dict(prev)),
    }
    watcher = dmd.DormantBalanceWatcher.__new__(dmd.DormantBalanceWatcher)
    watcher.db = MagicMock()
    watcher.max_targets = 10
    watcher.web3_clients = {}
    monkeypatch.setattr(watcher, "get_watchlist", lambda: [target])
    monkeypatch.setattr(watcher, "capture_snapshot", lambda *a, **k: curr)
    monkeypatch.setattr(dmd, "load_saved_source", lambda *a, **k: "x")
    check = MagicMock(return_value=True)
    monkeypatch.setattr(watcher, "check_and_update_contract", check)
    tot, act = watcher.run_cycle()
    assert tot == 1 and act == 1
    check.assert_called_once()


def test_roundtrip_dict():
    snap = _s(eth_balance=0.2, pool_eth=3.0, swap_enabled=False)
    restored = snapshot_from_dict(snapshot_to_dict(snap))
    assert restored == snap
    assert snapshot_from_dict(None) is None
    assert snapshot_from_dict({}) is None
