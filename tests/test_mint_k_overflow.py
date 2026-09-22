"""Public mint, broken-K swap, and pre-0.8 balance overflow gates."""

from unittest.mock import MagicMock

from factory_listener import process_factory_pair
from fork_profit_gate import ForkGateResult, split_fork_gated
from profit_estimator import (
    apply_profit_gate,
    estimate_broken_k_profit,
    estimate_unlimited_sell_profit,
)
from token_scanner_daemon import OnChainStateVerifier, StaticVulnerabilityAuditor

from test_process_factory_pair import EV, _est


def _types(src: str):
    _flags, evidence = StaticVulnerabilityAuditor.audit_source(src)
    return {e["type"] for e in evidence}


def test_owner_mint_is_not_public():
    src = """
    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }
    """
    kinds = _types(src)
    assert "UNLIMITED_MINT" in kinds
    assert "PUBLIC_MINT" not in kinds


def test_public_mint_with_amount_flags():
    src = """
    contract Token {
        function mint(address to, uint256 amount) public {
            _mint(to, amount);
        }
    }
    """
    assert "PUBLIC_MINT" in _types(src)
    sig, args = OnChainStateVerifier.mint_probe_plan(src)
    assert sig == "mint(address,uint256)"
    assert len(args) == 64


def test_payable_mint_is_not_unlimited_sell():
    src = """
    function mint(uint256 amount) public payable {
        _mint(msg.sender, amount);
    }
    """
    assert "PUBLIC_MINT" not in _types(src)
    assert OnChainStateVerifier.mint_probe_plan(src) is None


def test_interface_mint_ignored():
    src = """
    interface I {
        function mint(address to, uint256 amount) external;
    }
    """
    assert "PUBLIC_MINT" not in _types(src)


def test_pre_08_raw_transfer_flags_overflow():
    src = """
    pragma solidity ^0.4.24;
    contract T {
        function transfer(address to, uint256 value) public returns (bool) {
            balances[msg.sender] -= value;
            balances[to] += value;
            return true;
        }
    }
    """
    kinds = _types(src)
    assert "BALANCE_OVERFLOW" in kinds
    flags, evidence = StaticVulnerabilityAuditor.audit_source(src)
    assert flags["has_balance_overflow"] is True
    overflow = next(e for e in evidence if e["type"] == "BALANCE_OVERFLOW")
    assert overflow["requires_live_fork"] is True


def test_safemath_and_solc08_are_not_overflow():
    safe = """
    pragma solidity ^0.7.0;
    function transfer(address to, uint256 value) public returns (bool) {
        _balances[msg.sender] = _balances[msg.sender].sub(value);
        _balances[to] = _balances[to].add(value);
        return true;
    }
    """
    modern = """
    pragma solidity ^0.8.0;
    function transfer(address to, uint256 value) public returns (bool) {
        balances[msg.sender] -= value;
        balances[to] += value;
        return true;
    }
    """
    assert "BALANCE_OVERFLOW" not in _types(safe)
    assert "BALANCE_OVERFLOW" not in _types(modern)


def test_unlimited_sell_approaches_fee_on_reserve():
    est = estimate_unlimited_sell_profit(pool_eth=1.0, gas_eth=0.002)
    assert est.method == "unlimited_sell"
    assert est.actionable is True
    assert abs(est.expected_profit_eth - (0.997 - 0.002)) < 1e-9


def test_unlimited_sell_dust_is_not_actionable():
    est = estimate_unlimited_sell_profit(pool_eth=0.04)
    assert est.actionable is False


def test_broken_k_takes_reserve_net_of_gas():
    est = estimate_broken_k_profit(pool_eth=1.0, gas_eth=0.002)
    assert est.method == "broken_k"
    assert est.actionable is True
    assert abs(est.expected_profit_eth - 0.998) < 1e-9
    assert estimate_broken_k_profit(pool_eth=0.051).actionable is False


def test_profit_gate_prices_public_mint_from_pool_not_native():
    kept, _notes, est = apply_profit_gate(
        [{"type": "PUBLIC_MINT", "_pool_eth": 1.0}],
        eth_balance=0.0,
        pool_eth=0.0,
    )
    assert kept and kept[0]["type"] == "PUBLIC_MINT"
    assert est is not None and est.method == "unlimited_sell"


def test_profit_gate_keeps_overflow_fork_flag():
    kept, _notes, est = apply_profit_gate(
        [{"type": "BALANCE_OVERFLOW", "_pool_eth": 1.0, "requires_live_fork": True}],
        eth_balance=0.0,
        pool_eth=0.0,
    )
    assert kept[0]["requires_live_fork"] is True
    assert est.method == "unlimited_sell"


def test_swap_calldata_asks_for_weth_reserve_minus_one():
    raw = OnChainStateVerifier.encode_univ2_swap_args(
        0, 10**18 - 1, OnChainStateVerifier.PROBE_EOA
    )
    assert int.from_bytes(raw[0:32], "big") == 0
    assert int.from_bytes(raw[32:64], "big") == 10**18 - 1
    assert int.from_bytes(raw[96:128], "big") == 128
    assert raw[128:160] == b"\x00" * 32


def test_broken_k_success_emits_without_source():
    db = MagicMock()
    gen = MagicMock(return_value="/tmp/k.md")
    process_factory_pair(
        db,
        "base",
        EV,
        load_source=lambda *a: "",
        audit=lambda src: ({}, []),
        verify=lambda *a: (False, "X", 0.0, [], None),
        generate_triage=gen,
        estimate=lambda **k: _est(actionable=False),
        reserves=lambda: (1.0, 1000.0),
        treasury_raw=lambda: 0,
        k_probe=lambda: "success",
    )
    gen.assert_called_once()
    flags = db.update_token_flags.call_args[0][1]
    assert flags["dynamic_status"] == "PAIR_K_BROKEN"
    assert flags.get("is_user_exploitable") == 1
    assert flags.get("expected_profit_eth", 0) >= 0.05


def test_broken_k_revert_keeps_factory_status():
    db = MagicMock()
    gen = MagicMock()
    process_factory_pair(
        db,
        "base",
        EV,
        load_source=lambda *a: "",
        audit=lambda src: ({}, []),
        verify=lambda *a: (False, "X", 0.0, [], None),
        generate_triage=gen,
        estimate=lambda **k: _est(actionable=False),
        reserves=lambda: (1.0, 1000.0),
        treasury_raw=lambda: 0,
        k_probe=lambda: "revert",
    )
    gen.assert_not_called()
    flags = db.update_token_flags.call_args[0][1]
    assert "FACTORY_NEW_PAIR_NO_SOURCE" in flags["dynamic_status"]
    assert "PAIR_K_REVERT" in flags["dynamic_status"]
    assert flags.get("is_user_exploitable") != 1


def test_overflow_without_executed_fork_is_not_queued():
    db = MagicMock()
    gen = MagicMock()
    hit = {
        "type": "BALANCE_OVERFLOW",
        "user_exploitable": True,
        "requires_live_fork": True,
        "severity": "CRITICAL",
        "title": "overflow",
        "exploiter": "e",
        "victim": "v",
        "payoff": "p",
        "snippet": "s",
    }
    process_factory_pair(
        db,
        "base",
        EV,
        load_source=lambda *a: "pragma solidity ^0.4.24; function transfer(address to, uint256 value) public { balances[msg.sender] -= value; }",
        audit=lambda src: ({"has_balance_overflow": True}, [hit]),
        verify=lambda *a: (True, "BALANCE_OVERFLOW_CANDIDATE", 0.0, [hit], {"expected_profit_eth": 0.9, "method": "unlimited_sell"}),
        generate_triage=gen,
        estimate=lambda **k: _est(actionable=False),
        reserves=lambda: (1.0, 1000.0),
        treasury_raw=lambda: 0,
    )
    gen.assert_not_called()
    flags = db.update_token_flags.call_args[0][1]
    assert "OVERFLOW_FORK_DISABLED" in flags["dynamic_status"]
    assert flags.get("is_user_exploitable") != 1


def test_split_fork_holds_overflow_when_gate_skipped():
    skip = ForkGateResult(passed=True, skipped=True, reason="disabled")
    ok = ForkGateResult(passed=True, skipped=False, reason="ok")
    plain = {"type": "PUBLIC_MINT"}
    held = {"type": "BALANCE_OVERFLOW", "requires_live_fork": True}
    emit, notes = split_fork_gated([plain, held], skip, skip)
    assert emit == [plain]
    assert notes == ["OVERFLOW_FORK_DISABLED"]
    emit_ok, notes_ok = split_fork_gated([held], skip, ok)
    assert emit_ok == [held]
    assert notes_ok == []


def test_schema_has_new_flag_columns():
    import os
    import tempfile

    from token_scanner_daemon import TokenScannerDB

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        db = TokenScannerDB(path)
        with db.get_connection() as conn:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(tokens)")}
        assert "has_public_mint" in cols
        assert "has_balance_overflow" in cols
        db.save_scan({
            "address": "0x" + "a" * 40,
            "has_public_mint": True,
            "has_balance_overflow": True,
            "verified": True,
        })
        with db.get_connection() as conn:
            row = conn.execute(
                "SELECT has_public_mint, has_balance_overflow FROM tokens WHERE address = ?",
                ("0x" + "a" * 40,),
            ).fetchone()
        assert row[0] in (1, True)
        assert row[1] in (1, True)
    finally:
        os.unlink(path)
