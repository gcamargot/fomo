"""Factory pair → profit gate → optional triage (no RPC)."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from factory_listener import process_factory_pair
from profit_estimator import ProfitEstimate


EV = {
    "token": "0x1111111111111111111111111111111111111111",
    "pair": "0x2222222222222222222222222222222222222222",
    "weth": "0x4200000000000000000000000000000000000006",
}


def _est(*, actionable, profit=0.0, pool=0.001):
    return ProfitEstimate(
        expected_profit_eth=profit,
        pool_eth=pool,
        treasury_token_raw=0,
        sell_fraction=0.25,
        gas_eth=0.002,
        method="xyk_spot",
        actionable=actionable,
    )


def test_unverified_dust_writes_profit_no_triage():
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
        estimate=lambda **k: _est(actionable=False, profit=0.0, pool=0.001),
        reserves=lambda: (0.001, 1000.0),
        treasury_raw=lambda: 0,
    )
    db.ensure_token_row.assert_called()
    db.update_token_flags.assert_called()
    flags = db.update_token_flags.call_args[0][1]
    assert flags["dynamic_status"].startswith("FACTORY_NEW_PAIR")
    assert EV["pair"] in flags["state_snapshot"]
    assert "verified" not in flags
    gen.assert_not_called()


def test_verified_swapback_fat_pool_emits_triage():
    db = MagicMock()
    gen = MagicMock(return_value="/tmp/t.md")
    process_factory_pair(
        db,
        "base",
        EV,
        load_source=lambda *a: "function swapBack() public {}",
        audit=lambda src: ({"has_public_swapback": True}, [{"user_exploitable": True, "type": "PUBLIC_SWAPBACK_TRIGGER"}]),
        verify=lambda *a: (True, "PUBLIC_SWAPBACK_ACTIVE", 0.0, [{"type": "PUBLIC_SWAPBACK_TRIGGER", "severity": "HIGH", "title": "x", "exploiter": "e", "victim": "v", "payoff": "p", "snippet": ""}], {"expected_profit_eth": 0.5, "gate": "PASS", "method": "xyk_spot", "pool_eth": 20.0, "actionable": True}),
        generate_triage=gen,
        estimate=lambda **k: _est(actionable=True, profit=0.5, pool=20.0),
        reserves=lambda: (20.0, 500_000.0),
        treasury_raw=lambda: 80_000 * 10**18,
        fork_result=SimpleNamespace(passed=True, skipped=True, reason="disabled"),
    )
    gen.assert_called_once()
    flags = db.update_token_flags.call_args[0][1]
    assert flags.get("is_user_exploitable") == 1
    assert flags.get("verified") == 1
    assert flags.get("has_public_swapback") == 1
    assert EV["pair"] in flags["state_snapshot"]


def test_fork_run_skipped_when_not_emitting():
    db = MagicMock()
    ran = []
    process_factory_pair(
        db,
        "base",
        EV,
        load_source=lambda *a: "",
        audit=lambda src: ({}, []),
        verify=lambda *a: (True, "X", 0.0, [{"type": "x"}], None),
        generate_triage=MagicMock(),
        estimate=lambda **k: _est(actionable=False),
        reserves=lambda: (0.001, 1.0),
        treasury_raw=lambda: 0,
        fork_run=lambda: ran.append("ran") or SimpleNamespace(passed=True, skipped=False, reason="ok"),
    )
    assert ran == []
