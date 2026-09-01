"""Unit tests for XYK / native profit estimates (no RPC)."""

from profit_estimator import (
    MIN_NET_PROFIT_ETH,
    MIN_POOL_ETH,
    ProfitEstimate,
    apply_profit_gate,
    estimate_native_drain_profit,
    estimate_swapback_sandwich_profit,
    xyk_amount_out,
)


def test_xyk_amount_out_matches_uniswap_v2():
    # 2650 tokens into 52192 token / 0.00056 ETH (LaunchDay-scale dust)
    out = xyk_amount_out(2650.0, 52192.0, 0.0005606)
    assert 0.00002 < out < 0.00004


def test_dust_pool_not_actionable():
    est = estimate_swapback_sandwich_profit(
        pool_eth=0.00056,
        pool_token=52192.0,
        sell_token=2650.0,
    )
    assert est.method == "xyk_spot"
    assert est.actionable is False
    assert est.expected_profit_eth < MIN_NET_PROFIT_ETH


def test_fat_pool_large_sell_is_actionable():
    est = estimate_swapback_sandwich_profit(
        pool_eth=20.0,
        pool_token=1_000_000.0,
        sell_token=50_000.0,
        gas_eth=0.002,
        min_net_profit_eth=0.05,
    )
    assert est.actionable is True
    assert est.expected_profit_eth > 0.05


def test_gas_eats_profit():
    est = estimate_swapback_sandwich_profit(
        pool_eth=0.2,
        pool_token=10_000.0,
        sell_token=500.0,
        gas_eth=0.15,
        min_net_profit_eth=0.05,
    )
    assert est.actionable is False


def test_zero_reserves_method_none():
    est = estimate_swapback_sandwich_profit(
        pool_eth=0.0,
        pool_token=0.0,
        sell_token=100.0,
    )
    assert est.method == "none"
    assert est.actionable is False
    assert est.expected_profit_eth == 0.0


def test_pool_below_dust_floor():
    est = estimate_swapback_sandwich_profit(
        pool_eth=0.04,
        pool_token=1_000.0,
        sell_token=100.0,
    )
    assert est.pool_eth < MIN_POOL_ETH
    assert est.actionable is False


def test_native_drain_dust_wei_not_actionable():
    est = estimate_native_drain_profit(eth_balance=1e-18)
    assert est.method == "native_balance"
    assert est.actionable is False


def test_native_drain_funded_is_actionable():
    est = estimate_native_drain_profit(eth_balance=1.5)
    assert est.actionable is True
    assert est.expected_profit_eth >= MIN_NET_PROFIT_ETH


def test_profit_gate_filters_public_swapback_dust():
    confirmed = [{"type": "PUBLIC_SWAPBACK_TRIGGER"}]
    kept, notes, est = apply_profit_gate(
        confirmed,
        eth_balance=0.0,
        pool_eth=0.0006,
        pool_token=50_000.0,
        treasury_token_raw=10_000 * 10**18,
        enabled=True,
    )
    assert kept == []
    assert any("PROFIT_BELOW_THRESHOLD" in n for n in notes)
    assert est is not None and est.actionable is False
    assert est.treasury_token_raw == 10_000 * 10**18


def test_profit_gate_keeps_profitable_swapback():
    confirmed = [{"type": "ZERO_SLIPPAGE_LIQUIDATION"}]
    kept, notes, est = apply_profit_gate(
        confirmed,
        eth_balance=0.0,
        pool_eth=25.0,
        pool_token=500_000.0,
        treasury_token_raw=80_000 * 10**18,
        enabled=True,
    )
    assert len(kept) == 1
    assert est is not None and est.actionable is True
    assert notes == []
    assert est.treasury_token_raw == 80_000 * 10**18


def test_profit_gate_disabled_passthrough():
    confirmed = [{"type": "PUBLIC_SWAPBACK_TRIGGER"}]
    kept, notes, est = apply_profit_gate(
        confirmed,
        eth_balance=0.0,
        pool_eth=0.0001,
        pool_token=1.0,
        treasury_token_raw=10**18,
        enabled=False,
    )
    assert kept == confirmed
    assert notes == []
    assert est is None


def test_profit_gate_enabled_env(monkeypatch):
    monkeypatch.setenv("FOMO_PROFIT_GATE", "0")
    from profit_estimator import profit_gate_enabled
    assert profit_gate_enabled() is False
    monkeypatch.setenv("FOMO_PROFIT_GATE", "1")
    assert profit_gate_enabled() is True


def test_profit_estimate_frozen_dataclass():
    est = ProfitEstimate(
        expected_profit_eth=0.0,
        pool_eth=0.0,
        treasury_token_raw=0,
        sell_fraction=0.25,
        gas_eth=0.002,
        method="none",
        actionable=False,
    )
    assert est.actionable is False
