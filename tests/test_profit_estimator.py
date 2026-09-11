"""Unit tests for XYK / native profit estimates (no RPC)."""

from profit_estimator import (
    MIN_NET_PROFIT_ETH,
    MIN_POOL_ETH,
    ProfitEstimate,
    apply_profit_gate,
    estimate_attacker_sandwich_profit,
    estimate_collect_profit,
    estimate_native_drain_profit,
    estimate_skim_profit,
    estimate_spot_oracle_profit,
    estimate_swapback_sandwich_profit,
    estimate_vault_inflation_profit,
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
        pool_eth=50.0,
        pool_token=1_000_000.0,
        treasury_token_raw=80_000 * 10**18,
        sell_fraction=1.0,
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


def test_skim_excess_weth_is_actionable():
    est = estimate_skim_profit(
        pair_eth=1.2,
        pair_token=1000.0,
        reserve_eth=1.0,
        reserve_token=1000.0,
    )
    assert est.method == "pair_skim"
    assert est.actionable is True
    assert abs(est.expected_profit_eth - (0.2 - 0.002)) < 1e-9


def test_skim_dust_excess_not_actionable():
    est = estimate_skim_profit(
        pair_eth=1.001,
        pair_token=1000.0,
        reserve_eth=1.0,
        reserve_token=1000.0,
    )
    assert est.actionable is False


def test_collect_owed_weth_actionable():
    est = estimate_collect_profit(owed_weth=0.2, owed_token=0.0)
    assert est.method == "v3_collect"
    assert est.actionable is True


def test_sandwich_fat_dump_is_actionable():
    est = estimate_attacker_sandwich_profit(
        pool_eth=50.0,
        pool_token=1_000_000.0,
        victim_token=80_000.0,
    )
    assert est.method == "sandwich_xyk"
    assert est.actionable is True
    assert est.expected_profit_eth >= MIN_NET_PROFIT_ETH


def test_sandwich_dust_dump_not_actionable():
    est = estimate_attacker_sandwich_profit(
        pool_eth=0.2,
        pool_token=10_000.0,
        victim_token=10.0,
    )
    assert est.actionable is False


def test_profit_gate_keeps_sandwichable_swapback():
    confirmed = [{"type": "PUBLIC_SWAPBACK_TRIGGER"}]
    kept, notes, est = apply_profit_gate(
        confirmed,
        eth_balance=0.0,
        pool_eth=50.0,
        pool_token=1_000_000.0,
        treasury_token_raw=80_000 * 10**18,
        sell_fraction=1.0,
        enabled=True,
    )
    assert len(kept) == 1
    assert est is not None and est.method == "sandwich_xyk" and est.actionable


def test_profit_gate_collect_uses_owed_native():
    confirmed = [{"type": "V3_COLLECT_UNPROTECTED"}]
    kept, _notes, est = apply_profit_gate(
        confirmed,
        eth_balance=0.2,
        pool_eth=10.0,
        pool_token=10_000.0,
        treasury_token_raw=0,
    )
    assert len(kept) == 1
    assert est is not None and est.method == "v3_collect"


def test_profit_gate_enabled_env(monkeypatch):
    monkeypatch.setenv("FOMO_PROFIT_GATE", "0")
    from profit_estimator import profit_gate_enabled
    assert profit_gate_enabled() is False
    monkeypatch.setenv("FOMO_PROFIT_GATE", "1")
    assert profit_gate_enabled() is True


def test_spot_oracle_thin_pool_fat_vault_is_actionable():
    est = estimate_spot_oracle_profit(
        pool_eth=0.2,
        protocol_eth=5.0,
        pool_token=1_000_000.0,
    )
    assert est.method == "spot_oracle_xyk"
    assert est.actionable is True
    assert est.expected_profit_eth > 1.0


def test_spot_oracle_deep_pool_tiny_vault_fails():
    est = estimate_spot_oracle_profit(
        pool_eth=50.0,
        protocol_eth=0.2,
        pool_token=1_000_000.0,
    )
    assert est.method == "spot_oracle_xyk"
    assert est.actionable is False


def test_spot_oracle_zero_pool_is_none():
    est = estimate_spot_oracle_profit(pool_eth=0.0, protocol_eth=10.0)
    assert est.method == "none"
    assert est.actionable is False


def test_spot_oracle_monotonic_in_protocol_over_pool():
    thin = estimate_spot_oracle_profit(pool_eth=0.5, protocol_eth=4.0, pool_token=1e6)
    fat_pool = estimate_spot_oracle_profit(pool_eth=4.0, protocol_eth=0.5, pool_token=1e6)
    assert thin.expected_profit_eth > fat_pool.expected_profit_eth


def test_profit_gate_spot_oracle_keeps_thin_fat():
    confirmed = [{"type": "SPOT_ORACLE_MANIPULATION"}]
    kept, notes, est = apply_profit_gate(
        confirmed,
        eth_balance=5.0,
        pool_eth=0.2,
        pool_token=1_000_000.0,
    )
    assert kept == confirmed
    assert est is not None and est.method == "spot_oracle_xyk"
    assert est.actionable is True
    assert notes == []


def test_profit_gate_spot_oracle_drops_deep_pool():
    confirmed = [{"type": "SPOT_ORACLE_MANIPULATION"}]
    kept, notes, est = apply_profit_gate(
        confirmed,
        eth_balance=0.2,
        pool_eth=50.0,
        pool_token=1_000_000.0,
    )
    assert kept == []
    assert est is not None and est.actionable is False
    assert any("ORACLE" in n for n in notes)


def test_vault_inflation_empty_donation_is_actionable():
    est = estimate_vault_inflation_profit(total_supply_raw=0, asset_eth=5.0)
    assert est.method == "vault_inflation"
    assert est.actionable is True
    assert est.expected_profit_eth > 4.0


def test_vault_inflation_unseeded_empty_fails():
    est = estimate_vault_inflation_profit(total_supply_raw=0, asset_eth=0.0)
    assert est.actionable is False


def test_vault_inflation_already_seeded_fails():
    est = estimate_vault_inflation_profit(total_supply_raw=1, asset_eth=5.0)
    assert est.actionable is False


def test_profit_gate_ror_uses_asset_eth():
    confirmed = [{"type": "READ_ONLY_REENTRANCY", "_asset_eth": 1.0}]
    kept, notes, est = apply_profit_gate(confirmed, eth_balance=0.0)
    assert kept == confirmed
    assert est is not None and est.actionable is True
    assert notes == []


def test_profit_gate_ror_dust_drops():
    confirmed = [{"type": "READ_ONLY_REENTRANCY", "_asset_eth": 0.01}]
    kept, notes, est = apply_profit_gate(confirmed, eth_balance=0.0)
    assert kept == []
    assert any("ROR" in n for n in notes)


def test_profit_gate_clmm_never_keeps():
    confirmed = [{"type": "CLMM_TICK_ROUNDING"}]
    kept, notes, _est = apply_profit_gate(confirmed, eth_balance=10.0, pool_eth=10.0)
    assert kept == []
    assert any("UNMODELED_CLMM" in n for n in notes)


def test_profit_gate_vault_inflation_uses_asset_eth():
    confirmed = [{"type": "ERC4626_INFLATION_ATTACK", "_asset_eth": 1.0}]
    kept, notes, est = apply_profit_gate(
        confirmed,
        eth_balance=0.0,
        pool_eth=0.0,
        pool_token=0.0,
    )
    assert kept == confirmed
    assert est is not None and est.method == "vault_inflation"
    assert notes == []


def test_profit_gate_vault_inflation_dust_drops():
    confirmed = [{"type": "ERC4626_INFLATION_ATTACK", "_asset_eth": 0.01}]
    kept, notes, est = apply_profit_gate(confirmed, eth_balance=0.0)
    assert kept == []
    assert est is not None and est.actionable is False
    assert any("VAULT" in n for n in notes)


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
