"""ERC-20 treasury → ETH-equivalent (no RPC)."""

from erc20_treasury import eth_equiv_from_balances
from profit_estimator import apply_profit_gate


def test_weth_one_to_one():
    weth = "0x4200000000000000000000000000000000000006"
    eth = eth_equiv_from_balances(
        {weth: 10 * 10**18},
        weth=weth,
        stables={},
        eth_usd=2500.0,
    )
    assert abs(eth - 10.0) < 1e-9


def test_usdc_uses_eth_usd():
    usdc = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
    eth = eth_equiv_from_balances(
        {usdc: 10_000 * 10**6},
        weth="0x4200000000000000000000000000000000000006",
        stables={usdc: 6},
        eth_usd=2500.0,
    )
    assert abs(eth - 4.0) < 1e-9


def test_dust_usdc_not_actionable_via_gate():
    kept, notes, est = apply_profit_gate(
        [{"type": "BROKEN_ACCESS_CONTROL"}],
        eth_balance=0.0,
        erc20_eth_equiv=0.001,
        enabled=True,
    )
    assert kept == []
    assert est is not None and est.actionable is False


def test_broken_access_with_erc20_treasury_passes():
    kept, notes, est = apply_profit_gate(
        [{"type": "BROKEN_ACCESS_CONTROL"}],
        eth_balance=0.0,
        erc20_eth_equiv=2.0,
        enabled=True,
    )
    assert len(kept) == 1
    assert est is not None and est.actionable is True
    assert est.method == "native_plus_erc20"
