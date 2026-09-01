"""Map ERC-20 balances on a target to an ETH-equivalent (no live oracle)."""

from __future__ import annotations

import os
from typing import Mapping

# chain -> {token: decimals} for stables; WETH is 1:1 via DEX_CONFIG weth.
DEFAULT_STABLES = {
    "ethereum": {
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": 6,  # USDC
        "0xdac17f958d2ee523a2206206994597c13d831ec7": 6,  # USDT
    },
    "base": {
        "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": 6,  # USDC
        "0xfde4c96c8593536e31f229ea8f37b2ada2699bb2": 6,  # USDT
    },
    "arbitrum": {
        "0xaf88d065e77c8cc2239327c5edb3a432268e5831": 6,  # USDC
        "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9": 6,  # USDT
    },
}


def eth_usd_rate() -> float:
    try:
        return float(os.environ.get("FOMO_ETH_USD") or "2500")
    except ValueError:
        return 2500.0


def eth_equiv_from_balances(
    balances_raw: Mapping[str, int],
    *,
    weth: str,
    stables: Mapping[str, int],
    eth_usd: float | None = None,
) -> float:
    """WETH 1:1; stables use eth_usd (USD per ETH) and token decimals."""
    px = float(eth_usd if eth_usd is not None else eth_usd_rate())
    if px <= 0:
        px = 2500.0
    weth_l = weth.lower()
    stables_l = {k.lower(): int(d) for k, d in stables.items()}
    total = 0.0
    for token, raw in balances_raw.items():
        t = token.lower()
        amt = int(raw or 0)
        if amt <= 0:
            continue
        if t == weth_l:
            total += amt / 1e18
        elif t in stables_l:
            dec = stables_l[t]
            usd = amt / (10 ** dec)
            total += usd / px
    return total
