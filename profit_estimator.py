"""Pure profit estimates for triage gating (no RPC)."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

MIN_NET_PROFIT_ETH = 0.05
MIN_POOL_ETH = 0.05
DEFAULT_GAS_ETH = 0.002
DEFAULT_SELL_FRACTION = 0.25

XYK_TYPES = frozenset({
    "ZERO_SLIPPAGE_LIQUIDATION",
    "PUBLIC_SWAPBACK_TRIGGER",
})
NATIVE_DRAIN_TYPES = frozenset({
    "BROKEN_ACCESS_CONTROL",
    "UNPROTECTED_INITIALIZER_HIJACK",
    "UNCONSTRAINED_ARBITRARY_CALL",
    "CHECKS_EFFECTS_REENTRANCY",
    "MULTICALL_MSGVALUE_REUSE",
    "FEE_ON_TRANSFER_INVARIANT",
})


@dataclass(frozen=True)
class ProfitEstimate:
    expected_profit_eth: float
    pool_eth: float
    treasury_token_raw: int
    sell_fraction: float
    gas_eth: float
    method: str  # xyk_spot | native_balance | none
    actionable: bool


def xyk_amount_out(amount_in: float, reserve_in: float, reserve_out: float) -> float:
    """Uniswap V2 getAmountOut with 0.3% fee."""
    if amount_in <= 0 or reserve_in <= 0 or reserve_out <= 0:
        return 0.0
    amount_in_with_fee = amount_in * 997.0
    numerator = amount_in_with_fee * reserve_out
    denominator = reserve_in * 1000.0 + amount_in_with_fee
    if denominator <= 0:
        return 0.0
    return numerator / denominator


def estimate_swapback_sandwich_profit(
    *,
    pool_eth: float,
    pool_token: float,
    sell_token: float,
    gas_eth: float = DEFAULT_GAS_ETH,
    min_net_profit_eth: float = MIN_NET_PROFIT_ETH,
    min_pool_eth: float = MIN_POOL_ETH,
    sell_fraction: float = DEFAULT_SELL_FRACTION,
    treasury_token_raw: int = 0,
) -> ProfitEstimate:
    if pool_eth <= 0 or pool_token <= 0 or sell_token <= 0:
        return ProfitEstimate(
            expected_profit_eth=0.0,
            pool_eth=float(pool_eth or 0.0),
            treasury_token_raw=treasury_token_raw,
            sell_fraction=sell_fraction,
            gas_eth=gas_eth,
            method="none",
            actionable=False,
        )
    eth_out = xyk_amount_out(sell_token, pool_token, pool_eth)
    net = eth_out - gas_eth
    actionable = pool_eth >= min_pool_eth and net >= min_net_profit_eth
    return ProfitEstimate(
        expected_profit_eth=max(0.0, net),
        pool_eth=pool_eth,
        treasury_token_raw=treasury_token_raw,
        sell_fraction=sell_fraction,
        gas_eth=gas_eth,
        method="xyk_spot",
        actionable=actionable,
    )


def estimate_native_drain_profit(
    eth_balance: float,
    *,
    erc20_eth_equiv: float = 0.0,
    gas_eth: float = DEFAULT_GAS_ETH,
    min_net_profit_eth: float = MIN_NET_PROFIT_ETH,
) -> ProfitEstimate:
    gross = float(eth_balance or 0.0) + float(erc20_eth_equiv or 0.0)
    net = max(0.0, gross - gas_eth)
    method = "native_plus_erc20" if erc20_eth_equiv else "native_balance"
    return ProfitEstimate(
        expected_profit_eth=net,
        pool_eth=0.0,
        treasury_token_raw=0,
        sell_fraction=0.0,
        gas_eth=gas_eth,
        method=method,
        actionable=net >= min_net_profit_eth,
    )


def profit_to_dict(est: Optional[ProfitEstimate]) -> Optional[Dict[str, Any]]:
    if est is None:
        return None
    payload = asdict(est)
    payload["gate"] = "PASS" if est.actionable else "FAIL"
    return payload


def profit_gate_enabled() -> bool:
    raw = os.environ.get("FOMO_PROFIT_GATE", "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def apply_profit_gate(
    confirmed: Sequence[Dict[str, Any]],
    *,
    eth_balance: float,
    pool_eth: float = 0.0,
    pool_token: float = 0.0,
    treasury_token_raw: int = 0,
    token_decimals: int = 18,
    erc20_eth_equiv: float = 0.0,
    sell_fraction: float = DEFAULT_SELL_FRACTION,
    enabled: bool = True,
    gas_eth: float = DEFAULT_GAS_ETH,
    min_net_profit_eth: float = MIN_NET_PROFIT_ETH,
) -> Tuple[List[Dict[str, Any]], List[str], Optional[ProfitEstimate]]:
    """Filter confirmed exploits that cannot pay net of gas.

    ``treasury_token_raw`` is the ERC-20 ``balanceOf`` in base units (wei-scale).
    Returns (kept_exploits, status_notes, last_estimate).
    """
    if not enabled:
        return list(confirmed), [], None

    kept: List[Dict[str, Any]] = []
    notes: List[str] = []
    last: Optional[ProfitEstimate] = None
    scale = 10 ** int(token_decimals)
    raw = int(treasury_token_raw or 0)
    whole_tokens = raw / scale if raw else 0.0
    sell = whole_tokens * sell_fraction if whole_tokens else 0.0

    for exp in confirmed:
        vtype = exp.get("type") or ""
        if vtype in XYK_TYPES:
            last = estimate_swapback_sandwich_profit(
                pool_eth=pool_eth,
                pool_token=pool_token,
                sell_token=sell or whole_tokens,
                gas_eth=gas_eth,
                min_net_profit_eth=min_net_profit_eth,
                sell_fraction=sell_fraction,
                treasury_token_raw=raw,
            )
            if last.actionable:
                kept.append(exp)
            else:
                notes.append(
                    f"PROFIT_BELOW_THRESHOLD_XYK_{last.expected_profit_eth:.4f}ETH"
                )
        elif vtype in NATIVE_DRAIN_TYPES:
            last = estimate_native_drain_profit(
                eth_balance,
                erc20_eth_equiv=erc20_eth_equiv,
                gas_eth=gas_eth,
                min_net_profit_eth=min_net_profit_eth,
            )
            if last.actionable:
                kept.append(exp)
            else:
                notes.append(
                    f"PROFIT_BELOW_THRESHOLD_NATIVE_{last.expected_profit_eth:.4f}ETH"
                )
        else:
            last = estimate_native_drain_profit(
                eth_balance,
                erc20_eth_equiv=erc20_eth_equiv,
                gas_eth=gas_eth,
                min_net_profit_eth=min_net_profit_eth,
            )
            if last.actionable or (
                pool_eth >= MIN_POOL_ETH and last.expected_profit_eth >= min_net_profit_eth
            ):
                kept.append(exp)
            else:
                notes.append(
                    f"PROFIT_BELOW_THRESHOLD_{vtype}_{eth_balance:.4f}ETH"
                )

    return kept, notes, last
