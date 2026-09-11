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
SKIM_TYPES = frozenset({"PAIR_SKIM"})
COLLECT_TYPES = frozenset({"V3_COLLECT_UNPROTECTED"})
SPOT_ORACLE_TYPES = frozenset({"SPOT_ORACLE_MANIPULATION"})
INFLATION_TYPES = frozenset({"ERC4626_INFLATION_ATTACK"})
AAVE_V3_FLASH_FEE = 0.0005
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


def xyk_amount_in(amount_out: float, reserve_in: float, reserve_out: float) -> float:
    """Uniswap V2 getAmountIn with 0.3% fee."""
    if amount_out <= 0 or reserve_in <= 0 or reserve_out <= 0 or amount_out >= reserve_out:
        return 0.0
    numerator = reserve_in * amount_out * 1000.0
    denominator = (reserve_out - amount_out) * 997.0
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


def estimate_skim_profit(
    *,
    pair_eth: float,
    pair_token: float,
    reserve_eth: float,
    reserve_token: float,
    gas_eth: float = DEFAULT_GAS_ETH,
    min_net_profit_eth: float = MIN_NET_PROFIT_ETH,
) -> ProfitEstimate:
    """UniV2 skim: excess balance above reserves, then sell leftover tokens."""
    excess_eth = max(0.0, float(pair_eth or 0.0) - float(reserve_eth or 0.0))
    excess_token = max(0.0, float(pair_token or 0.0) - float(reserve_token or 0.0))
    token_eth = 0.0
    if excess_token > 0 and reserve_token > 0 and reserve_eth > 0:
        token_eth = xyk_amount_out(excess_token, reserve_token, reserve_eth)
    gross = excess_eth + token_eth
    net = max(0.0, gross - gas_eth)
    return ProfitEstimate(
        expected_profit_eth=net,
        pool_eth=float(reserve_eth or 0.0),
        treasury_token_raw=0,
        sell_fraction=0.0,
        gas_eth=gas_eth,
        method="pair_skim",
        actionable=net >= min_net_profit_eth,
    )


def estimate_collect_profit(
    *,
    owed_weth: float,
    owed_token: float = 0.0,
    pool_eth: float = 0.0,
    pool_token: float = 0.0,
    gas_eth: float = DEFAULT_GAS_ETH,
    min_net_profit_eth: float = MIN_NET_PROFIT_ETH,
) -> ProfitEstimate:
    """V3 collect: fees owed in WETH plus selling owed token into the pool."""
    token_eth = 0.0
    if owed_token > 0 and pool_eth > 0 and pool_token > 0:
        token_eth = xyk_amount_out(owed_token, pool_token, pool_eth)
    gross = float(owed_weth or 0.0) + token_eth
    net = max(0.0, gross - gas_eth)
    return ProfitEstimate(
        expected_profit_eth=net,
        pool_eth=float(pool_eth or 0.0),
        treasury_token_raw=0,
        sell_fraction=0.0,
        gas_eth=gas_eth,
        method="v3_collect",
        actionable=net >= min_net_profit_eth,
    )


def _sandwich_roundtrip(
    pool_eth: float,
    pool_token: float,
    victim_token: float,
    front_token: float,
) -> float:
    """Gross attacker ETH sandwiching a token→ETH dump (sell tokens, victim dumps, buy back)."""
    if front_token <= 0 or victim_token <= 0 or pool_eth <= 0 or pool_token <= 0:
        return 0.0
    if front_token >= pool_token * 0.45:
        return 0.0
    eth_out = xyk_amount_out(front_token, pool_token, pool_eth)
    if eth_out <= 0 or eth_out >= pool_eth:
        return 0.0
    r_tok = pool_token + front_token
    r_eth = pool_eth - eth_out
    victim_eth = xyk_amount_out(victim_token, r_tok, r_eth)
    if victim_eth <= 0 or victim_eth >= r_eth:
        return 0.0
    r_tok2 = r_tok + victim_token
    r_eth2 = r_eth - victim_eth
    eth_in = xyk_amount_in(front_token, r_eth2, r_tok2)
    if eth_in <= 0:
        return 0.0
    return eth_out - eth_in


def estimate_attacker_sandwich_profit(
    *,
    pool_eth: float,
    pool_token: float,
    victim_token: float,
    gas_eth: float = DEFAULT_GAS_ETH,
    min_net_profit_eth: float = MIN_NET_PROFIT_ETH,
    min_pool_eth: float = MIN_POOL_ETH,
    treasury_token_raw: int = 0,
    sell_fraction: float = DEFAULT_SELL_FRACTION,
) -> ProfitEstimate:
    """Search a front-run size and return net attacker ETH after two swaps."""
    empty = ProfitEstimate(
        expected_profit_eth=0.0,
        pool_eth=float(pool_eth or 0.0),
        treasury_token_raw=treasury_token_raw,
        sell_fraction=sell_fraction,
        gas_eth=gas_eth * 2.0,
        method="sandwich_xyk",
        actionable=False,
    )
    if pool_eth < min_pool_eth or pool_token <= 0 or victim_token <= 0:
        return empty
    best = 0.0
    two_gas = gas_eth * 2.0
    for i in range(1, 25):
        front_tok = pool_token * (i / 50.0)
        gross = _sandwich_roundtrip(pool_eth, pool_token, victim_token, front_tok)
        net = gross - two_gas
        if net > best:
            best = net
    return ProfitEstimate(
        expected_profit_eth=max(0.0, best),
        pool_eth=pool_eth,
        treasury_token_raw=treasury_token_raw,
        sell_fraction=sell_fraction,
        gas_eth=two_gas,
        method="sandwich_xyk",
        actionable=best >= min_net_profit_eth,
    )


def _oracle_roundtrip(dump_eth: float, pool_eth: float, pool_token: float):
    """Dump ETH into a V2 pool and sell the tokens back. Returns (loss, p0, p1) or None."""
    if dump_eth <= 0 or dump_eth >= pool_eth * 0.9 or pool_token <= 0:
        return None
    tokens_out = xyk_amount_out(dump_eth, pool_eth, pool_token)
    if tokens_out <= 0 or tokens_out >= pool_token:
        return None
    r_eth = pool_eth + dump_eth
    r_tok = pool_token - tokens_out
    if r_tok <= 0:
        return None
    eth_back = xyk_amount_out(tokens_out, r_tok, r_eth)
    if eth_back <= 0:
        return None
    p0 = pool_eth / pool_token
    p1 = r_eth / r_tok
    return dump_eth - eth_back, p0, p1


def estimate_spot_oracle_profit(
    *,
    pool_eth: float,
    protocol_eth: float,
    pool_token: float = 1_000_000.0,
    gas_eth: float = DEFAULT_GAS_ETH,
    min_net_profit_eth: float = MIN_NET_PROFIT_ETH,
    flash_fee: float = AAVE_V3_FLASH_FEE,
) -> ProfitEstimate:
    """Net ETH if a flash loan moves spot on a thin V2 oracle vs a fat vault.

    Extractable is protocol_eth * min(1, |price_after/price_before - 1|).
    Cost is AMM round-trip + Aave-style flash fee + gas. No RPC.
    """
    empty = ProfitEstimate(
        expected_profit_eth=0.0,
        pool_eth=float(pool_eth or 0.0),
        treasury_token_raw=0,
        sell_fraction=0.0,
        gas_eth=gas_eth,
        method="none",
        actionable=False,
    )
    R = float(pool_eth or 0.0)
    T = float(pool_token or 0.0)
    P = float(protocol_eth or 0.0)
    if R <= 0 or T <= 0 or P <= 0:
        return empty
    best = 0.0
    for frac in (0.05, 0.1, 0.25, 0.5, 1.0, 2.0):
        d = min(frac * R, R * 0.89)
        trip = _oracle_roundtrip(d, R, T)
        if trip is None:
            continue
        loss, p0, p1 = trip
        if p0 <= 0:
            continue
        move = abs(p1 / p0 - 1.0)
        extracted = P * min(1.0, move)
        net = extracted - loss - flash_fee * d - gas_eth
        if net > best:
            best = net
    # Vault must be at least as large as the oracle pool (thin AMM, fat protocol).
    fat_vault = P >= R
    return ProfitEstimate(
        expected_profit_eth=max(0.0, best),
        pool_eth=R,
        treasury_token_raw=0,
        sell_fraction=0.0,
        gas_eth=gas_eth,
        method="spot_oracle_xyk",
        actionable=fat_vault and best >= min_net_profit_eth,
    )


def estimate_vault_inflation_profit(
    *,
    total_supply_raw: int,
    asset_eth: float,
    gas_eth: float = DEFAULT_GAS_ETH,
    min_net_profit_eth: float = MIN_NET_PROFIT_ETH,
) -> ProfitEstimate:
    """First depositor takes an empty vault that already holds a donation.

    Only supply==0 is user-exploitable for us (we can still be first).
    Seeded vaults already belong to whoever minted the 1-wei share.
    """
    empty = ProfitEstimate(
        expected_profit_eth=0.0,
        pool_eth=0.0,
        treasury_token_raw=0,
        sell_fraction=0.0,
        gas_eth=gas_eth,
        method="none",
        actionable=False,
    )
    if int(total_supply_raw or 0) != 0:
        return empty
    eth = float(asset_eth or 0.0)
    if eth <= 0:
        return empty
    net = max(0.0, eth - gas_eth)
    return ProfitEstimate(
        expected_profit_eth=net,
        pool_eth=0.0,
        treasury_token_raw=0,
        sell_fraction=0.0,
        gas_eth=gas_eth,
        method="vault_inflation",
        actionable=net >= min_net_profit_eth,
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
            last = estimate_attacker_sandwich_profit(
                pool_eth=pool_eth,
                pool_token=pool_token,
                victim_token=sell or whole_tokens,
                gas_eth=gas_eth,
                min_net_profit_eth=min_net_profit_eth,
                sell_fraction=sell_fraction,
                treasury_token_raw=raw,
            )
            if last.actionable:
                kept.append(exp)
            else:
                notes.append(
                    f"PROFIT_BELOW_THRESHOLD_SANDWICH_{last.expected_profit_eth:.4f}ETH"
                )
        elif vtype in SKIM_TYPES:
            # eth_balance is treated as excess WETH sitting on the pair (pair - reserve).
            last = estimate_skim_profit(
                pair_eth=eth_balance + pool_eth,
                pair_token=pool_token,
                reserve_eth=pool_eth,
                reserve_token=pool_token,
                gas_eth=gas_eth,
                min_net_profit_eth=min_net_profit_eth,
            )
            if last.actionable:
                kept.append(exp)
            else:
                notes.append(
                    f"PROFIT_BELOW_THRESHOLD_SKIM_{last.expected_profit_eth:.4f}ETH"
                )
        elif vtype in COLLECT_TYPES:
            last = estimate_collect_profit(
                owed_weth=eth_balance,
                owed_token=whole_tokens,
                pool_eth=pool_eth,
                pool_token=pool_token,
                gas_eth=gas_eth,
                min_net_profit_eth=min_net_profit_eth,
            )
            if last.actionable:
                kept.append(exp)
            else:
                notes.append(
                    f"PROFIT_BELOW_THRESHOLD_COLLECT_{last.expected_profit_eth:.4f}ETH"
                )
        elif vtype in INFLATION_TYPES:
            last = estimate_vault_inflation_profit(
                total_supply_raw=0,
                asset_eth=float(exp.get("_asset_eth") or erc20_eth_equiv or 0.0),
                gas_eth=gas_eth,
                min_net_profit_eth=min_net_profit_eth,
            )
            if last.actionable:
                kept.append(exp)
            else:
                notes.append(
                    f"PROFIT_BELOW_THRESHOLD_VAULT_{last.expected_profit_eth:.4f}ETH"
                )
        elif vtype in SPOT_ORACLE_TYPES:
            last = estimate_spot_oracle_profit(
                pool_eth=pool_eth,
                protocol_eth=float(eth_balance or 0.0) + float(erc20_eth_equiv or 0.0),
                pool_token=pool_token,
                gas_eth=gas_eth,
                min_net_profit_eth=min_net_profit_eth,
            )
            if last.actionable:
                kept.append(exp)
            else:
                notes.append(
                    f"PROFIT_BELOW_THRESHOLD_ORACLE_{last.expected_profit_eth:.4f}ETH"
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
