"""Compare cached vs live snapshots to skip no-op re-audits."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional

MIN_ETH_DELTA = 0.01
MIN_POOL_DELTA = 0.05
MIN_TREASURY_DELTA = 1.0


@dataclass(frozen=True)
class StateSnapshot:
    eth_balance: float = 0.0
    pool_eth: float = 0.0
    treasury_tokens: float = 0.0
    swap_enabled: Optional[bool] = None
    erc20_treasury_eth: float = 0.0
    pair: Optional[str] = None


def snapshot_to_dict(snap: StateSnapshot) -> Dict[str, Any]:
    return asdict(snap)


def snapshot_from_dict(data: Optional[Dict[str, Any]]) -> Optional[StateSnapshot]:
    if not data:
        return None
    try:
        se = data.get("swap_enabled")
        if isinstance(se, str):
            se_l = se.strip().lower()
            se = None if se_l in {"", "none", "null"} else se_l not in {"0", "false", "no", "off"}
        elif se is not None:
            se = bool(se)
        return StateSnapshot(
            eth_balance=float(data.get("eth_balance") or 0.0),
            pool_eth=float(data.get("pool_eth") or 0.0),
            treasury_tokens=float(data.get("treasury_tokens") or 0.0),
            swap_enabled=se,
            erc20_treasury_eth=float(data.get("erc20_treasury_eth") or 0.0),
            pair=(str(data["pair"]).lower() if data.get("pair") else None),
        )
    except (TypeError, ValueError):
        return None


def should_wakeup(
    prev: Optional[StateSnapshot],
    curr: StateSnapshot,
    *,
    min_eth_delta: float = MIN_ETH_DELTA,
    min_pool_delta: float = MIN_POOL_DELTA,
    min_treasury_delta: float = MIN_TREASURY_DELTA,
) -> bool:
    """True = run full liveness/profit; False = snapshot unchanged, skip."""
    if prev is None:
        return True
    if abs(curr.eth_balance - prev.eth_balance) >= min_eth_delta:
        return True
    if abs(curr.pool_eth - prev.pool_eth) >= min_pool_delta:
        return True
    if abs(curr.treasury_tokens - prev.treasury_tokens) >= min_treasury_delta:
        return True
    if abs(curr.erc20_treasury_eth - prev.erc20_treasury_eth) >= min_eth_delta:
        return True
    if curr.swap_enabled is not None and curr.swap_enabled != prev.swap_enabled:
        return True
    return False
