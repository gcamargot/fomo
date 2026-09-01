"""Opportunity watchlist: who to re-check (not 0-ETH-only)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

BUCKET_UNFUNDED_DRAIN = "unfunded_drain"
BUCKET_SLEEPING_TAX = "sleeping_tax"
BUCKET_NEAR_MISS = "near_miss"

DRAIN_FLAG_COLUMNS = (
    "has_unprotected_initializer",
    "has_unprotected_critical_function",
    "has_reentrancy_flaw",
    "has_signature_replay_flaw",
    "has_vault_inflation",
    "has_flash_staking_flaw",
    "has_arbitrary_call",
    "has_fee_on_transfer_flaw",
    "has_spot_oracle_flaw",
    "has_tx_origin_auth",
    "has_unprotected_router_setter",
    "has_permit_no_nonce",
    "has_multicall_msgvalue",
)

WATCHLIST_SELECT_COLUMNS = (
    "address",
    "chain",
    "name",
    "compiler",
    "category",
    "dynamic_status",
    "eth_balance",
    "has_zero_slippage",
    "has_public_swapback",
    "expected_profit_eth",
    "last_checked_at",
    "next_check_at",
    "state_snapshot",
    *DRAIN_FLAG_COLUMNS,
)


def init_watchlist_schema(conn) -> None:
    """Minimal tokens table for unit tests / in-memory fixtures."""
    drain_defs = ",\n        ".join(f"{c} INTEGER DEFAULT 0" for c in DRAIN_FLAG_COLUMNS)
    conn.execute(
        f"""
        CREATE TABLE IF NOT EXISTS tokens (
            address TEXT PRIMARY KEY,
            chain TEXT,
            name TEXT,
            compiler TEXT,
            category TEXT,
            verified INTEGER DEFAULT 0,
            is_user_exploitable INTEGER DEFAULT 0,
            dynamic_status TEXT,
            eth_balance REAL DEFAULT 0,
            has_zero_slippage INTEGER DEFAULT 0,
            has_public_swapback INTEGER DEFAULT 0,
            expected_profit_eth REAL,
            last_checked_at TEXT,
            next_check_at TEXT,
            watch_bucket TEXT,
            state_snapshot TEXT,
            {drain_defs}
        )
        """
    )
    conn.commit()


def _truthy(val: Any) -> bool:
    return bool(val) and val not in (0, "0", "false", "False")


def classify_row_bucket(row: Dict[str, Any]) -> Optional[str]:
    status = str(row.get("dynamic_status") or "")
    profit = row.get("expected_profit_eth")
    try:
        profit_f = float(profit) if profit is not None else 0.0
    except (TypeError, ValueError):
        profit_f = 0.0

    if profit_f > 0 or "PROFIT_BELOW" in status:
        return BUCKET_NEAR_MISS

    sleeping_flag = _truthy(row.get("has_zero_slippage")) or _truthy(
        row.get("has_public_swapback")
    )
    if sleeping_flag:
        return BUCKET_SLEEPING_TAX

    if any(_truthy(row.get(c)) for c in DRAIN_FLAG_COLUMNS):
        return BUCKET_UNFUNDED_DRAIN
    return None


def _row_to_dict(cursor, raw) -> Dict[str, Any]:
    names = [d[0] for d in cursor.description]
    return dict(zip(names, raw))


def _due(next_check_at: Optional[str], now: datetime) -> bool:
    if not next_check_at:
        return True
    try:
        due = datetime.fromisoformat(str(next_check_at).replace("Z", "+00:00"))
    except ValueError:
        return True
    if due.tzinfo is None:
        due = due.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return due <= now


def fetch_watchlist(
    conn,
    *,
    now: datetime,
    max_targets: int = 100,
) -> List[Dict[str, Any]]:
    """Return due, non-exploitable verified contracts in watch buckets."""
    drain_or = " OR ".join(f"IFNULL({c}, 0) = 1" for c in DRAIN_FLAG_COLUMNS)
    sql = f"""
        SELECT {", ".join(WATCHLIST_SELECT_COLUMNS)}
        FROM tokens
        WHERE IFNULL(verified, 0) = 1
          AND IFNULL(is_user_exploitable, 0) = 0
          AND (
                IFNULL(has_zero_slippage, 0) = 1
             OR IFNULL(has_public_swapback, 0) = 1
             OR {drain_or}
          )
        ORDER BY CASE WHEN last_checked_at IS NULL THEN 0 ELSE 1 END,
                 last_checked_at ASC
    """
    cur = conn.execute(sql)
    out: List[Dict[str, Any]] = []
    for raw in cur.fetchall():
        row = _row_to_dict(cur, raw)
        if not _due(row.get("next_check_at"), now):
            continue
        bucket = classify_row_bucket(row)
        if not bucket:
            continue
        row["bucket"] = bucket
        out.append(row)
        if len(out) >= max_targets:
            break
    return out


def backoff_next_check(now: datetime, failures: int = 0) -> datetime:
    """Exponential backoff: 2, 4, 8, ... minutes, capped at 6 hours."""
    minutes = min(6 * 60, 2 ** max(1, failures + 1))
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return now + timedelta(minutes=minutes)
