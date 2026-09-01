"""Dashboard snapshot for the profit pipeline (not detector prevalence)."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple

from opportunity_watchlist import (
    BUCKET_UNFUNDED_DRAIN,
    DRAIN_FLAG_COLUMNS,
    WATCHLIST_SELECT_COLUMNS,
    classify_row_bucket,
)
from profit_estimator import MIN_NET_PROFIT_ETH

TOP_N = 10

# Dashboard drain = user-callable payoff, not owner-auth / FP-prone flags.
DASHBOARD_DRAIN_COLUMNS = (
    "has_unprotected_critical_function",
    "has_unprotected_initializer",
    "has_arbitrary_call",
    "has_reentrancy_flaw",
)


def _rows(cur) -> List[Dict[str, Any]]:
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def parse_triage_filename(name: str) -> Optional[Tuple[str, str]]:
    stem = name[:-3] if name.endswith(".md") else name
    if not stem.startswith("triage_"):
        return None
    rest = stem[len("triage_") :]
    chain, sep, addr = rest.partition("_")
    if not sep or not addr:
        return None
    return chain.lower(), addr.lower()


def list_triage_queue(triage_dir: str) -> List[Dict[str, str]]:
    if not triage_dir or not os.path.isdir(triage_dir):
        return []
    out: List[Dict[str, str]] = []
    for fname in sorted(os.listdir(triage_dir)):
        if not fname.endswith(".md"):
            continue
        parsed = parse_triage_filename(fname)
        path = os.path.abspath(os.path.join(triage_dir, fname))
        entry = {"path": path, "file": fname}
        if parsed:
            entry["chain"], entry["address"] = parsed
        out.append(entry)
    return out


def collect_pipeline_stats(
    conn,
    *,
    triage_dir: str,
    min_profit_eth: float = MIN_NET_PROFIT_ETH,
    top_n: int = TOP_N,
) -> Dict[str, Any]:
    """Single-query-set snapshot for `--stats` (JSON or table)."""
    cur = conn.cursor()
    total = cur.execute("SELECT COUNT(*) FROM tokens").fetchone()[0]
    verified = cur.execute(
        "SELECT COUNT(*) FROM tokens WHERE IFNULL(verified, 0) = 1"
    ).fetchone()[0]
    by_chain = dict(
        cur.execute("SELECT IFNULL(chain, 'unknown'), COUNT(*) FROM tokens GROUP BY chain")
    )

    confirmed = cur.execute(
        """
        SELECT COUNT(*) FROM tokens
        WHERE IFNULL(is_user_exploitable, 0) = 1
          AND IFNULL(onchain_verified, 0) = 1
        """
    ).fetchone()[0]
    profit_pass = cur.execute(
        "SELECT COUNT(*) FROM tokens WHERE IFNULL(expected_profit_eth, 0) >= ?",
        (float(min_profit_eth),),
    ).fetchone()[0]

    swapback = cur.execute(
        "SELECT COUNT(*) FROM tokens WHERE IFNULL(has_public_swapback, 0) = 1"
    ).fetchone()[0]
    zero_slip = cur.execute(
        "SELECT COUNT(*) FROM tokens WHERE IFNULL(has_zero_slippage, 0) = 1"
    ).fetchone()[0]

    factory_rows = cur.execute(
        """
        SELECT IFNULL(dynamic_status, '') FROM tokens
        WHERE IFNULL(dynamic_status, '') LIKE '%FACTORY_NEW_PAIR%'
        """
    ).fetchall()
    factory = {"no_source": 0, "dust": 0, "actionable": 0, "total": len(factory_rows)}
    for (status,) in factory_rows:
        s = str(status)
        if "NO_SOURCE" in s:
            factory["no_source"] += 1
        elif "ACTIONABLE" in s:
            factory["actionable"] += 1
        elif "DUST" in s:
            factory["dust"] += 1

    drain_or = " OR ".join(f"IFNULL({c}, 0) = 1" for c in DRAIN_FLAG_COLUMNS)
    select_cols = ", ".join(WATCHLIST_SELECT_COLUMNS)
    watch_rows = _rows(
        cur.execute(
            f"""
            SELECT {select_cols}
            FROM tokens
            WHERE IFNULL(is_user_exploitable, 0) = 0
              AND (
                    IFNULL(has_zero_slippage, 0) = 1
                 OR IFNULL(has_public_swapback, 0) = 1
                 OR IFNULL(expected_profit_eth, 0) > 0
                 OR IFNULL(dynamic_status, '') LIKE '%PROFIT_BELOW%'
                 OR {drain_or}
              )
            """
        )
    )
    watchlist = {"near_miss": 0, "sleeping_tax": 0, "unfunded_drain": 0}
    for row in watch_rows:
        bucket = classify_row_bucket(row)
        if bucket == BUCKET_UNFUNDED_DRAIN and not any(
            bool(row.get(c)) and row.get(c) not in (0, "0", "false", "False")
            for c in DASHBOARD_DRAIN_COLUMNS
        ):
            continue
        if bucket in watchlist:
            watchlist[bucket] += 1

    top = _rows(
        cur.execute(
            """
            SELECT address, chain, expected_profit_eth, dynamic_status,
                   IFNULL(is_user_exploitable, 0) AS is_user_exploitable,
                   triage_file_path
            FROM tokens
            WHERE expected_profit_eth IS NOT NULL AND expected_profit_eth > 0
            ORDER BY expected_profit_eth DESC
            LIMIT ?
            """,
            (int(top_n),),
        )
    )
    for item in top:
        try:
            item["expected_profit_eth"] = float(item["expected_profit_eth"])
        except (TypeError, ValueError):
            item["expected_profit_eth"] = 0.0

    queue = list_triage_queue(triage_dir)
    by_addr = {}
    addrs = [q["address"] for q in queue if q.get("address")]
    if addrs:
        placeholders = ",".join("?" * len(addrs))
        for row in _rows(
            cur.execute(
                f"""
                SELECT address, chain, expected_profit_eth, dynamic_status
                FROM tokens WHERE address IN ({placeholders})
                """,
                addrs,
            )
        ):
            by_addr[str(row["address"]).lower()] = row
    for q in queue:
        extra = by_addr.get(q.get("address") or "")
        if extra:
            try:
                q["expected_profit_eth"] = float(extra.get("expected_profit_eth") or 0.0)
            except (TypeError, ValueError):
                q["expected_profit_eth"] = None
            q["dynamic_status"] = extra.get("dynamic_status")
        else:
            q["expected_profit_eth"] = None
            q.setdefault("dynamic_status", None)

    return {
        "corpus": {
            "total": int(total),
            "verified": int(verified),
            "by_chain": {str(k): int(v) for k, v in by_chain.items()},
        },
        "hits": {
            "pending_review": len(queue),
            "confirmed": int(confirmed),
            "profit_pass": int(profit_pass),
            "min_profit_eth": float(min_profit_eth),
            "queue": queue,
        },
        "watchlist": watchlist,
        "factory": factory,
        "inventory": {
            "public_swapback": int(swapback),
            "zero_slippage": int(zero_slip),
        },
        "top_expected_profit": top,
        # aliases used by older --stats --json callers
        "total_scanned": int(total),
        "verified_contracts": int(verified),
        "chains_breakdown": {str(k): int(v) for k, v in by_chain.items()},
        "pending_triage_cards_count": len(queue),
        "triage_queue_files": [q["path"] for q in queue],
    }
