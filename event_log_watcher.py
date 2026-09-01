"""Watch pair Swap logs and allowlisted liquidations (HTTP getLogs)."""

from __future__ import annotations

import argparse
import os
import time
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Set

try:
    from web3 import Web3
except ImportError:
    Web3 = None

if Web3 is not None:
    SWAP_TOPIC0 = "0x" + Web3.keccak(
        text="Swap(address,uint256,uint256,uint256,uint256,address)"
    ).hex().replace("0x", "")
    AAVE_V3_LIQ_TOPIC0 = "0x" + Web3.keccak(
        text="LiquidationCall(address,address,address,uint256,uint256,address,bool)"
    ).hex().replace("0x", "")
else:
    SWAP_TOPIC0 = "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822"
    AAVE_V3_LIQ_TOPIC0 = (
        "0xe413a321e8681d831f4dbccbca790d2952b56f977908e45be373350091fba3"
    )


def _topic0(log: Dict[str, Any]) -> str:
    topics = log.get("topics") or []
    if not topics:
        return ""
    t = str(topics[0]).lower()
    return t if t.startswith("0x") else "0x" + t


def tokens_from_swap_logs(
    logs: Iterable[Dict[str, Any]],
    pair_to_token: Dict[str, str],
) -> List[str]:
    """Return watched token addresses whose pair emitted a Swap."""
    wanted: Set[str] = set()
    mapping = {k.lower(): v.lower() for k, v in pair_to_token.items()}
    for log in logs:
        if _topic0(log) != SWAP_TOPIC0.lower():
            continue
        pair = str(log.get("address") or "").lower()
        token = mapping.get(pair)
        if token:
            wanted.add(token)
    return sorted(wanted)


def liquidation_hits(
    logs: Iterable[Dict[str, Any]],
    allowlisted_pools: Iterable[str],
) -> List[str]:
    allow = {a.lower() for a in allowlisted_pools}
    hits: List[str] = []
    for log in logs:
        addr = str(log.get("address") or "").lower()
        if addr in allow and _topic0(log) == AAVE_V3_LIQ_TOPIC0.lower():
            hits.append(addr)
    return hits


def log_watcher_enabled() -> bool:
    raw = os.environ.get("FOMO_LOG_WATCHER", "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def run_log_watch_cycle(
    db,
    clients: Mapping[str, Any],
    pair_to_token_by_chain: Mapping[str, Dict[str, str]],
    liq_pools_by_chain: Mapping[str, Iterable[str]],
    *,
    lookback: int = 200,
    max_span: int = 2000,
    on_swap_token: Optional[Callable[[str, str], None]] = None,
    on_liq_pool: Optional[Callable[[str, str], None]] = None,
) -> int:
    from log_sync import chunk_block_range, cursor_key, next_cursor, normalize_log

    hits = 0
    for chain, pair_map in pair_to_token_by_chain.items():
        w3 = clients.get(chain)
        if not w3 or not pair_map:
            continue
        try:
            head = int(w3.eth.block_number)
        except Exception:
            continue
        for pair, token in pair_map.items():
            key = cursor_key(chain, pair, "Swap")
            last = db.get_cursor(key, default=max(0, head - lookback))
            frm = last + 1
            if frm > head:
                continue
            for start, end in chunk_block_range(frm, head, max_span=max_span):
                try:
                    raw = w3.eth.get_logs(
                        {
                            "fromBlock": start,
                            "toBlock": end,
                            "address": pair,
                            "topics": [SWAP_TOPIC0],
                        }
                    )
                except Exception:
                    raw = []
                logs = [normalize_log(x) for x in raw]
                tokens = tokens_from_swap_logs(logs, {pair: token})
                for tok in tokens:
                    hits += 1
                    if on_swap_token:
                        on_swap_token(chain, tok)
                db.set_cursor(key, next_cursor(last, end))
                last = end

    for chain, pools in (liq_pools_by_chain or {}).items():
        w3 = clients.get(chain)
        pool_list = [p for p in pools]
        if not w3 or not pool_list:
            continue
        try:
            head = int(w3.eth.block_number)
        except Exception:
            continue
        for pool in pool_list:
            key = cursor_key(chain, pool, "LiquidationCall")
            last = db.get_cursor(key, default=max(0, head - lookback))
            frm = last + 1
            if frm > head:
                continue
            for start, end in chunk_block_range(frm, head, max_span=max_span):
                try:
                    raw = w3.eth.get_logs(
                        {
                            "fromBlock": start,
                            "toBlock": end,
                            "address": pool,
                            "topics": [AAVE_V3_LIQ_TOPIC0],
                        }
                    )
                except Exception:
                    raw = []
                logs = [normalize_log(x) for x in raw]
                for addr in liquidation_hits(logs, [pool]):
                    hits += 1
                    if on_liq_pool:
                        on_liq_pool(chain, addr)
                db.set_cursor(key, next_cursor(last, end))
                last = end
    return hits


def main() -> None:
    parser = argparse.ArgumentParser(description="FOMO Swap/liquidation log watcher")
    parser.add_argument("--daemon", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=int, default=8)
    parser.add_argument("--lookback", type=int, default=200)
    args = parser.parse_args()
    if not log_watcher_enabled() and not args.once:
        print("[log_watcher] FOMO_LOG_WATCHER=0 — idle")
        if args.daemon:
            while True:
                time.sleep(max(60, args.interval))
        return

    from token_scanner_daemon import DEX_CONFIG, RPC_ENDPOINTS, TokenScannerDB

    db = TokenScannerDB()
    clients = {}
    if Web3 is not None:
        for chain in DEX_CONFIG:
            for url in RPC_ENDPOINTS.get(chain, []):
                try:
                    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 15}))
                    if w3.is_connected():
                        clients[chain] = w3
                        break
                except Exception:
                    continue

    def _tick():
        n = run_log_watch_cycle(
            db,
            clients,
            pair_to_token_by_chain={},
            liq_pools_by_chain={},
            lookback=args.lookback,
        )
        print(f"[log_watcher] hits={n} chains={list(clients)}")

    if args.once:
        _tick()
        return
    if args.daemon:
        print("[log_watcher] daemon start")
        while True:
            try:
                _tick()
            except Exception as e:
                print(f"[log_watcher] error: {e}")
            time.sleep(args.interval)
        return
    parser.print_help()


if __name__ == "__main__":
    main()
