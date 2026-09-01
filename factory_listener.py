"""DEX factory PairCreated listener (WETH pairs only, v1)."""

from __future__ import annotations

import argparse
import os
import time
from typing import Any, Callable, Dict, Mapping, Optional

from log_sync import chunk_block_range, cursor_key, next_cursor, normalize_log
from profit_estimator import ProfitEstimate

try:
    from web3 import Web3
except ImportError:
    Web3 = None

if Web3 is not None:
    PAIR_CREATED_TOPIC0 = "0x" + Web3.keccak(
        text="PairCreated(address,address,address,uint256)"
    ).hex().replace("0x", "")
else:
    PAIR_CREATED_TOPIC0 = (
        "0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9"
    )


def _topic_addr(topic: str) -> str:
    h = topic.lower().replace("0x", "")
    return "0x" + h[-40:]


def _word_addr(word: str) -> str:
    h = word.lower().replace("0x", "")
    return "0x" + h[-40:]


def decode_pair_created(log: Dict[str, Any], *, weth: str) -> Optional[Dict[str, str]]:
    topics = log.get("topics") or []
    if len(topics) < 3:
        return None
    t0 = str(topics[0]).lower()
    if not t0.startswith("0x"):
        t0 = "0x" + t0
    if t0 != PAIR_CREATED_TOPIC0.lower():
        return None
    token0 = _topic_addr(str(topics[1]))
    token1 = _topic_addr(str(topics[2]))
    data = str(log.get("data") or "")
    hexdata = data[2:] if data.startswith("0x") else data
    if len(hexdata) < 64:
        return None
    pair = _word_addr(hexdata[:64])
    weth_l = weth.lower()
    if token0 == weth_l:
        token = token1
    elif token1 == weth_l:
        token = token0
    else:
        return None
    return {
        "token0": token0,
        "token1": token1,
        "pair": pair,
        "token": token,
        "weth": weth_l,
    }


def should_emit_factory_triage(
    *,
    verified: bool,
    has_source: bool,
    flags: Dict[str, Any],
    estimate: Optional[ProfitEstimate],
) -> bool:
    """Conservative v1: only verified source with tax/swapBack flags and actionable profit."""
    if estimate is None or not estimate.actionable:
        return False
    if not (verified and has_source):
        return False
    return bool(
        flags.get("has_public_swapback")
        or flags.get("has_zero_slippage")
        or flags.get("has_unprotected_critical_function")
        or flags.get("has_unprotected_initializer")
        or flags.get("has_arbitrary_call")
    )


def factory_listener_enabled() -> bool:
    raw = os.environ.get("FOMO_FACTORY_LISTENER", "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def run_factory_cycle(
    db,
    clients: Mapping[str, Any],
    *,
    lookback: int = 500,
    max_span: int = 2000,
    on_pair: Optional[Callable[[str, Dict[str, str]], None]] = None,
) -> int:
    """Poll PairCreated logs; persist token rows; advance cursors. Returns pair count."""
    from token_scanner_daemon import DEX_CONFIG

    found = 0
    for chain, cfg in DEX_CONFIG.items():
        w3 = clients.get(chain)
        if not w3:
            continue
        try:
            head = int(w3.eth.block_number)
        except Exception:
            continue
        weth = cfg["weth"]
        for _dex_name, factory in cfg["factories"]:
            key = cursor_key(chain, factory, "PairCreated")
            last = db.get_cursor(key, default=max(0, head - lookback))
            frm = last + 1
            if frm > head:
                continue
            for start, end in chunk_block_range(frm, head, max_span=max_span):
                try:
                    raw_logs = w3.eth.get_logs(
                        {
                            "fromBlock": start,
                            "toBlock": end,
                            "address": factory,
                            "topics": [PAIR_CREATED_TOPIC0],
                        }
                    )
                except Exception:
                    raw_logs = []
                for log in raw_logs:
                    ev = decode_pair_created(normalize_log(log), weth=weth)
                    if not ev:
                        continue
                    db.ensure_token_row(
                        address=ev["token"],
                        chain=chain,
                        name="FactoryPairToken",
                        category="ERC20_TOKEN",
                        verified=False,
                    )
                    found += 1
                    if on_pair:
                        on_pair(chain, ev)
                db.set_cursor(key, next_cursor(last, end))
                last = end
    return found


def main() -> None:
    parser = argparse.ArgumentParser(description="FOMO DEX PairCreated listener")
    parser.add_argument("--daemon", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=int, default=15)
    parser.add_argument("--lookback", type=int, default=500)
    args = parser.parse_args()
    if not factory_listener_enabled() and not args.once:
        print("[factory_listener] FOMO_FACTORY_LISTENER=0 — idle")
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
        n = run_factory_cycle(db, clients, lookback=args.lookback)
        print(f"[factory_listener] pairs={n} chains={list(clients)}")

    if args.once:
        _tick()
        return
    if args.daemon:
        print("[factory_listener] daemon start")
        while True:
            try:
                _tick()
            except Exception as e:
                print(f"[factory_listener] error: {e}")
            time.sleep(args.interval)
        return
    parser.print_help()


if __name__ == "__main__":
    main()
