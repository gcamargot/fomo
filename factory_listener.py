"""DEX factory PairCreated listener (WETH pairs only, v1)."""

from __future__ import annotations

import argparse
import json
import os
import time
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

from log_sync import chunk_block_range, cursor_key, next_cursor, normalize_log
from profit_estimator import ProfitEstimate
from state_delta import StateSnapshot, snapshot_to_dict

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


_PAIR_ABI = [
    {
        "constant": True,
        "inputs": [],
        "name": "getReserves",
        "outputs": [
            {"name": "_reserve0", "type": "uint112"},
            {"name": "_reserve1", "type": "uint112"},
            {"name": "_blockTimestampLast", "type": "uint32"},
        ],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "token0",
        "outputs": [{"name": "", "type": "address"}],
        "type": "function",
    },
]
_ERC20_BAL_ABI = [
    {
        "inputs": [{"name": "account", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    }
]
_AUDIT_FLAG_COLS = (
    "has_public_swapback",
    "has_zero_slippage",
    "has_unprotected_critical_function",
    "has_unprotected_initializer",
    "has_arbitrary_call",
    "has_reentrancy_flaw",
    "has_dynamic_taxes",
)


def _checksum(w3, addr: str) -> str:
    fn = getattr(w3, "to_checksum_address", None)
    return fn(addr) if callable(fn) else addr


def pair_reserves_eth_token(w3, pair: str, weth: str) -> Tuple[float, float]:
    """Return (pool_eth, pool_token) from a UniV2 pair. (0, 0) on RPC errors."""
    if w3 is None or not pair:
        return 0.0, 0.0
    try:
        pair_c = w3.eth.contract(address=_checksum(w3, pair), abi=_PAIR_ABI)
        r0, r1, _ = pair_c.functions.getReserves().call()
        t0 = pair_c.functions.token0().call()
        weth_is_t0 = str(t0).lower() == weth.lower()
        eth_reserve = (r0 if weth_is_t0 else r1) / 1e18
        token_reserve = (r1 if weth_is_t0 else r0) / 1e18
        return float(eth_reserve), float(token_reserve)
    except Exception:
        return 0.0, 0.0


def erc20_balance_raw(w3, token: str, holder: str) -> int:
    if w3 is None or not token or not holder:
        return 0
    try:
        c = w3.eth.contract(address=_checksum(w3, token), abi=_ERC20_BAL_ABI)
        return int(c.functions.balanceOf(_checksum(w3, holder)).call() or 0)
    except Exception:
        return 0


def process_factory_pair(
    db,
    chain: str,
    ev: Dict[str, str],
    *,
    load_source,
    audit,
    verify,
    generate_triage,
    estimate,
    reserves,
    treasury_raw,
    fork_result=None,
    fork_run=None,
) -> bool:
    """Ingest a new WETH pair: persist row, profit estimate, optional full pipeline.

    Returns True if a triage card was written.
    """
    from fork_profit_gate import ForkGateResult, should_emit_triage

    token = ev["token"]
    db.ensure_token_row(
        address=token,
        chain=chain,
        name="FactoryPairToken",
        category="ERC20_TOKEN",
        verified=False,
    )
    pool_eth, pool_token = 0.0, 0.0
    try:
        pool_eth, pool_token = reserves()
    except Exception:
        pass
    raw = 0
    try:
        raw = int(treasury_raw() or 0)
    except Exception:
        raw = 0
    est = estimate(
        pool_eth=float(pool_eth or 0.0),
        pool_token=float(pool_token or 0.0),
        sell_token=(raw / 1e18) * 0.25 if raw else 0.0,
        treasury_token_raw=raw,
    )
    src = load_source(chain, token) or ""
    flags: Dict[str, Any] = {}
    user_exploits: list = []
    if src:
        flags, evidence = audit(src)
        user_exploits = [e for e in (evidence or []) if e.get("user_exploitable")]
    verified = bool(src)
    status = "FACTORY_NEW_PAIR_NO_SOURCE"
    profit_payload = None
    confirmed: list = []
    is_active = False
    if src and user_exploits:
        is_active, status, _eth, confirmed, profit_payload = verify(
            token, chain, user_exploits, src
        )
    else:
        from profit_estimator import profit_to_dict
        profit_payload = profit_to_dict(est)
        status = (
            "FACTORY_NEW_PAIR_ACTIONABLE"
            if est.actionable
            else "FACTORY_NEW_PAIR_DUST"
        )

    emit = False
    if src and user_exploits:
        emit = bool(is_active and confirmed)
        fr = fork_result
        if fr is None and fork_run is not None and emit:
            try:
                fr = fork_run()
            except Exception:
                fr = ForkGateResult(passed=False, skipped=False, reason="fork_error")
        if fr is None:
            fr = ForkGateResult(passed=True, skipped=True, reason="disabled")
        if emit and not should_emit_triage(
            is_active=True, confirmed=confirmed, fork_result=fr
        ):
            emit = False
            status = f"{status} | FORK_GATE_{fr.reason.upper()}"
    else:
        emit = should_emit_factory_triage(
            verified=verified,
            has_source=bool(src),
            flags=flags or {},
            estimate=est,
        )

    pair = str(ev.get("pair") or "").lower() or None
    fields: Dict[str, Any] = {
        "dynamic_status": status,
        "expected_profit_eth": (
            (profit_payload or {}).get("expected_profit_eth")
            if profit_payload
            else est.expected_profit_eth
        ),
        "state_snapshot": json.dumps(
            snapshot_to_dict(
                StateSnapshot(
                    pool_eth=float(pool_eth or 0.0),
                    treasury_tokens=(raw / 1e18) if raw else 0.0,
                    pair=pair,
                )
            )
        ),
    }
    if src:
        fields["verified"] = 1
    for col in _AUDIT_FLAG_COLS:
        if flags.get(col):
            fields[col] = 1
    if emit and (confirmed or user_exploits):
        meta = {
            "address": token,
            "chain": chain,
            "name": "FactoryPairToken",
            "dynamic_status": status,
            "profit": profit_payload,
        }
        exploits = confirmed or user_exploits
        path = generate_triage(meta, exploits)
        fields["is_user_exploitable"] = 1
        fields["onchain_verified"] = 1
        fields["triage_file_path"] = path
        db.update_token_flags(token, fields)
        return True
    db.update_token_flags(token, fields)
    return False


def handle_factory_pair(db, chain: str, ev: Dict[str, str], w3) -> bool:
    """Live daemon hook: source + reserves + profit + optional fork/triage."""
    from fork_profit_gate import run_fork_profit_test
    from profit_estimator import estimate_swapback_sandwich_profit
    from token_scanner_daemon import (
        OnChainStateVerifier,
        StaticVulnerabilityAuditor,
        TriageReportGenerator,
        load_saved_source,
    )

    token = ev["token"]
    return process_factory_pair(
        db,
        chain,
        ev,
        load_source=load_saved_source,
        audit=StaticVulnerabilityAuditor.audit_source,
        verify=OnChainStateVerifier.verify_onchain_liveness,
        generate_triage=TriageReportGenerator.generate_triage_file,
        estimate=lambda **k: estimate_swapback_sandwich_profit(**k),
        reserves=lambda: pair_reserves_eth_token(w3, ev.get("pair") or "", ev.get("weth") or ""),
        treasury_raw=lambda: erc20_balance_raw(w3, token, token),
        fork_run=lambda: run_fork_profit_test(token, chain),
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
                    found += 1
                    db.ensure_token_row(
                        address=ev["token"],
                        chain=chain,
                        name="FactoryPairToken",
                        category="ERC20_TOKEN",
                        verified=False,
                    )
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
        def on_pair(chain: str, ev: Dict[str, str]) -> None:
            try:
                handle_factory_pair(db, chain, ev, clients.get(chain))
            except Exception as e:
                print(f"[factory_listener] on_pair {ev.get('token')}: {e}")

        n = run_factory_cycle(db, clients, lookback=args.lookback, on_pair=on_pair)
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
