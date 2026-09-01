#!/usr/bin/env python3
"""
Opportunity Watchlist daemon
============================
Re-checks verified contracts that still look exploitable on paper but are not
yet actionable (sleeping swapBack, unfunded drains, profit-gate near-misses).

Activation requires full liveness + profit gate — not merely “ETH arrived”.
"""

import argparse
import json
import os
import time
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from web3 import Web3

from fork_profit_gate import run_fork_profit_test, should_emit_triage
from opportunity_watchlist import backoff_next_check, fetch_watchlist
from state_delta import (
    StateSnapshot,
    should_wakeup,
    snapshot_from_dict,
    snapshot_to_dict,
)
from token_scanner_daemon import (
    DB_PATH,
    RPC_ENDPOINTS,
    AlertDispatcher,
    OnChainStateVerifier,
    StaticVulnerabilityAuditor,
    TokenScannerDB,
    TriageReportGenerator,
    load_saved_source,
)

console = Console()


class DormantBalanceWatcher:
    def __init__(self, db_path: str = DB_PATH, interval_seconds: int = 120, max_targets: int = 100):
        self.db = TokenScannerDB(db_path)
        self.interval_seconds = interval_seconds
        self.max_targets = max_targets
        self.web3_clients = {}
        for chain, urls in RPC_ENDPOINTS.items():
            for u in urls:
                try:
                    w3 = Web3(Web3.HTTPProvider(u, request_kwargs={"timeout": 10}))
                    if w3.is_connected():
                        self.web3_clients[chain] = w3
                        break
                except Exception:
                    continue

    def get_watchlist(self):
        now = datetime.now(timezone.utc)
        conn = self.db.get_connection()
        try:
            return fetch_watchlist(conn, now=now, max_targets=self.max_targets)
        finally:
            conn.close()

    def get_dormant_targets(self):
        """Back-compat alias used by tests / CLI copy."""
        return self.get_watchlist()

    def get_zero_slippage_dormants(self):
        return [t for t in self.get_watchlist() if t.get("bucket") == "sleeping_tax"]

    def _delta_enabled(self) -> bool:
        raw = os.environ.get("FOMO_STATE_DELTA", "1").strip().lower()
        return raw not in {"0", "false", "no", "off"}

    def capture_snapshot(self, addr: str, chain: str, src: str = "") -> StateSnapshot:
        w3 = self.web3_clients.get(chain) or OnChainStateVerifier.get_web3_client(chain)
        eth = 0.0
        pool_eth = 0.0
        treasury = 0.0
        swap_enabled = None
        if w3:
            try:
                c_addr = w3.to_checksum_address(addr)
                eth = float(w3.from_wei(w3.eth.get_balance(c_addr), "ether"))
            except Exception:
                pass
            try:
                live = OnChainStateVerifier.evaluate_swapback_liveness(w3, addr, src)
                swap_enabled = live.get("swap_enabled")
                raw_t = live.get("treasury_tokens") or 0
                treasury = float(raw_t) / 1e18 if raw_t else 0.0
            except Exception:
                pass
            try:
                amm = OnChainStateVerifier.evaluate_amm_slippage_reserves(w3, chain, addr)
                pool_eth = float(amm.get("eth_reserve") or 0.0)
            except Exception:
                pass
        return StateSnapshot(
            eth_balance=eth,
            pool_eth=pool_eth,
            treasury_tokens=treasury,
            swap_enabled=swap_enabled,
        )

    def _mark_checked(
        self,
        addr: str,
        bucket: str,
        activated: bool,
        snapshot: Optional[StateSnapshot] = None,
    ) -> None:
        now = datetime.now(timezone.utc)
        nxt = now if activated else backoff_next_check(now, failures=1)
        fields = {
            "last_checked_at": now.isoformat(),
            "next_check_at": nxt.isoformat(),
            "watch_bucket": bucket,
        }
        if snapshot is not None:
            fields["state_snapshot"] = json.dumps(snapshot_to_dict(snapshot))
        self.db.update_token_flags(addr, fields)

    def check_zero_slippage_dormant(self, target: Dict) -> bool:
        return self.check_and_update_contract(target)

    def check_and_update_contract(self, target: Dict) -> bool:
        """Re-run full liveness + profit gates. Do not alert just because ETH arrived."""
        chain = (target.get("chain") or "").lower()
        addr = target["address"]
        src = load_saved_source(chain, addr)
        if not src:
            return False
        _findings, evidence = StaticVulnerabilityAuditor.audit_source(src)
        user_exploits = [e for e in evidence if e.get("user_exploitable")]
        if not user_exploits:
            return False
        is_active, status, eth_bal, confirmed, profit_payload = OnChainStateVerifier.verify_onchain_liveness(
            addr, chain, user_exploits, src
        )
        if profit_payload:
            target["profit"] = profit_payload
            try:
                self.db.update_token_flags(
                    addr,
                    {
                        "expected_profit_eth": profit_payload.get("expected_profit_eth"),
                        "dynamic_status": status,
                        "eth_balance": eth_bal,
                    },
                )
            except Exception:
                pass
        if not (is_active and confirmed):
            return False
        fork_res = run_fork_profit_test(addr, chain)
        if not should_emit_triage(is_active=True, confirmed=confirmed, fork_result=fork_res):
            try:
                self.db.update_token_flags(
                    addr,
                    {"dynamic_status": f"{status} | FORK_GATE_{fork_res.reason.upper()}"},
                )
            except Exception:
                pass
            return False
        target["eth_balance"] = eth_bal
        target["dynamic_status"] = status
        profit = profit_payload or ((confirmed[0] or {}).get("profit") if confirmed else None)
        if profit:
            target["profit"] = profit
        triage_path = TriageReportGenerator.generate_triage_file(target, confirmed)
        flags = {
            "is_user_exploitable": 1,
            "onchain_verified": 1,
            "dynamic_status": status,
            "eth_balance": eth_bal,
            "triage_file_path": triage_path,
        }
        if profit and profit.get("expected_profit_eth") is not None:
            flags["expected_profit_eth"] = profit["expected_profit_eth"]
        self.db.update_token_flags(addr, flags)
        AlertDispatcher.emit_triage_alert(target, confirmed, triage_path)
        return True

    def run_cycle(self) -> Tuple[int, int]:
        targets = self.get_watchlist()
        activated = 0
        for t in targets:
            addr = t.get("address") or ""
            bucket = t.get("bucket") or ""
            chain = (t.get("chain") or "").lower()
            snap = None
            try:
                src = load_saved_source(chain, addr) if addr else ""
                snap = self.capture_snapshot(addr, chain, src)
                prev = snapshot_from_dict(None)
                raw_prev = t.get("state_snapshot")
                if raw_prev:
                    try:
                        prev = snapshot_from_dict(
                            json.loads(raw_prev) if isinstance(raw_prev, str) else raw_prev
                        )
                    except (TypeError, json.JSONDecodeError):
                        prev = None
                if self._delta_enabled() and prev is not None and not should_wakeup(prev, snap):
                    if addr:
                        self._mark_checked(addr, bucket, activated=False, snapshot=snap)
                    continue
                ok = self.check_and_update_contract(t)
                if ok:
                    activated += 1
                if addr:
                    self._mark_checked(addr, bucket, activated=ok, snapshot=snap)
                time.sleep(0.2)
            except Exception:
                if addr:
                    try:
                        self._mark_checked(addr, bucket, activated=False, snapshot=snap)
                    except Exception:
                        pass
        return len(targets), activated

    def start_monitoring(self):
        targets = self.get_watchlist()
        console.print(Panel(
            f"[bold green]🛰️ Opportunity Watchlist Active[/]\n\n"
            f"[bold yellow]Due targets this cycle:[/] {len(targets)} "
            f"(sleeping swapBack / unfunded drains / profit near-miss — not 0-ETH-only)\n"
            f"[bold yellow]Max per cycle:[/] {self.max_targets}\n"
            f"[bold yellow]Polling Interval:[/] Every {self.interval_seconds}s "
            f"(Base, Arbitrum, Ethereum)\n"
            f"[bold yellow]Trigger:[/] Liveness + profit gate pass → triage card\n\n"
            f"[bold cyan]Press Ctrl+C to stop.[/]",
            title="Opportunity Watchlist Monitor",
            border_style="cyan bold",
        ))

        while True:
            try:
                tot, act = self.run_cycle()
                ts = datetime.now().strftime("%H:%M:%S")
                console.print(
                    f"[dim]{ts} - Checked {tot} watchlist targets. {act} newly actionable.[/]"
                )
                time.sleep(self.interval_seconds)
            except KeyboardInterrupt:
                console.print("\n[yellow]Watchlist monitor stopped by user.[/]")
                break
            except Exception as e:
                console.print(f"[red]Watcher loop error: {e}[/]")
                time.sleep(10)


def main():
    parser = argparse.ArgumentParser(
        description="Opportunity watchlist: re-check sleeping / unfunded / near-miss contracts"
    )
    parser.add_argument("--interval", type=int, default=120, help="Polling interval in seconds (default: 120)")
    parser.add_argument("--max-targets", type=int, default=100, help="Max contracts per cycle (default: 100)")
    parser.add_argument("--once", action="store_true", help="Run a single watchlist cycle and exit")
    parser.add_argument("--daemon", action="store_true", help="Run in continuous background polling mode")

    args = parser.parse_args()
    watcher = DormantBalanceWatcher(
        interval_seconds=args.interval,
        max_targets=args.max_targets,
    )

    if args.once:
        console.print("[cyan]Running single opportunity watchlist cycle...[/]")
        tot, act = watcher.run_cycle()
        console.print(f"[green]✓ Checked {tot} targets. {act} newly actionable.[/]")
    elif args.daemon:
        watcher.start_monitoring()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
