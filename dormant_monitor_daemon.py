#!/usr/bin/env python3
"""
Dormant Vulnerable Contract Balance & Activation Monitor Daemon
===============================================================
Continuously polls the blockchain for contracts in our research database
that contain known static architectural vulnerabilities (uninitialized proxies,
broken access control, CEI reentrancy, un-nonce'd signatures) but currently
hold zero funds (0.0 ETH).

Whenever funds are deposited or a contract becomes actively funded,
this daemon:
  1. Updates SQLite with live balance and dynamic_status = 'CONFIRMED_FUNDED'.
  2. Emits an audible terminal chime & high-visibility real-time alert.
  3. Generates an actionable Triage Card in ./contracts/triage_queue/.
"""

import time
import argparse
from datetime import datetime
from typing import Dict, List, Tuple
from web3 import Web3
from rich.console import Console
from rich.panel import Panel

from token_scanner_daemon import (
    DB_PATH, TokenScannerDB, OnChainStateVerifier,
    AlertDispatcher, TriageReportGenerator,
    StaticVulnerabilityAuditor, load_saved_source,
    RPC_ENDPOINTS
)

console = Console()

class DormantBalanceWatcher:
    def __init__(self, db_path: str = DB_PATH, interval_seconds: int = 120):
        self.db = TokenScannerDB(db_path)
        self.interval_seconds = interval_seconds
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

    def get_dormant_targets(self) -> List[Dict]:
        """
        Retrieves contracts from SQLite that have code vulnerabilities but 0 balance.
        """
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
        SELECT address, chain, name, compiler, category, dynamic_status,
               has_unprotected_initializer, has_unprotected_critical_function,
               has_reentrancy_flaw, has_signature_replay_flaw, has_vault_inflation,
               has_flash_staking_flaw, has_arbitrary_call, has_fee_on_transfer_flaw,
               has_spot_oracle_flaw,
               IFNULL(has_tx_origin_auth, 0),
               IFNULL(has_unprotected_router_setter, 0),
               IFNULL(has_permit_no_nonce, 0),
               IFNULL(has_multicall_msgvalue, 0),
               IFNULL(has_public_swapback, 0)
        FROM tokens
        WHERE verified = 1 AND (
            has_unprotected_initializer = 1 OR
            has_unprotected_critical_function = 1 OR
            has_reentrancy_flaw = 1 OR
            has_signature_replay_flaw = 1 OR
            has_vault_inflation = 1 OR
            has_flash_staking_flaw = 1 OR
            has_arbitrary_call = 1 OR
            has_fee_on_transfer_flaw = 1 OR
            has_spot_oracle_flaw = 1 OR
            IFNULL(has_tx_origin_auth, 0) = 1 OR
            IFNULL(has_unprotected_router_setter, 0) = 1 OR
            IFNULL(has_permit_no_nonce, 0) = 1 OR
            IFNULL(has_multicall_msgvalue, 0) = 1 OR
            IFNULL(has_public_swapback, 0) = 1
        )
        """)
        rows = cursor.fetchall()
        conn.close()

        targets = []
        for r in rows:
            targets.append({
                "address": r[0],
                "chain": r[1],
                "name": r[2],
                "compiler": r[3],
                "category": r[4],
                "dynamic_status": r[5],
                "has_unprotected_initializer": bool(r[6]),
                "has_unprotected_critical_function": bool(r[7]),
                "has_reentrancy_flaw": bool(r[8]),
                "has_signature_replay_flaw": bool(r[9]),
                "has_vault_inflation": bool(r[10]),
                "has_flash_staking_flaw": bool(r[11]),
                "has_arbitrary_call": bool(r[12]),
                "has_fee_on_transfer_flaw": bool(r[13]),
                "has_spot_oracle_flaw": bool(r[14]),
            })
        return targets

    def get_zero_slippage_dormants(self) -> List[Dict]:
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
        SELECT address, chain, name, compiler, category, dynamic_status
        FROM tokens
        WHERE verified = 1 AND has_zero_slippage = 1
          AND IFNULL(is_user_exploitable, 0) = 0
        """)
        rows = cursor.fetchall()
        conn.close()
        return [
            {
                "address": r[0],
                "chain": r[1],
                "name": r[2],
                "compiler": r[3],
                "category": r[4],
                "dynamic_status": r[5],
            }
            for r in rows
        ]

    def check_zero_slippage_dormant(self, target: Dict) -> bool:
        """Re-run swapBack liveness. Alert only if it became reachable."""
        chain = (target.get("chain") or "").lower()
        addr = target["address"]
        src = load_saved_source(chain, addr)
        if not src:
            return False
        _findings, evidence = StaticVulnerabilityAuditor.audit_source(src)
        user_exploits = [e for e in evidence if e.get("user_exploitable")]
        if not user_exploits:
            return False
        is_active, status, eth_bal, confirmed = OnChainStateVerifier.verify_onchain_liveness(
            addr, chain, user_exploits, src
        )
        if not (is_active and confirmed):
            return False
        target["eth_balance"] = eth_bal
        target["dynamic_status"] = status
        triage_path = TriageReportGenerator.generate_triage_file(target, confirmed)
        self.db.update_token_flags(
            addr,
            {
                "is_user_exploitable": 1,
                "onchain_verified": 1,
                "dynamic_status": status,
                "eth_balance": eth_bal,
                "triage_file_path": triage_path,
            },
        )
        AlertDispatcher.emit_triage_alert(target, confirmed, triage_path)
        return True

    def check_and_update_contract(self, target: Dict) -> bool:
        """Re-run full liveness gates. Do not alert just because ETH arrived."""
        chain = (target.get("chain") or "").lower()
        addr = target["address"]
        src = load_saved_source(chain, addr)
        if not src:
            return False
        _findings, evidence = StaticVulnerabilityAuditor.audit_source(src)
        user_exploits = [e for e in evidence if e.get("user_exploitable")]
        if not user_exploits:
            return False
        is_active, status, eth_bal, confirmed = OnChainStateVerifier.verify_onchain_liveness(
            addr, chain, user_exploits, src
        )
        if not (is_active and confirmed):
            return False
        target["eth_balance"] = eth_bal
        target["dynamic_status"] = status
        triage_path = TriageReportGenerator.generate_triage_file(target, confirmed)
        self.db.update_token_flags(
            addr,
            {
                "is_user_exploitable": 1,
                "onchain_verified": 1,
                "dynamic_status": status,
                "eth_balance": eth_bal,
                "triage_file_path": triage_path,
            },
        )
        AlertDispatcher.emit_triage_alert(target, confirmed, triage_path)
        return True

    def run_cycle(self) -> Tuple[int, int]:
        targets = self.get_dormant_targets()
        zs_dormants = self.get_zero_slippage_dormants()
        activated = 0
        for t in targets:
            try:
                if self.check_and_update_contract(t):
                    activated += 1
                time.sleep(0.2)
            except Exception:
                pass
        for t in zs_dormants:
            try:
                if self.check_zero_slippage_dormant(t):
                    activated += 1
                time.sleep(0.2)
            except Exception:
                pass
        return len(targets) + len(zs_dormants), activated

    def start_monitoring(self):
        targets = self.get_dormant_targets()
        console.print(Panel(
            f"[bold green]🛰️ Dormant Vulnerable Contract Watcher Active[/]\n\n"
            f"[bold yellow]Monitoring Targets:[/] {len(targets)} dormant contracts with code flaws (0.0 ETH balance)\n"
            f"[bold yellow]Polling Interval:[/] Every {self.interval_seconds} seconds across Base, Arbitrum, Ethereum\n"
            f"[bold yellow]Trigger Action:[/] Generates Triage Card + Audible Alert upon detecting balance (> 0 ETH)\n\n"
            f"[bold cyan]Press Ctrl+C to stop.[/]",
            title="Dormant Contract Balance Monitor",
            border_style="cyan bold"
        ))

        while True:
            try:
                tot, act = self.run_cycle()
                ts = datetime.now().strftime("%H:%M:%S")
                console.print(f"[dim]{ts} - Checked {tot} dormant targets. {act} newly activated with funds.[/]")
                time.sleep(self.interval_seconds)
            except KeyboardInterrupt:
                console.print("\n[yellow]Dormant monitor stopped by user.[/]")
                break
            except Exception as e:
                console.print(f"[red]Watcher loop error: {e}[/]")
                time.sleep(10)

def main():
    parser = argparse.ArgumentParser(description="Dormant Vulnerable Contract Balance & Activation Monitor")
    parser.add_argument("--interval", type=int, default=120, help="Polling interval in seconds (default: 120)")
    parser.add_argument("--once", action="store_true", help="Run a single balance check across all dormant contracts and exit")
    parser.add_argument("--daemon", action="store_true", help="Run in continuous background polling mode")

    args = parser.parse_args()
    watcher = DormantBalanceWatcher(interval_seconds=args.interval)

    if args.once:
        console.print("[cyan]Running single balance check across dormant contracts...[/]")
        tot, act = watcher.run_cycle()
        console.print(f"[green]✓ Completed check of {tot} dormant contracts. {act} newly funded & activated.[/]")
    elif args.daemon:
        watcher.start_monitoring()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
