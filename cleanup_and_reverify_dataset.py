#!/usr/bin/env python3
"""
Parallel dataset cleanup & re-verification.

Workers run static + on-chain checks without holding SQLite. Each result is
persisted via TokenScannerDB.update_token_flags (WAL + busy retry).
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from token_scanner_daemon import (
    DB_PATH,
    TRIAGE_DIR,
    TokenScannerDB,
    OnChainStateVerifier,
    StaticVulnerabilityAuditor,
    TriageReportGenerator,
    load_saved_source,
)

DISK_CHAINS = ("ethereum", "arbitrum", "base")


def discover_disk_contracts(contracts_root: str = "./contracts") -> List[Tuple[str, str, str, str, str]]:
    """Walk contracts/<chain>/<address>/src into (address, chain, name, compiler, category)."""
    rows: List[Tuple[str, str, str, str, str]] = []
    for chain in DISK_CHAINS:
        root = os.path.join(contracts_root, chain)
        if not os.path.isdir(root):
            continue
        for name in os.listdir(root):
            addr = name.lower()
            if not addr.startswith("0x") or len(addr) < 42:
                continue
            src_dir = os.path.join(root, name, "src")
            if not os.path.isdir(src_dir):
                continue
            meta: Dict[str, Any] = {}
            meta_path = os.path.join(root, name, "metadata.json")
            if os.path.isfile(meta_path):
                try:
                    with open(meta_path, encoding="utf-8") as fh:
                        meta = json.load(fh)
                except (OSError, json.JSONDecodeError):
                    meta = {}
            rows.append((
                addr,
                chain,
                str(meta.get("contract_name") or "Unknown"),
                str(meta.get("compiler_version") or "Unknown"),
                str(meta.get("category") or "CUSTOM_LOGIC"),
            ))
    return rows


def ingest_disk_contracts(db: TokenScannerDB, contracts_root: str = "./contracts") -> int:
    """INSERT OR IGNORE on-disk verified folders so reverify has rows to work on."""
    rows = discover_disk_contracts(contracts_root)
    ts = datetime.now(timezone.utc).isoformat()
    for addr, chain, name, compiler, category in rows:
        db.ensure_token_row(
            address=addr,
            chain=chain,
            name=name,
            compiler=compiler,
            category=category,
            timestamp=ts,
        )
    return len(rows)


def _default_workers() -> int:
    cpu = os.cpu_count() or 8
    return max(4, min(12, cpu))


def reverify_one(
    row: Tuple[str, str, str, str, str],
) -> Dict[str, Any]:
    """CPU/RPC-only reverify for one contract. No DB I/O here."""
    addr, chain, name, compiler, category = row
    result: Dict[str, Any] = {
        "address": addr,
        "chain": chain,
        "name": name,
        "skipped_no_source": False,
        "is_active": False,
        "mitigated": False,
        "dynamic_status": "CLEAN_NO_EXPLOIT",
        "eth_bal": 0.0,
        "triage_path": None,
        "findings": {},
        "error": None,
    }

    try:
        all_source = load_saved_source(chain, addr)
        if not all_source:
            result["skipped_no_source"] = True
            result["dynamic_status"] = "NO_SOURCE_ON_DISK"
            return result

        findings, evidence_list = StaticVulnerabilityAuditor.audit_source(all_source)
        result["findings"] = findings
        user_exploits = [e for e in evidence_list if e.get("user_exploitable", False)]

        is_active = False
        dynamic_status = "CLEAN_NO_EXPLOIT"
        eth_bal = 0.0
        triage_path = None

        if user_exploits:
            is_active, dynamic_status, eth_bal, confirmed, profit_payload = (
                OnChainStateVerifier.verify_onchain_liveness(
                    addr, chain, user_exploits, all_source
                )
            )
            result["expected_profit_eth"] = (
                profit_payload.get("expected_profit_eth") if profit_payload else None
            )
            if is_active and confirmed:
                contract_meta = {
                    "address": addr,
                    "chain": chain,
                    "name": name,
                    "compiler": compiler,
                    "category": category,
                    "eth_balance": eth_bal,
                    "dynamic_status": dynamic_status,
                    "profit": profit_payload,
                }
                triage_path = TriageReportGenerator.generate_triage_file(
                    contract_meta, confirmed
                )
            else:
                result["mitigated"] = True

        result["is_active"] = bool(is_active and triage_path)
        result["dynamic_status"] = dynamic_status
        result["eth_bal"] = eth_bal
        result["triage_path"] = triage_path
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        result["dynamic_status"] = f"REVERIFY_ERROR:{type(e).__name__}"
    return result


def _persist_result(db: TokenScannerDB, result: Dict[str, Any]) -> None:
    findings = result.get("findings") or {}
    is_active = bool(result.get("is_active"))
    triage_path = result.get("triage_path")
    fields = {
        "is_user_exploitable": 1 if is_active else 0,
        "onchain_verified": 1 if is_active else 0,
        "dynamic_status": result.get("dynamic_status") or "CLEAN_NO_EXPLOIT",
        "eth_balance": float(result.get("eth_bal") or 0.0),
        "has_zero_slippage": bool(findings.get("has_zero_slippage", False)),
        "has_dynamic_taxes": bool(findings.get("has_dynamic_taxes", False)),
        "has_conditional_honeypot": bool(findings.get("has_conditional_honeypot", False)),
        "has_unlimited_mint": bool(findings.get("has_unlimited_mint", False)),
        "has_unprotected_critical_function": bool(
            findings.get("has_unprotected_critical_function", False)
        ),
        "has_vault_inflation": bool(findings.get("has_vault_inflation", False)),
        "has_fee_on_transfer_flaw": bool(findings.get("has_fee_on_transfer_flaw", False)),
        "has_flash_staking_flaw": bool(findings.get("has_flash_staking_flaw", False)),
        "has_arbitrary_call": bool(findings.get("has_arbitrary_call", False)),
        "has_reflection_ratio_flaw": bool(findings.get("has_reflection_ratio_flaw", False)),
        "has_reentrancy_flaw": bool(findings.get("has_reentrancy_flaw", False)),
        "has_unprotected_initializer": bool(
            findings.get("has_unprotected_initializer", False)
        ),
        "has_spot_oracle_flaw": bool(findings.get("has_spot_oracle_flaw", False)),
        "has_signature_replay_flaw": bool(findings.get("has_signature_replay_flaw", False)),
        "has_tx_origin_auth": bool(findings.get("has_tx_origin_auth", False)),
        "has_unprotected_router_setter": bool(
            findings.get("has_unprotected_router_setter", False)
        ),
        "has_permit_no_nonce": bool(findings.get("has_permit_no_nonce", False)),
        "has_multicall_msgvalue": bool(findings.get("has_multicall_msgvalue", False)),
        "has_public_swapback": bool(findings.get("has_public_swapback", False)),
        "triage_file_path": triage_path,
        "expected_profit_eth": result.get("expected_profit_eth"),
    }
    # Skips with no source still clear stale exploitable flags.
    db.update_token_flags(result["address"], fields)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parallel cleanup & re-verification of verified contracts"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=_default_workers(),
        help="Thread pool size for audit/RPC (default: min(12, cpu))",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Optional cap on contracts processed (0 = all)",
    )
    parser.add_argument(
        "--keep-queue",
        action="store_true",
        help="Do not wipe existing triage_queue cards before starting",
    )
    parser.add_argument(
        "--from-disk",
        action="store_true",
        help="Ingest contracts/{ethereum,arbitrum,base}/<addr> folders into SQLite first",
    )
    parser.add_argument(
        "--contracts-root",
        default="./contracts",
        help="Root folder that contains per-chain contract directories",
    )
    args = parser.parse_args()
    workers = max(1, args.workers)

    print("[*] Starting Complete Dataset Cleanup & Re-verification...")
    db = TokenScannerDB(DB_PATH)
    print(f"[*] SQLite journal_mode={db.journal_mode()} path={DB_PATH}")
    if args.from_disk:
        n = ingest_disk_contracts(db, args.contracts_root)
        print(f"[*] Ingested {n} on-disk contract folders (INSERT OR IGNORE)")

    os.makedirs(TRIAGE_DIR, exist_ok=True)
    if not args.keep_queue:
        old_cards = glob.glob(os.path.join(TRIAGE_DIR, "*.md"))
        for card in old_cards:
            os.remove(card)
        print(f"✓ Removed {len(old_cards)} old unverified triage cards from {TRIAGE_DIR}")
    else:
        print(f"[*] Keeping existing triage cards in {TRIAGE_DIR}")

    verified_rows = db.fetch_verified_rows()
    if args.limit and args.limit > 0:
        verified_rows = verified_rows[: args.limit]
    total = len(verified_rows)
    print(
        f"[*] Re-auditing {total} verified contracts with {workers} workers "
        f"(Two-Stage Invariant Verification)...\n"
    )

    counters_lock = threading.Lock()
    active_confirmed_count = 0
    mitigated_count = 0
    skipped_no_source = 0
    error_count = 0
    done_count = 0

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(reverify_one, row): row[0] for row in verified_rows}
        for fut in as_completed(futures):
            result = fut.result()
            try:
                _persist_result(db, result)
            except Exception as e:
                with counters_lock:
                    error_count += 1
                print(
                    f"[!] DB persist failed for {result.get('address')}: {e}",
                    flush=True,
                )

            with counters_lock:
                done_count += 1
                i = done_count
                if result.get("skipped_no_source"):
                    skipped_no_source += 1
                elif result.get("error"):
                    error_count += 1
                elif result.get("is_active"):
                    active_confirmed_count += 1
                    print(
                        f"🚨 ACTIVE CONFIRMED ({str(result.get('chain', '')).upper()}): "
                        f"{result.get('name')} ({result.get('address')}) -> "
                        f"{result.get('dynamic_status')}",
                        flush=True,
                    )
                elif result.get("mitigated") or result.get("findings"):
                    if result.get("mitigated"):
                        mitigated_count += 1

                if i % 100 == 0 or i == total:
                    print(
                        f"  [{i}/{total}] active={active_confirmed_count} "
                        f"filtered={mitigated_count} no_src={skipped_no_source} "
                        f"err={error_count}",
                        flush=True,
                    )

    print("\n" + "=" * 80)
    print("CLEANUP & RE-VERIFICATION SUMMARY")
    print("=" * 80)
    print(f"Workers: {workers}")
    print(f"Total Verified Contracts Processed: {total}")
    print(f"Skipped (no source on disk): {skipped_no_source}")
    print(f"Mitigated / False Positive Filtered: {mitigated_count}")
    print(f"Active Confirmed Exploitable Contracts: {active_confirmed_count}")
    print(f"Errors: {error_count}")
    print(
        f"Actionable Triage Cards in Queue: "
        f"{len(glob.glob(os.path.join(TRIAGE_DIR, '*.md')))}"
    )


if __name__ == "__main__":
    main()
