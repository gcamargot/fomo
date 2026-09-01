#!/usr/bin/env python3
"""
Unified Multi-Chain Token Security Scanner with Deep Dynamic On-Chain Invariant Verification
=============================================================================================
Performs a comprehensive Two-Stage Security Assessment in a single automated pipeline:
  Stage 1: Multi-threaded Static AST & Pattern Audit across 14 vulnerability classes.
  Stage 2: Deep Dynamic On-Chain Invariant, Storage Slot, and Balance Verification via RPC:
    • Proxy Storage Slots (EIP-1967 implementation & admin slots)
    • Vault Share Inflation (totalSupply == 0 vs seeded ratio)
    • Signature Replay & Signer Threshold Isolation (2-of-3 multisig checks)
    • Broken Access Control Simulation (unprivileged eth_call test)
    • Auto-Liquidity AMM Reserves & Treasury Balance Check
Only contracts meeting both static and active dynamic criteria enter the actionable Triage Queue.
"""

import os
import sys
import time
import json
import sqlite3
import re
import argparse
import threading
import random
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor
try:
    from web3 import Web3
except ImportError:
    Web3 = None
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from evm_extractor import EVMExtractor
from solana_extractor import SolanaExtractor
from analyzer import ContractAnalyzer
from profit_estimator import apply_profit_gate, profit_gate_enabled, profit_to_dict
from fork_profit_gate import run_fork_profit_test, should_emit_triage

console = Console()

DB_PATH = "./contracts/token_research_dataset.db"
TRIAGE_DIR = "./contracts/triage_queue"
ALERTS_LOG = "./contracts/ALERTS.log"

EXPLORER_ADDRESS_URL = {
    "ethereum": "https://etherscan.io/address/{addr}",
    "arbitrum": "https://arbiscan.io/address/{addr}",
    "base": "https://basescan.org/address/{addr}",
    "optimism": "https://optimistic.etherscan.io/address/{addr}",
    "polygon": "https://polygonscan.com/address/{addr}",
    "bsc": "https://bscscan.com/address/{addr}",
}


def explorer_address_url(chain: str, address: str) -> str:
    tmpl = EXPLORER_ADDRESS_URL.get((chain or "").lower(), "https://basescan.org/address/{addr}")
    return tmpl.format(addr=address.lower())


def load_saved_source(chain: str, address: str) -> str:
    src_dir = os.path.join("./contracts", chain.lower(), address.lower(), "src")
    if not os.path.isdir(src_dir):
        return ""
    chunks = []
    for root, _, files in os.walk(src_dir):
        for fname in files:
            if fname.endswith((".sol", ".rs")):
                try:
                    with open(os.path.join(root, fname), "r", encoding="utf-8", errors="ignore") as fh:
                        chunks.append(fh.read())
                except Exception:
                    pass
    return "\n".join(chunks)

EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"

DEX_CONFIG = {
    "base": {
        "weth": "0x4200000000000000000000000000000000000006",
        "factories": [
            ("Uniswap V2", "0x8909Dc15e40173Ff4699343b6eB8132c65e18eC6"),
            ("BaseSwap", "0xFDa619b6d20975be80A10332cD39b9a4b0FAa8BB"),
            ("SushiSwap V2", "0x71524B4f93c58fcbF659783284E38825f0622859"),
            ("PancakeSwap V2", "0x02a84c1b3BBD7401a5f7fa98a384EBC70bB5749E"),
            ("SwapBased", "0x04C9f118d21e8B767D2e50C946f0cC9F6C367300")
        ]
    },
    "ethereum": {
        "weth": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        "factories": [
            ("Uniswap V2", "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"),
            ("SushiSwap V2", "0xC0AEe478e3658e2610c5F7A4A2E1777cE9e4f2Ac"),
            ("PancakeSwap V2", "0x1097053Fd2ea711dad45caCcc45EfF7548fCB362"),
            ("ShibaSwap", "0x115934131916C5934fbbf9F5e902bB8206A42220")
        ]
    },
    "arbitrum": {
        "weth": "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1",
        "factories": [
            ("SushiSwap V2", "0xc35DADB65012eC5796536bD9864eD8773aBc74C4"),
            ("Camelot V2", "0x6EcCab422D763aC031210895C81787E87B43A652"),
            ("PancakeSwap V2", "0x02a84c1b3BBD7401a5f7fa98a384EBC70bB5749E"),
            ("Uniswap V2 Fork", "0xf1D7CC64Fb4452F05c498126312eBE29f30Fbcf9")
        ]
    }
}

PAIR_ABI = [
    {"constant": True, "inputs": [], "name": "getReserves", "outputs": [{"name": "_reserve0", "type": "uint112"}, {"name": "_reserve1", "type": "uint112"}, {"name": "_blockTimestampLast", "type": "uint32"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "token0", "outputs": [{"name": "", "type": "address"}], "type": "function"}
]

FACTORY_ABI = [
    {"constant": True, "inputs": [{"name": "tokenA", "type": "address"}, {"name": "tokenB", "type": "address"}], "name": "getPair", "outputs": [{"name": "pair", "type": "address"}], "type": "function"}
]

# Aerodrome (Base) uses getPool(tokenA, tokenB, stable) instead of getPair.
AERO_FACTORY = "0x420DD381b31aEf6683db6B902084cB0FFECe40Da"
AERO_FACTORY_ABI = [
    {
        "inputs": [
            {"name": "tokenA", "type": "address"},
            {"name": "tokenB", "type": "address"},
            {"name": "stable", "type": "bool"},
        ],
        "name": "getPool",
        "outputs": [{"name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    }
]

TAX_TOKEN_ABI = [
    {"inputs": [], "name": "swapEnabled", "outputs": [{"type": "bool"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "owner", "outputs": [{"type": "address"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "swapTokensAtAmount", "outputs": [{"type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "buyTotalFees", "outputs": [{"type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "sellTotalFees", "outputs": [{"type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "uniswapV2Pair", "outputs": [{"type": "address"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"name": "account", "type": "address"}], "name": "balanceOf", "outputs": [{"type": "uint256"}], "stateMutability": "view", "type": "function"},
    {
        "inputs": [
            {"name": "to", "type": "address"},
            {"name": "amount", "type": "uint256"},
        ],
        "name": "transfer",
        "outputs": [{"type": "bool"}],
        "stateMutability": "nonpayable",
        "type": "function",
    },
]

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
AUTOLIQ_FN_RE = re.compile(
    r"function\s+(_swapBack|swapAndLiquify|_swapTokensForETH|_swapTokensForEth)\s*\("
)
AUTH_HINT = re.compile(
    r"onlyOwner|onlyRole|onlyAdmin|onlyGovernance|onlyKeeper|onlyOperator|"
    r"onlyAuth|requiresAuth|canCall|ensure_owner|onlyPatron|onlyManager|"
    r"onlyPlatform|onlyFactory|isOwner|governance\(\)|"
    r"msg\.sender\s*==\s*(?:owner|_owner|platform|governance|manager)",
    re.I,
)
SAFE_HINTS = (
    "approvedHashes", "signedMessages", "checkNSignatures", "GS025", "GS026",
    "GnosisSafe", "SafeProxy", "function nonce(",
)
LENDING_HINTS = ("borrow", "collateral", "liquida", "healthFactor", "ltv", "debtShares")

# Reliable Public RPC Fallbacks per Chain
RPC_ENDPOINTS = {
    "base": ["https://mainnet.base.org", "https://base.llamarpc.com"],
    "arbitrum": ["https://arb1.arbitrum.io/rpc", "https://arbitrum.llamarpc.com"],
    "ethereum": ["https://ethereum-rpc.publicnode.com", "https://eth.llamarpc.com", "https://cloudflare-eth.com"],
    "optimism": ["https://mainnet.optimism.io", "https://optimism.llamarpc.com"],
    "polygon": ["https://polygon-rpc.com", "https://polygon.llamarpc.com"],
    "bsc": ["https://binance.llamarpc.com", "https://bsc-dataseed.binance.org"]
}

db_lock = threading.Lock()  # schema init / rare exclusive sections only

# Allowed columns for partial UPDATEs (reverify / dormant).
_TOKEN_UPDATE_COLUMNS = frozenset({
    "is_user_exploitable", "onchain_verified", "dynamic_status", "eth_balance",
    "has_zero_slippage", "has_dynamic_taxes", "has_conditional_honeypot",
    "has_unlimited_mint", "has_unprotected_critical_function", "has_vault_inflation",
    "has_fee_on_transfer_flaw", "has_flash_staking_flaw", "has_arbitrary_call",
    "has_reflection_ratio_flaw", "has_reentrancy_flaw", "has_unprotected_initializer",
    "has_spot_oracle_flaw", "has_signature_replay_flaw", "has_tx_origin_auth",
    "has_unprotected_router_setter", "has_permit_no_nonce", "has_multicall_msgvalue",
    "has_public_swapback", "triage_file_path",
    "slither_high", "slither_medium", "slither_low",
    "expected_profit_eth", "last_checked_at", "next_check_at", "watch_bucket",
    "state_snapshot",
})


def _is_db_locked(exc: BaseException) -> bool:
    msg = str(exc).lower()
    return isinstance(exc, sqlite3.OperationalError) and (
        "locked" in msg or "busy" in msg
    )


def db_execute_with_retry(
    fn: Callable[[], Any],
    *,
    retries: int = 10,
    base_delay: float = 0.05,
) -> Any:
    """Run a short DB op; retry on SQLite locked/busy with exponential backoff."""
    last: Optional[BaseException] = None
    for attempt in range(retries):
        try:
            return fn()
        except sqlite3.OperationalError as e:
            last = e
            if not _is_db_locked(e) or attempt == retries - 1:
                raise
            delay = base_delay * (2 ** attempt) + random.uniform(0, 0.05)
            time.sleep(min(delay, 2.0))
    assert last is not None
    raise last


class TokenScannerDB:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        parent = os.path.dirname(self.db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.init_db()

    def get_connection(self):
        conn = sqlite3.connect(
            self.db_path,
            timeout=60.0,
            check_same_thread=False,
        )
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=60000")
            conn.execute("PRAGMA temp_store=MEMORY")
        except sqlite3.Error:
            pass
        return conn

    def init_db(self):
        with db_lock:
            def _init():
                with self.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                    CREATE TABLE IF NOT EXISTS tokens (
                        address TEXT PRIMARY KEY,
                        name TEXT,
                        symbol TEXT,
                        chain TEXT,
                        compiler TEXT,
                        category TEXT,
                        verified BOOLEAN,
                        first_seen_timestamp TEXT,
                        is_user_exploitable BOOLEAN,
                        onchain_verified BOOLEAN DEFAULT 0,
                        dynamic_status TEXT DEFAULT 'UNVERIFIED',
                        eth_balance REAL DEFAULT 0,
                        has_zero_slippage BOOLEAN,
                        has_dynamic_taxes BOOLEAN,
                        has_conditional_honeypot BOOLEAN,
                        has_unlimited_mint BOOLEAN,
                        has_unprotected_critical_function BOOLEAN DEFAULT 0,
                        has_vault_inflation BOOLEAN DEFAULT 0,
                        has_fee_on_transfer_flaw BOOLEAN DEFAULT 0,
                        has_flash_staking_flaw BOOLEAN DEFAULT 0,
                        has_arbitrary_call BOOLEAN DEFAULT 0,
                        has_reflection_ratio_flaw BOOLEAN DEFAULT 0,
                        has_reentrancy_flaw BOOLEAN DEFAULT 0,
                        has_unprotected_initializer BOOLEAN DEFAULT 0,
                        has_spot_oracle_flaw BOOLEAN DEFAULT 0,
                        has_signature_replay_flaw BOOLEAN DEFAULT 0,
                        has_tx_origin_auth BOOLEAN DEFAULT 0,
                        has_unprotected_router_setter BOOLEAN DEFAULT 0,
                        has_permit_no_nonce BOOLEAN DEFAULT 0,
                        has_multicall_msgvalue BOOLEAN DEFAULT 0,
                        has_public_swapback BOOLEAN DEFAULT 0,
                        slither_high INTEGER,
                        slither_medium INTEGER,
                        slither_low INTEGER,
                        triage_file_path TEXT,
                        raw_metadata TEXT
                    )
                    """)
                    cursor.execute("PRAGMA table_info(tokens)")
                    existing_cols = {row[1] for row in cursor.fetchall()}
                    new_columns = [
                        ("is_user_exploitable", "BOOLEAN DEFAULT 0"),
                        ("onchain_verified", "BOOLEAN DEFAULT 0"),
                        ("dynamic_status", "TEXT DEFAULT 'UNVERIFIED'"),
                        ("eth_balance", "REAL DEFAULT 0"),
                        ("has_unprotected_critical_function", "BOOLEAN DEFAULT 0"),
                        ("has_vault_inflation", "BOOLEAN DEFAULT 0"),
                        ("has_fee_on_transfer_flaw", "BOOLEAN DEFAULT 0"),
                        ("has_flash_staking_flaw", "BOOLEAN DEFAULT 0"),
                        ("has_arbitrary_call", "BOOLEAN DEFAULT 0"),
                        ("has_reflection_ratio_flaw", "BOOLEAN DEFAULT 0"),
                        ("has_reentrancy_flaw", "BOOLEAN DEFAULT 0"),
                        ("has_unprotected_initializer", "BOOLEAN DEFAULT 0"),
                        ("has_spot_oracle_flaw", "BOOLEAN DEFAULT 0"),
                        ("has_signature_replay_flaw", "BOOLEAN DEFAULT 0"),
                        ("has_tx_origin_auth", "BOOLEAN DEFAULT 0"),
                        ("has_unprotected_router_setter", "BOOLEAN DEFAULT 0"),
                        ("has_permit_no_nonce", "BOOLEAN DEFAULT 0"),
                        ("has_multicall_msgvalue", "BOOLEAN DEFAULT 0"),
                        ("has_public_swapback", "BOOLEAN DEFAULT 0"),
                        ("triage_file_path", "TEXT"),
                        ("expected_profit_eth", "REAL"),
                        ("last_checked_at", "TEXT"),
                        ("next_check_at", "TEXT"),
                        ("watch_bucket", "TEXT"),
                        ("state_snapshot", "TEXT"),
                    ]
                    for col_name, col_type in new_columns:
                        if col_name not in existing_cols:
                            try:
                                cursor.execute(
                                    f"ALTER TABLE tokens ADD COLUMN {col_name} {col_type}"
                                )
                            except Exception:
                                pass
                    cursor.execute("""
                    CREATE TABLE IF NOT EXISTS sync_cursors (
                        key TEXT PRIMARY KEY,
                        block_number INTEGER NOT NULL
                    )
                    """)
                    conn.commit()
                    # Ensure WAL is durable on the DB file itself.
                    mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()
                    return mode[0] if mode else None

            db_execute_with_retry(_init)

    def is_scanned(self, address: str) -> bool:
        addr = address.lower()

        def _op():
            with self.get_connection() as conn:
                cur = conn.execute(
                    "SELECT 1 FROM tokens WHERE address = ?", (addr,)
                )
                return cur.fetchone() is not None

        return bool(db_execute_with_retry(_op))

    def save_scan(self, data: Dict):
        params = (
            data["address"].lower(),
            data.get("name", "Unknown"),
            data.get("symbol", "N/A"),
            data.get("chain", "base"),
            data.get("compiler", "Unknown"),
            data.get("category", "CUSTOM_LOGIC"),
            data.get("verified", False),
            data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            data.get("is_user_exploitable", False),
            data.get("onchain_verified", False),
            data.get("dynamic_status", "UNVERIFIED"),
            data.get("eth_balance", 0.0),
            data.get("has_zero_slippage", False),
            data.get("has_dynamic_taxes", False),
            data.get("has_conditional_honeypot", False),
            data.get("has_unlimited_mint", False),
            data.get("has_unprotected_critical_function", False),
            data.get("has_vault_inflation", False),
            data.get("has_fee_on_transfer_flaw", False),
            data.get("has_flash_staking_flaw", False),
            data.get("has_arbitrary_call", False),
            data.get("has_reflection_ratio_flaw", False),
            data.get("has_reentrancy_flaw", False),
            data.get("has_unprotected_initializer", False),
            data.get("has_spot_oracle_flaw", False),
            data.get("has_signature_replay_flaw", False),
            data.get("has_tx_origin_auth", False),
            data.get("has_unprotected_router_setter", False),
            data.get("has_permit_no_nonce", False),
            data.get("has_multicall_msgvalue", False),
            data.get("has_public_swapback", False),
            data.get("slither_high", 0),
            data.get("slither_medium", 0),
            data.get("slither_low", 0),
            data.get("triage_file_path", None),
            json.dumps(data.get("raw_metadata", {})),
            data.get("expected_profit_eth"),
        )

        def _op():
            with self.get_connection() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO tokens (
                        address, name, symbol, chain, compiler, category, verified,
                        first_seen_timestamp, is_user_exploitable, onchain_verified,
                        dynamic_status, eth_balance,
                        has_zero_slippage, has_dynamic_taxes, has_conditional_honeypot,
                        has_unlimited_mint, has_unprotected_critical_function,
                        has_vault_inflation, has_fee_on_transfer_flaw,
                        has_flash_staking_flaw, has_arbitrary_call,
                        has_reflection_ratio_flaw, has_reentrancy_flaw,
                        has_unprotected_initializer, has_spot_oracle_flaw,
                        has_signature_replay_flaw, has_tx_origin_auth,
                        has_unprotected_router_setter, has_permit_no_nonce,
                        has_multicall_msgvalue, has_public_swapback,
                        slither_high, slither_medium, slither_low,
                        triage_file_path, raw_metadata, expected_profit_eth
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    params,
                )
                conn.commit()

        db_execute_with_retry(_op)

    def get_cursor(self, key: str, default: int = 0) -> int:
        def _op():
            with self.get_connection() as conn:
                row = conn.execute(
                    "SELECT block_number FROM sync_cursors WHERE key = ?",
                    (key,),
                ).fetchone()
                return int(row[0]) if row else int(default)

        return int(db_execute_with_retry(_op))

    def set_cursor(self, key: str, block_number: int) -> None:
        def _op():
            with self.get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO sync_cursors (key, block_number) VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET block_number = excluded.block_number
                    """,
                    (key, int(block_number)),
                )
                conn.commit()

        db_execute_with_retry(_op)

    def ensure_token_row(
        self,
        *,
        address: str,
        chain: str,
        name: str = "Unknown",
        compiler: str = "Unknown",
        category: str = "CUSTOM_LOGIC",
        timestamp: Optional[str] = None,
        verified: bool = True,
    ) -> None:
        """Insert a row if missing (disk ingest / factory). Does not overwrite scans."""
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        addr = address.lower()

        def _op():
            with self.get_connection() as conn:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO tokens (
                        address, name, chain, compiler, category, verified,
                        first_seen_timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (addr, name, chain, compiler, category, 1 if verified else 0, ts),
                )
                conn.commit()

        db_execute_with_retry(_op)

    def update_token_flags(self, address: str, fields: Dict[str, Any]) -> None:
        """Short-txn partial UPDATE for reverify / dormant activation."""
        if not fields:
            return
        bad = set(fields) - _TOKEN_UPDATE_COLUMNS
        if bad:
            raise ValueError(f"Disallowed token columns: {sorted(bad)}")
        cols = list(fields.keys())
        assignments = ", ".join(f"{c} = ?" for c in cols)
        values = [fields[c] for c in cols] + [address.lower()]

        def _op():
            with self.get_connection() as conn:
                conn.execute(
                    f"UPDATE tokens SET {assignments} WHERE address = ?",
                    values,
                )
                conn.commit()

        db_execute_with_retry(_op)

    def fetch_verified_rows(self) -> List[Tuple]:
        def _op():
            with self.get_connection() as conn:
                cur = conn.execute(
                    "SELECT address, chain, name, compiler, category "
                    "FROM tokens WHERE verified = 1"
                )
                return cur.fetchall()

        return list(db_execute_with_retry(_op))

    def journal_mode(self) -> str:
        def _op():
            with self.get_connection() as conn:
                row = conn.execute("PRAGMA journal_mode").fetchone()
                return (row[0] if row else "unknown")

        return str(db_execute_with_retry(_op))


class OnChainStateVerifier:
    """
    Unified Deep Dynamic On-Chain Verification Engine.
    Evaluates storage slots, balances, simulation calls, and key isolation automatically.
    """

    @staticmethod
    def get_web3_client(chain: str) -> Optional[object]:
        if Web3 is None:
            return None
        endpoints = RPC_ENDPOINTS.get(chain.lower(), [])
        for ep in endpoints:
            try:
                w3 = Web3(Web3.HTTPProvider(ep, request_kwargs={"timeout": 10}))
                if w3.is_connected():
                    return w3
            except Exception:
                continue
        return None

    @staticmethod
    def evaluate_amm_slippage_reserves(w3, chain: str, token_address: str, batch_val_eth: float = 0.10) -> Dict:
        chain = chain.lower()
        cfg = DEX_CONFIG.get(chain)
        if not cfg or not w3:
            return {"status": "UNAVAILABLE", "eth_reserve": 0.0, "threshold_eth": 16.67, "pools": []}

        weth_addr = w3.to_checksum_address(cfg["weth"])
        tkn_addr = w3.to_checksum_address(token_address)
        critical_threshold = batch_val_eth / 0.006

        discovered_pools = []
        for dex_name, f_addr in cfg["factories"]:
            try:
                fc = w3.eth.contract(address=w3.to_checksum_address(f_addr), abi=FACTORY_ABI)
                p_addr = fc.functions.getPair(tkn_addr, weth_addr).call()
                if p_addr and p_addr != "0x0000000000000000000000000000000000000000":
                    pair_c = w3.eth.contract(address=w3.to_checksum_address(p_addr), abi=PAIR_ABI)
                    r0, r1, _ = pair_c.functions.getReserves().call()
                    t0 = pair_c.functions.token0().call()
                    weth_is_t0 = t0.lower() == weth_addr.lower()
                    eth_reserve = (r0 if weth_is_t0 else r1) / 1e18
                    token_reserve = (r1 if weth_is_t0 else r0) / 1e18

                    is_crit = eth_reserve <= critical_threshold
                    is_warn = (not is_crit) and (eth_reserve <= critical_threshold * 2.0)

                    discovered_pools.append({
                        "dex": dex_name,
                        "pair": p_addr,
                        "eth_reserve": eth_reserve,
                        "token_reserve": token_reserve,
                        "is_critical": is_crit,
                        "is_warning": is_warn,
                        "official": False,
                    })
            except Exception:
                continue

        if chain == "base":
            try:
                aero = w3.eth.contract(address=w3.to_checksum_address(AERO_FACTORY), abi=AERO_FACTORY_ABI)
                for stable, label in ((False, "Aerodrome Volatile"), (True, "Aerodrome Stable")):
                    p_addr = aero.functions.getPool(tkn_addr, weth_addr, stable).call()
                    if p_addr and int(p_addr, 16) != 0:
                        pair_c = w3.eth.contract(address=w3.to_checksum_address(p_addr), abi=PAIR_ABI)
                        r0, r1, _ = pair_c.functions.getReserves().call()
                        t0 = pair_c.functions.token0().call()
                        weth_is_t0 = t0.lower() == weth_addr.lower()
                        eth_reserve = (r0 if weth_is_t0 else r1) / 1e18
                        token_reserve = (r1 if weth_is_t0 else r0) / 1e18
                        is_crit = eth_reserve <= critical_threshold
                        is_warn = (not is_crit) and (eth_reserve <= critical_threshold * 2.0)
                        discovered_pools.append({
                            "dex": label,
                            "pair": p_addr,
                            "eth_reserve": eth_reserve,
                            "token_reserve": token_reserve,
                            "is_critical": is_crit,
                            "is_warning": is_warn,
                            "official": False,
                        })
            except Exception:
                pass

        if not discovered_pools:
            return {"status": "NO_V2_PAIRS_FOUND", "eth_reserve": 0.0, "threshold_eth": critical_threshold, "pools": []}

        discovered_pools.sort(key=lambda x: x["eth_reserve"], reverse=True)
        primary_pool = discovered_pools[0]
        critical_pools = [p for p in discovered_pools if p["is_critical"]]
        warning_pools = [p for p in discovered_pools if p["is_warning"]]

        if len(critical_pools) == len(discovered_pools):
            status = "CRITICAL_ALL_POOLS_EXTRACTABLE"
        elif len(critical_pools) > 0 and not primary_pool["is_critical"]:
            status = "FRAGMENTED_SECONDARY_POOLS_CRITICAL"
        elif primary_pool["is_warning"]:
            status = "WARNING_APPROACHING_THREAT"
        else:
            status = "SAFE_HIGH_LIQUIDITY_BUFFER"

        return {
            "status": status,
            "primary_pool": primary_pool,
            "discovered_pools": discovered_pools,
            "critical_pools": critical_pools,
            "warning_pools": warning_pools,
            "eth_reserve": primary_pool["eth_reserve"],
            "token_reserve": primary_pool.get("token_reserve", 0.0),
            "threshold_eth": critical_threshold
        }

    @staticmethod
    def _safe_call(fn, default=None):
        try:
            return fn.call()
        except Exception:
            return default

    @staticmethod
    def _safe_owner(w3, c_addr) -> Optional[str]:
        try:
            token = w3.eth.contract(address=c_addr, abi=TAX_TOKEN_ABI)
            owner = OnChainStateVerifier._safe_call(token.functions.owner())
            if owner is None:
                return None
            return w3.to_checksum_address(owner).lower()
        except Exception:
            return None

    @staticmethod
    def probe_unauth_selector(w3, address: str, signature: str, args_addr: Optional[str] = None) -> str:
        """Probe a selector from a random EOA. Returns success | auth | revert."""
        try:
            sel = w3.keccak(text=signature)[:4]
            data = sel
            if args_addr:
                data = sel + bytes.fromhex(args_addr[2:].rjust(64, "0"))
            w3.eth.call({
                "from": w3.to_checksum_address("0x000000000000000000000000000000000000a11ce"),
                "to": w3.to_checksum_address(address),
                "data": data,
            })
            return "success"
        except Exception as e:
            msg = str(e).lower()
            if any(
                x in msg
                for x in (
                    "owner", "auth", "caller is not", "unauthorized",
                    "accesscontrol", "ownable", "only ", "only factory",
                    "only platform", "not eoa", "not from", "governance",
                    "forbidden", "access denied", "!gov", "not manager",
                    "not admin", "not keeper", "not operator",
                )
            ):
                return "auth"
            return "revert"

    @staticmethod
    def evaluate_swapback_liveness(w3, token_address: str, source_text: str) -> Dict:
        """Reachability gates for tax-token auto-liq (`_swapBack`)."""
        c_addr = w3.to_checksum_address(token_address)
        token = w3.eth.contract(address=c_addr, abi=TAX_TOKEN_ABI)
        owner = OnChainStateVerifier._safe_call(token.functions.owner())
        swap_enabled = OnChainStateVerifier._safe_call(token.functions.swapEnabled())
        threshold = OnChainStateVerifier._safe_call(token.functions.swapTokensAtAmount())
        buy_fees = OnChainStateVerifier._safe_call(token.functions.buyTotalFees())
        sell_fees = OnChainStateVerifier._safe_call(token.functions.sellTotalFees())
        official_pair = OnChainStateVerifier._safe_call(token.functions.uniswapV2Pair())
        treasury_tokens = OnChainStateVerifier._safe_call(token.functions.balanceOf(c_addr))

        owner_s = None
        if owner is not None:
            try:
                owner_s = w3.to_checksum_address(owner).lower()
            except Exception:
                owner_s = str(owner).lower()
        owner_burned = owner_s == ZERO_ADDRESS.lower() if owner_s else None
        if official_pair is not None:
            try:
                official_pair = w3.to_checksum_address(official_pair)
            except Exception:
                official_pair = str(official_pair)
        fees_zero = None
        if buy_fees is not None and sell_fees is not None:
            fees_zero = int(buy_fees) == 0 and int(sell_fees) == 0
        can_swap = None
        if treasury_tokens is not None and threshold is not None:
            can_swap = int(treasury_tokens) >= int(threshold)

        official_pair_eth = None
        if official_pair and int(official_pair, 16) != 0:
            try:
                pair_c = w3.eth.contract(address=w3.to_checksum_address(official_pair), abi=PAIR_ABI)
                r0, r1, _ = pair_c.functions.getReserves().call()
                t0 = pair_c.functions.token0().call()
                official_pair_eth = (r1 if t0.lower() == c_addr.lower() else r0) / 1e18
            except Exception:
                official_pair_eth = None

        return {
            "has_autoliq_sink": bool(AUTOLIQ_FN_RE.search(source_text or "")),
            "swap_enabled": swap_enabled,
            "owner": owner_s,
            "owner_burned": owner_burned,
            "can_swap": can_swap,
            "fees_zero": fees_zero,
            "official_pair": official_pair,
            "official_pair_eth": official_pair_eth,
            "treasury_tokens": treasury_tokens,
            "threshold": threshold,
        }

    @staticmethod
    def probe_swapback_fires(w3, token_address: str) -> Optional[bool]:
        """
        Simulate a non-pair transfer from a throwaway EOA whose ERC-20 balance
        is injected at mapping slot 0 (OZ ERC20). SwapBack that actually calls
        the router costs far more gas than a no-op early return.
        Returns True/False when the node accepts state overrides, else None.
        """
        try:
            token = w3.to_checksum_address(token_address)
            alice = w3.to_checksum_address("0x000000000000000000000000000000000000a11ce")
            bob = w3.to_checksum_address("0x0000000000000000000000000000000000000b0b")
            amount = 10 ** 18
            calldata = (
                "0xa9059cbb"
                + bob[2:].lower().rjust(64, "0")
                + hex(amount)[2:].rjust(64, "0")
            )
            slot = w3.to_hex(w3.keccak(bytes.fromhex(alice[2:].lower().rjust(64, "0") + "00" * 32)))
            balance_word = "0x" + (amount * 10_000).to_bytes(32, "big").hex()
            overrides = {token: {"stateDiff": {slot: balance_word}}}
            tx = {"from": alice, "to": token, "data": calldata, "gas": hex(2_000_000)}
            res = w3.provider.make_request("eth_estimateGas", [tx, "latest", overrides])
            if res.get("result"):
                gas = int(res["result"], 16)
                if gas >= 160000:
                    return True
                if gas <= 130000:
                    return False
                return None
            err = str(res.get("error", "")).lower()
            if "insufficient" in err or "exceeds balance" in err or "transfer amount exceeds" in err:
                return None
            if "revert" in err or "uniswap" in err or "pancake" in err:
                return True
            return None
        except Exception:
            return None

    @staticmethod
    def verify_onchain_liveness(address: str, chain: str, static_exploits: List[Dict], source_text: str) -> Tuple[bool, str, float, List[Dict], Optional[Dict]]:
        """
        Deep dynamic evaluation of static findings against on-chain state.
        Returns: (is_active, dynamic_status, eth_balance, confirmed_exploits, profit_payload)
        """
        if chain.lower() == "solana":
            return False, "SOLANA_UNSUPPORTED_DYNAMIC", 0.0, [], None

        w3 = OnChainStateVerifier.get_web3_client(chain)
        if not w3:
            return False, "RPC_UNREACHABLE", 0.0, [], None

        c_addr = w3.to_checksum_address(address)
        eth_balance = 0.0
        try:
            raw_bal = w3.eth.get_balance(c_addr)
            eth_balance = float(w3.from_wei(raw_bal, "ether"))
        except Exception:
            pass

        confirmed_exploits = []
        status_notes = []
        profit_payload = None

        for exp in static_exploits:
            vtype = exp.get("type")

            # 1. Zero-slippage auto-liq: static `amountOutMin = 0` is not enough.
            #    TOSHI/BRETT taught us swapBack must actually be reachable.
            if vtype == "ZERO_SLIPPAGE_LIQUIDATION":
                live = OnChainStateVerifier.evaluate_swapback_liveness(w3, address, source_text)
                amm_eval = OnChainStateVerifier.evaluate_amm_slippage_reserves(w3, chain, address)
                thresh_eth = amm_eval.get("threshold_eth", 16.67)
                official_eth = live.get("official_pair_eth")
                res_eth = official_eth if official_eth is not None else amm_eval.get("eth_reserve", 0.0)

                if not live.get("has_autoliq_sink"):
                    status_notes.append("ZERO_SLIPPAGE_NOT_AUTOLIQ_SINK")
                    continue
                if live.get("swap_enabled") is False:
                    if live.get("owner_burned"):
                        status_notes.append("ZERO_SLIPPAGE_DORMANT_SWAP_OFF_OWNER_BURNED")
                    else:
                        status_notes.append("ZERO_SLIPPAGE_DORMANT_SWAP_OFF_OWNER_LIVE")
                    continue
                if live.get("can_swap") is False:
                    status_notes.append("ZERO_SLIPPAGE_BELOW_THRESHOLD")
                    continue
                if live.get("fees_zero") is True:
                    # Current buy/sell fees are 0. Private leftover buckets can
                    # still make swapBack sell. Probe a simulated transfer.
                    fired = OnChainStateVerifier.probe_swapback_fires(w3, address)
                    if fired is True:
                        status_notes.append("ZERO_SLIPPAGE_LEFTOVER_BUCKETS")
                    elif fired is False:
                        status_notes.append("ZERO_SLIPPAGE_FEES_ZERO_SWAPBACK_NOOP")
                        continue
                    elif live.get("owner_burned") is False:
                        status_notes.append("ZERO_SLIPPAGE_FEES_ZERO_OWNER_CAN_RAISE")
                        continue
                    else:
                        status_notes.append("ZERO_SLIPPAGE_FEES_ZERO_CANNOT_REFILL")
                        continue
                if res_eth and res_eth > thresh_eth:
                    status_notes.append(f"ZERO_SLIPPAGE_BUFFERED_OFFICIAL_{res_eth:.1f}ETH")
                    continue
                # Dust / empty official pair: nothing to sandwich profitably.
                if not res_eth or res_eth < 0.05:
                    status_notes.append(
                        f"ZERO_SLIPPAGE_DEAD_OR_DUST_POOL_{0.0 if not res_eth else res_eth:.4f}ETH"
                    )
                    continue

                pair_s = live.get("official_pair") or "unknown"
                exp["onchain_evidence"] = (
                    f"swapEnabled=true canSwap=true official_pair={pair_s} "
                    f"reserve={res_eth:.4f} ETH (<= {thresh_eth:.2f} ETH) "
                    f"native={eth_balance:.4f} ETH"
                )
                status_notes.append("ZERO_SLIPPAGE_ACTIVE")
                confirmed_exploits.append(exp)

            elif vtype == "UNPROTECTED_INITIALIZER_HIJACK":
                src_l = source_text.lower()
                if "facet" in src_l or "msg.sender == factory" in source_text or any(h in source_text for h in SAFE_HINTS):
                    status_notes.append("FACET_OR_SAFE_OR_FACTORY_INITIALIZER_MITIGATED")
                    continue
                try:
                    impl_raw = w3.eth.get_storage_at(c_addr, EIP1967_IMPL_SLOT).hex()
                    is_proxy_set = int(impl_raw, 16) != 0
                except Exception:
                    is_proxy_set = False
                owner = OnChainStateVerifier._safe_owner(w3, c_addr)
                init_probe = OnChainStateVerifier.probe_unauth_selector(w3, c_addr, "initialize()")
                if is_proxy_set:
                    status_notes.append("PROXY_ALREADY_SEALED")
                elif init_probe == "auth":
                    status_notes.append("INITIALIZE_AUTH_REVERTED")
                elif owner and owner != ZERO_ADDRESS.lower():
                    status_notes.append("INITIALIZE_OWNER_ALREADY_SET")
                elif eth_balance > 0.0 and init_probe in ("success", "revert"):
                    exp["onchain_evidence"] = (
                        f"Uninitialized (EIP-1967 empty, owner unset) holding {eth_balance:.4f} ETH; "
                        f"initialize() probe={init_probe}"
                    )
                    confirmed_exploits.append(exp)
                    status_notes.append("PROXY_UNINITIALIZED_FUNDED")
                else:
                    status_notes.append("INITIALIZE_OPEN_BUT_UNFUNDED")

            elif vtype == "SIGNATURE_REPLAY_FLAW":
                if any(h in source_text for h in SAFE_HINTS) or "sequenceId" in source_text:
                    status_notes.append("SIGNATURE_REPLAY_SAFE_OR_SEQUENCE_MITIGATED")
                elif eth_balance > 0.01:
                    exp["onchain_evidence"] = f"Funded contract ({eth_balance:.4f} ETH) with un-nonce'd ecrecover"
                    confirmed_exploits.append(exp)
                    status_notes.append("SIGNATURE_REPLAY_FUNDED")
                else:
                    status_notes.append("SIGNATURE_REPLAY_EMPTY_BALANCE")

            elif vtype == "ERC4626_INFLATION_ATTACK":
                try:
                    raw_ts = w3.eth.call({"to": c_addr, "data": w3.keccak(text="totalSupply()")[:4]})
                    ts_val = int(raw_ts.hex(), 16) if raw_ts else 0
                    assets = 0
                    try:
                        raw_asset = w3.eth.call({"to": c_addr, "data": w3.keccak(text="asset()")[:4]})
                        asset_addr = w3.to_checksum_address("0x" + raw_asset[-20:].hex())
                        raw_ab = w3.eth.call({
                            "to": asset_addr,
                            "data": w3.keccak(text="balanceOf(address)")[:4] + bytes.fromhex(c_addr[2:].zfill(64)),
                        })
                        assets = int(raw_ab.hex(), 16) if raw_ab else 0
                    except Exception:
                        assets = -1
                    if ts_val == 0 and assets == 0:
                        exp["onchain_evidence"] = "Vault unseeded: totalSupply=0 and asset.balanceOf(vault)=0"
                        confirmed_exploits.append(exp)
                        status_notes.append("VAULT_INFLATION_UNSEEDED")
                    elif ts_val == 0:
                        status_notes.append("VAULT_SUPPLY_ZERO_BUT_ALREADY_HAS_ASSETS")
                    else:
                        status_notes.append("VAULT_ALREADY_SEEDED")
                except Exception:
                    status_notes.append("VAULT_PROBE_FAILED")

            elif vtype == "BROKEN_ACCESS_CONTROL":
                # Only "success" proves an unauth call went through. A bare
                # revert is usually wrong-args / no balance / missing selector.
                probe = OnChainStateVerifier.probe_unauth_selector(w3, c_addr, "withdraw()")
                if probe == "auth":
                    status_notes.append("BROKEN_ACCESS_AUTH_REVERTED")
                elif probe == "success" and eth_balance > 0.0:
                    exp["onchain_evidence"] = (
                        f"Unauthed withdraw() succeeded with {eth_balance:.4f} ETH on contract"
                    )
                    confirmed_exploits.append(exp)
                    status_notes.append("BROKEN_ACCESS_CALLABLE")
                elif probe == "success":
                    status_notes.append("BROKEN_ACCESS_CALLABLE_BUT_UNFUNDED")
                else:
                    status_notes.append("BROKEN_ACCESS_REVERT_OR_UNKNOWN")

            elif vtype == "CHECKS_EFFECTS_REENTRANCY":
                if "nonReentrant" in source_text:
                    status_notes.append("REENTRANCY_HAS_GUARD")
                elif eth_balance > 0.0:
                    exp["onchain_evidence"] = f"Funded target holding {eth_balance:.4f} ETH with CEI violation"
                    confirmed_exploits.append(exp)
                    status_notes.append("REENTRANCY_FUNDED")
                else:
                    status_notes.append("REENTRANCY_EMPTY_BALANCE")

            elif vtype == "SPOT_ORACLE_MANIPULATION":
                # 1 wei / dust must not count as a funded lending target.
                if not any(h in source_text for h in LENDING_HINTS):
                    status_notes.append("SPOT_ORACLE_NOT_LENDING")
                elif eth_balance < 0.01:
                    status_notes.append(
                        f"SPOT_ORACLE_DUST_OR_EMPTY_{eth_balance:.6f}ETH"
                    )
                else:
                    exp["onchain_evidence"] = (
                        f"Lending-like contract with {eth_balance:.4f} ETH using spot reserves"
                    )
                    confirmed_exploits.append(exp)
                    status_notes.append("SPOT_ORACLE_LENDING_FUNDED")

            elif vtype == "FLASH_STAKING_REWARD_DRAIN":
                if eth_balance > 0.0:
                    exp["onchain_evidence"] = f"Funded reward pool holding {eth_balance:.4f} ETH without temporal checkpoints"
                    confirmed_exploits.append(exp)
                    status_notes.append("FLASH_STAKING_FUNDED")
                else:
                    status_notes.append("FLASH_STAKING_EMPTY_BALANCE")

            elif vtype == "REFLECTION_RATIO_MANIPULATION":
                amm_eval = OnChainStateVerifier.evaluate_amm_slippage_reserves(w3, chain, address)
                res_eth = amm_eval.get("eth_reserve", 0.0)
                if res_eth > 0.0:
                    exp["onchain_evidence"] = f"Active DEX pair holding {res_eth:.4f} ETH with callable reflection"
                    confirmed_exploits.append(exp)
                    status_notes.append("REFLECTION_PAIR_FUNDED")
                else:
                    status_notes.append("REFLECTION_DORMANT_ZERO_LIQUIDITY")

            elif vtype == "UNCONSTRAINED_ARBITRARY_CALL":
                if eth_balance > 0.0:
                    exp["onchain_evidence"] = f"Funded target ({eth_balance:.4f} ETH) with user-supplied call/delegatecall"
                    confirmed_exploits.append(exp)
                    status_notes.append("ARBITRARY_CALL_FUNDED")
                else:
                    status_notes.append("ARBITRARY_CALL_ZERO_BALANCE")

            elif vtype == "TX_ORIGIN_AUTH":
                exp["onchain_evidence"] = (
                    "tx.origin compared to owner()/_owner (phishing of privileged key); "
                    f"native={eth_balance:.4f} ETH"
                )
                confirmed_exploits.append(exp)
                status_notes.append("TX_ORIGIN_OWNER_PHISHING")

            elif vtype == "UNPROTECTED_ROUTER_SETTER":
                # Only eth_call success proves an unauth setter. Custom auth
                # strings ("!governance", "FORBIDDEN") look like bare "revert".
                probe = OnChainStateVerifier.probe_unauth_selector(
                    w3, c_addr, "setRouter(address)",
                    args_addr="0x0000000000000000000000000000000000000001",
                )
                if probe == "auth":
                    status_notes.append("ROUTER_SETTER_AUTH_REVERTED")
                elif probe == "success":
                    exp["onchain_evidence"] = (
                        f"Unauthed setRouter(address) succeeded; native={eth_balance:.4f} ETH"
                    )
                    confirmed_exploits.append(exp)
                    status_notes.append("ROUTER_SETTER_CALLABLE")
                else:
                    status_notes.append("ROUTER_SETTER_REVERT_OR_UNKNOWN")

            elif vtype == "PERMIT_NO_NONCE":
                if any(h in source_text for h in SAFE_HINTS):
                    status_notes.append("PERMIT_SAFE_SKIP")
                else:
                    exp["onchain_evidence"] = "permit() implementation without nonces[] / _useNonce"
                    confirmed_exploits.append(exp)
                    status_notes.append("PERMIT_NO_NONCE_PRESENT")

            elif vtype == "MULTICALL_MSGVALUE_REUSE":
                # Pattern alone is not live-exploitable without ETH at stake on
                # the victim contract / caller flow. Require meaningful balance.
                if eth_balance < 0.01:
                    status_notes.append(
                        f"MULTICALL_MSGVALUE_UNFUNDED_{eth_balance:.6f}ETH"
                    )
                else:
                    exp["onchain_evidence"] = (
                        f"multicall forwards call{{value: msg.value}} in a loop; "
                        f"native={eth_balance:.4f} ETH"
                    )
                    confirmed_exploits.append(exp)
                    status_notes.append("MULTICALL_MSGVALUE_FUNDED")

            elif vtype == "PUBLIC_SWAPBACK_TRIGGER":
                live = OnChainStateVerifier.evaluate_swapback_liveness(w3, address, source_text)
                amm_eval = OnChainStateVerifier.evaluate_amm_slippage_reserves(w3, chain, address)
                official_eth = live.get("official_pair_eth")
                res_eth = official_eth if official_eth is not None else amm_eval.get("eth_reserve", 0.0)
                if live.get("swap_enabled") is False:
                    status_notes.append("PUBLIC_SWAPBACK_DISABLED")
                elif live.get("can_swap") is False:
                    status_notes.append("PUBLIC_SWAPBACK_BELOW_THRESHOLD")
                elif live.get("fees_zero") is True and live.get("owner_burned") is not False:
                    status_notes.append("PUBLIC_SWAPBACK_FEES_ZERO")
                elif not res_eth or res_eth < 0.05:
                    status_notes.append(
                        f"PUBLIC_SWAPBACK_DEAD_OR_DUST_POOL_"
                        f"{0.0 if not res_eth else res_eth:.4f}ETH"
                    )
                else:
                    exp["onchain_evidence"] = (
                        f"Public swapBack reachable swapEnabled={live.get('swap_enabled')} "
                        f"canSwap={live.get('can_swap')} reserve={res_eth:.4f} ETH"
                    )
                    confirmed_exploits.append(exp)
                    status_notes.append("PUBLIC_SWAPBACK_ACTIVE")

            elif vtype == "FEE_ON_TRANSFER_INVARIANT":
                if eth_balance > 0.0:
                    exp["onchain_evidence"] = f"Vault/deposit contract funded ({eth_balance:.4f} ETH) credits input amount"
                    confirmed_exploits.append(exp)
                    status_notes.append("FOT_FUNDED")
                else:
                    status_notes.append("FOT_UNFUNDED")

            else:
                status_notes.append(f"{vtype}_NO_DYNAMIC_GATE")

        if confirmed_exploits:
            if profit_gate_enabled():
                amm_eval = OnChainStateVerifier.evaluate_amm_slippage_reserves(
                    w3, chain, address
                )
                live = OnChainStateVerifier.evaluate_swapback_liveness(
                    w3, address, source_text
                )
                treasury_raw = live.get("treasury_tokens") or 0
                try:
                    treasury_raw = int(treasury_raw)
                except (TypeError, ValueError):
                    treasury_raw = 0
                kept, profit_notes, est = apply_profit_gate(
                    confirmed_exploits,
                    eth_balance=eth_balance,
                    pool_eth=float(amm_eval.get("eth_reserve") or 0.0),
                    pool_token=float(amm_eval.get("token_reserve") or 0.0),
                    treasury_token_raw=treasury_raw,
                )
                if profit_notes:
                    status_notes.extend(profit_notes)
                payload = profit_to_dict(est)
                if payload:
                    for exp in kept:
                        exp["profit"] = payload
                confirmed_exploits = kept
                profit_payload = payload

        is_active = len(confirmed_exploits) > 0
        final_status = " | ".join(status_notes) if status_notes else "STATIC_ONLY"
        return is_active, final_status, eth_balance, confirmed_exploits, profit_payload

class AlertDispatcher:
    """
    Dispatches real-time alerts to console, log files, and system notifications.
    """

    @staticmethod
    def emit_triage_alert(contract_data: Dict, user_exploits: List[Dict], triage_path: str):
        addr = contract_data["address"]
        chain = contract_data.get("chain", "UNKNOWN").upper()
        name = contract_data.get("name", "Unknown")
        eth_bal = contract_data.get("eth_balance", 0.0)

        timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Audible terminal chime
        sys.stdout.write("\a")
        sys.stdout.flush()

        # High-Visibility Terminal Banner
        alert_body = (
            f"[bold yellow]CHAIN:[/] [bold cyan]{chain}[/] | [bold yellow]CONTRACT:[/] [bold white]{name}[/] (`{addr}`)\n"
            f"[bold yellow]ON-CHAIN BALANCE:[/] [bold green]{eth_bal:.4f} ETH[/]\n"
            f"[bold yellow]CONFIRMED VECTORS ({len(user_exploits)}):[/]\n"
        )
        for e in user_exploits:
            evidence = e.get("onchain_evidence", "Verified on-chain")
            alert_body += f"  🔥 [{e['severity']}] {e['title']}\n     ↳ Evidence: [cyan]{evidence}[/]\n     ↳ Payoff: [green]{e['payoff']}[/]\n"

        alert_body += f"\n[bold magenta]👉 TRIAGE CARD ACTIONABLE AT:[/] [underline]{triage_path}[/]"

        console.print("\n")
        console.print(Panel(
            alert_body,
            title=f"🚨 [bold red]NEW USER-EXPLOITABLE CONTRACT DETECTED ({chain})[/bold red] - {timestamp_str} 🚨",
            border_style="red bold",
            padding=(1, 2)
        ))
        console.print("\n")

        # Persistent ALERTS.log
        try:
            os.makedirs(os.path.dirname(ALERTS_LOG), exist_ok=True)
            with open(ALERTS_LOG, "a", encoding="utf-8") as f:
                log_entry = {
                    "timestamp": timestamp_str,
                    "chain": chain,
                    "address": addr,
                    "name": name,
                    "eth_balance": eth_bal,
                    "exploits_count": len(user_exploits),
                    "exploits": [e["title"] for e in user_exploits],
                    "triage_card": os.path.abspath(triage_path)
                }
                f.write(json.dumps(log_entry) + "\n")
        except Exception:
            pass

        # Trigger Autonomous AI Agent Triage in background (TEMPORARILY DISABLED)
        # try:
        #     from ai_triage_agent import AIAgentTriager
        #     AIAgentTriager.trigger_agent_triage_async(triage_path, contract_data)
        # except Exception:
        #     pass

class StaticVulnerabilityAuditor:
    """
    Performs static pattern audits across 14 vulnerability classes.
    """

    @staticmethod
    def audit_source(source_text: str) -> Tuple[Dict[str, bool], List[Dict]]:
        findings = {
            "has_zero_slippage": False,
            "has_dynamic_taxes": False,
            "has_conditional_honeypot": False,
            "has_unlimited_mint": False,
            "has_unprotected_critical_function": False,
            "has_vault_inflation": False,
            "has_fee_on_transfer_flaw": False,
            "has_flash_staking_flaw": False,
            "has_arbitrary_call": False,
            "has_reflection_ratio_flaw": False,
            "has_reentrancy_flaw": False,
            "has_unprotected_initializer": False,
            "has_spot_oracle_flaw": False,
            "has_signature_replay_flaw": False,
            "has_tx_origin_auth": False,
            "has_unprotected_router_setter": False,
            "has_permit_no_nonce": False,
            "has_multicall_msgvalue": False,
            "has_public_swapback": False,
        }
        evidence_list = []

        # 1. Zero Slippage Liquidation (auto-liq sink only; a user swap with
        #    amountOutMin=0 is ordinary MEV, not a treasury drain).
        slippage_match = re.search(r"swapExactTokensForETH\w*\s*\([^,]+,\s*0\s*,", source_text)
        if slippage_match:
            findings["has_zero_slippage"] = True
            is_autoliq = bool(AUTOLIQ_FN_RE.search(source_text))
            snippet = StaticVulnerabilityAuditor._extract_snippet(source_text, slippage_match.start())
            evidence_list.append({
                "type": "ZERO_SLIPPAGE_LIQUIDATION",
                "user_exploitable": is_autoliq,
                "title": "Falta de Protección de Slippage en Auto-Liquidación (`amountOutMin = 0`)",
                "severity": "HIGH",
                "exploiter": "Cualquier Usuario / Bot MEV / Flash Loan",
                "victim": "Tesorería del Contrato (Tokens acumulados de comisiones)",
                "payoff": "Ganancia Neta en ETH extraída de la venta forzada con deslizamiento máximo.",
                "snippet": snippet
            })

        # 2. Conditional Honeypot
        honeypot_match = re.search(r"require\s*\([^)]*(?:limited|_is\w+|isWhitelisted|_sniper)[^)]*\)", source_text, re.IGNORECASE)
        if honeypot_match:
            findings["has_conditional_honeypot"] = True
            snippet = StaticVulnerabilityAuditor._extract_snippet(source_text, honeypot_match.start())
            evidence_list.append({
                "type": "CONDITIONAL_HONEYPOT",
                "user_exploitable": False,
                "title": "Restricción de Transferencia Condicional (Anti-Sniper / Honeypot)",
                "severity": "MEDIUM",
                "exploiter": "Owner / Deployer",
                "victim": "Compradores generales",
                "payoff": "Restricción de venta o monopolio inicial de compra.",
                "snippet": snippet
            })

        # 3. Dynamic Fee Hijack
        tax_match = re.search(r"function\s+set\w*Fee\w*\s*\(", source_text, re.IGNORECASE)
        if tax_match:
            findings["has_dynamic_taxes"] = True
            snippet = StaticVulnerabilityAuditor._extract_snippet(source_text, tax_match.start())
            evidence_list.append({
                "type": "DYNAMIC_FEE_HIJACK",
                "user_exploitable": False,
                "title": "Modificación Dinámica de Comisiones (Taxes)",
                "severity": "LOW / MEDIUM",
                "exploiter": "Owner",
                "victim": "Traders",
                "payoff": "Aumento arbitrario de comisiones de compra/venta.",
                "snippet": snippet
            })

        # 4. Arbitrary Minting
        mint_match = re.search(r"function\s+mint\s*\([^)]*\)\s*(?:public|external)[^{]*onlyOwner", source_text)
        if mint_match:
            findings["has_unlimited_mint"] = True
            snippet = StaticVulnerabilityAuditor._extract_snippet(source_text, mint_match.start())
            evidence_list.append({
                "type": "UNLIMITED_MINT",
                "user_exploitable": False,
                "title": "Emisión Ilimitada Oculta de Tokens",
                "severity": "HIGH",
                "exploiter": "Owner",
                "victim": "Holders (Dilución del valor)",
                "payoff": "Creación arbitraria de suministro.",
                "snippet": snippet
            })

        # 5. Broken Access Control on Critical Financial Functions
        # Exclude self-redeem / escrow names (withdrawPullFunds, withdrawIncome, …).
        unprotected_match = re.search(
            r"function\s+(?:emergencyWithdraw|drainTokens|setFeeConfiguration|"
            r"withdrawETH|withdrawStuckTokens|"
            r"withdraw(?!PullFunds|Income|Deposit|Dividend|USDT|DAI|Token|LP|"
            r"Stake|Rewards|All|Fees)\w*|"
            r"rescueETH|rescue\w*|recoverETH|recover\w*|"
            r"sweepToken|sweep\w*|claimStuck|skim)\s*\([^)]*\)\s*"
            r"(?:public|external)",
            source_text,
            re.IGNORECASE,
        )
        if (
            unprotected_match
            and "{" in source_text[unprotected_match.start(): unprotected_match.start() + 250]
            and StaticVulnerabilityAuditor._header_lacks_auth(source_text, unprotected_match)
            and "onlyOwner" not in unprotected_match.group(0)
            and "interface " not in source_text[max(0, unprotected_match.start() - 80): unprotected_match.start()]
        ):
            findings["has_unprotected_critical_function"] = True
            snippet = StaticVulnerabilityAuditor._extract_snippet(source_text, unprotected_match.start())
            evidence_list.append({
                "type": "BROKEN_ACCESS_CONTROL",
                "user_exploitable": True,
                "title": "Función Financiera Crítica sin Control de Acceso",
                "severity": "CRITICAL",
                "exploiter": "Cualquier Usuario Externo",
                "victim": "Contrato / Fondos de Usuarios",
                "payoff": "Extracción directa de fondos o manipulación de parámetros críticos.",
                "snippet": snippet
            })

        # 6. ERC-4626 Vault Inflation Attack
        if "ERC4626" in source_text or "totalAssets()" in source_text:
            inflation_match = re.search(r"(?:assets|amount)\s*\*\s*(?:totalSupply|totalShares)\s*\/\s*(?:totalAssets\(\)|_totalAssets)", source_text)
            if inflation_match and "virtual" not in source_text.lower() and "_decimalsOffset" not in source_text:
                findings["has_vault_inflation"] = True
                snippet = StaticVulnerabilityAuditor._extract_snippet(source_text, inflation_match.start())
                evidence_list.append({
                    "type": "ERC4626_INFLATION_ATTACK",
                    "user_exploitable": True,
                    "title": "Vulnerabilidad de Inflación de Acciones en Bóveda ERC-4626 (First Depositor)",
                    "severity": "HIGH",
                    "exploiter": "Primer Depositante / Atacante de Inflación",
                    "victim": "Siguientes depositantes legítimos",
                    "payoff": "Robo del depósito de la víctima mediante truncamiento por división entera.",
                    "snippet": snippet
                })

        # 7. Fee-on-Transfer Invariant Violation
        fot_match = re.search(r"function\s+deposit\w*\s*\([^)]*uint256\s+(\w+)[^)]*\)[^{]*{[^}]*transferFrom\s*\([^,]+,\s*address\(this\),\s*\1\)[^}]*(?:balanceOf\[msg\.sender\]|\w+Shares\[msg\.sender\])\s*\+=\s*\1", source_text)
        if fot_match and "balanceBefore" not in source_text:
            findings["has_fee_on_transfer_flaw"] = True
            snippet = StaticVulnerabilityAuditor._extract_snippet(source_text, fot_match.start())
            evidence_list.append({
                "type": "FEE_ON_TRANSFER_INVARIANT",
                "user_exploitable": True,
                "title": "Incompatibilidad de Tokens con Comisión (Fee-on-Transfer Invariant Violation)",
                "severity": "HIGH",
                "exploiter": "Cualquier Depositante",
                "victim": "Bóveda / Otros Depositantes",
                "payoff": "Acreditación de saldo superior a los tokens netos recibidos, permitiendo drenar la diferencia.",
                "snippet": snippet
            })

        # 8. Flash-Staking / Instant Reward Drain
        if re.search(r"function\s+(?:stake|deposit)\w*", source_text) and re.search(r"function\s+(?:getReward|claimRewards)\w*", source_text):
            src_low = source_text.lower()
            if ("lastupdatetime" not in src_low and
                "rewardpertokenstored" not in src_low and
                "block.number" not in src_low and
                "cooldown" not in src_low and
                "delayduration" not in src_low and
                "vesting" not in src_low and
                "lockduration" not in src_low):
                findings["has_flash_staking_flaw"] = True
                snippet = StaticVulnerabilityAuditor._extract_snippet(source_text, 0, context_lines=15)
                evidence_list.append({
                    "type": "FLASH_STAKING_REWARD_DRAIN",
                    "user_exploitable": True,
                    "title": "Drenaje de Recompensas por Flash-Staking (Falta de Checkpoints Temporales)",
                    "severity": "HIGH",
                    "exploiter": "Flash Loan Staker",
                    "victim": "Pool de Recompensas",
                    "payoff": "Cosecha instantánea de recompensas en 1 solo bloque.",
                    "snippet": snippet
                })

        # 9. Unconstrained Arbitrary Call
        arb_call_match = re.search(
            r"function\s+\w+\s*\([^)]*address\s+(\w+)[^)]*\)\s*(?:external|public)"
            r"(?![^{]{0,240}(?:onlyOwner|onlyRole))[^{]{0,500}\.(?:call|delegatecall)\s*\(",
            source_text,
        )
        if arb_call_match and StaticVulnerabilityAuditor._header_lacks_auth(source_text, arb_call_match):
            findings["has_arbitrary_call"] = True
            snippet = StaticVulnerabilityAuditor._extract_snippet(source_text, arb_call_match.start())
            evidence_list.append({
                "type": "UNCONSTRAINED_ARBITRARY_CALL",
                "user_exploitable": True,
                "title": "Ejecución de Llamada Externa Arbitraria (Arbitrary Call / Approval Drain)",
                "severity": "CRITICAL",
                "exploiter": "Cualquier Usuario Externo",
                "victim": "Usuarios con Approvals previas / Contrato",
                "payoff": "Drenaje de aprobaciones de tokens o suplantación de identidad.",
                "snippet": snippet
            })

        # 10. Reflection / Rebase Ratio Manipulation
        if "_rTotal" in source_text and "_tTotal" in source_text:
            reflect_match = re.search(r"function\s+(?:deliver|reflect|burnReflect)\s*\([^)]*\)\s*(?:public|external)(?![^{]*onlyOwner)", source_text)
            if reflect_match:
                findings["has_reflection_ratio_flaw"] = True
                snippet = StaticVulnerabilityAuditor._extract_snippet(source_text, reflect_match.start())
                evidence_list.append({
                    "type": "REFLECTION_RATIO_MANIPULATION",
                    "user_exploitable": True,
                    "title": "Manipulación de Tasa de Reflexión en Memecoin (_rTotal / _tTotal)",
                    "severity": "HIGH",
                    "exploiter": "Comprador + Invocador de Reflexión",
                    "victim": "Pool DEX / Otros Holders",
                    "payoff": "Multiplicación artificial de balance relativo vendible en AMM.",
                    "snippet": snippet
                })

        # 11. Checks-Effects-Interactions Violation Reentrancy
        reentrancy_match = re.search(
            r"(?:msg\.sender|recipient|to)\.call\{value:[^}]*\}\(\"\"\)[^;]*;[\s\n]*(?:balanceOf|balances)\[",
            source_text
        )
        if reentrancy_match and "nonReentrant" not in source_text:
            findings["has_reentrancy_flaw"] = True
            snippet = StaticVulnerabilityAuditor._extract_snippet(source_text, reentrancy_match.start())
            evidence_list.append({
                "type": "CHECKS_EFFECTS_REENTRANCY",
                "user_exploitable": True,
                "title": "Reentrancy por Violación de Checks-Effects-Interactions (Drenaje de ETH)",
                "severity": "CRITICAL",
                "exploiter": "Contrato Atacante con Callback receive()",
                "victim": "Tesorería ETH del Contrato",
                "payoff": "Vaciado iterativo de las reservas de ETH del contrato.",
                "snippet": snippet
            })

        # 12. Unprotected Proxy Initializer Hijack
        init_match = re.search(r"function\s+initialize\s*\([^)]*\)\s*(?:public|external)(?![^{;]*(?:initializer|onlyInitializing|onlyOwner))[^{;]*{", source_text)
        if init_match:
            findings["has_unprotected_initializer"] = True
            snippet = StaticVulnerabilityAuditor._extract_snippet(source_text, init_match.start())
            evidence_list.append({
                "type": "UNPROTECTED_INITIALIZER_HIJACK",
                "user_exploitable": True,
                "title": "Inicializador de Proxy sin Protección (Proxy Takeover)",
                "severity": "CRITICAL",
                "exploiter": "Cualquier Usuario Externo",
                "victim": "Protocolo / Propietario Legítimo",
                "payoff": "Apropiación de permisos de admin y retiro de fondos acumulados.",
                "snippet": snippet
            })

        # 13. Spot AMM Price Oracle Reliance & Read-Only Reentrancy Lending Flaws
        # Prefer call-sites (`.getReserves(`) — skip bare `function getReserves()` iface decls.
        spot_match = re.search(
            r"(?<!function\s)(?:\.getVirtualPrice|\.get_virtual_price|\.getReserves|\.slot0|"
            r"(?<![.\w])getVirtualPrice|(?<![.\w])get_virtual_price|(?<![.\w])slot0)\s*\([^)]*\)"
            r"[^;]*;[\s\n]*[^;]*(?:collateral|borrow|liquidat|debt|ltv|healthFactor)\b",
            source_text,
            re.IGNORECASE,
        )
        if (
            spot_match
            and "observe" not in source_text
            and "latestRoundData" not in source_text
            and "nonReentrantView" not in source_text
            and "interface " not in source_text[max(0, spot_match.start() - 120): spot_match.start()]
        ):
            findings["has_spot_oracle_flaw"] = True
            snippet = StaticVulnerabilityAuditor._extract_snippet(source_text, spot_match.start())
            evidence_list.append({
                "type": "SPOT_ORACLE_MANIPULATION",
                "user_exploitable": True,
                "title": "Dependencia de Oráculo Spot / Read-Only Reentrancy en Préstamos",
                "severity": "HIGH",
                "exploiter": "Prestatario con Flash Loan",
                "victim": "Pool de Préstamos / Protocolo Lending",
                "payoff": "Extracción de fondos mediante préstamos sub-colateralizados a precios manipulados.",
                "snippet": snippet
            })

        # 14. Signature Replay / Nonce-less Verification
        sig_match = re.search(r"ecrecover\s*\([^)]*\)", source_text)
        looks_like_safe = any(h in source_text for h in SAFE_HINTS)
        if (
            sig_match
            and not looks_like_safe
            and "nonces[" not in source_text
            and "_useNonce" not in source_text
            and "usedSignatures" not in source_text
            and "function nonce(" not in source_text
        ):
            findings["has_signature_replay_flaw"] = True
            snippet = StaticVulnerabilityAuditor._extract_snippet(source_text, sig_match.start())
            evidence_list.append({
                "type": "SIGNATURE_REPLAY_FLAW",
                "user_exploitable": True,
                "title": "Verificación de Firma Criptográfica sin Control de Nonce (Replay Attack)",
                "severity": "HIGH",
                "exploiter": "Cualquier Observador de Mempool",
                "victim": "Firmante Legítimo",
                "payoff": "Re-ejecución arbitraria de autorizaciones de retiro o transferencias.",
                "snippet": snippet
            })

        # 15. tx.origin phishing: only when origin is used as *owner* auth.
        # `msg.sender == tx.origin` is an anti-contract (EOA-only) check, not a drain.
        txo_phish = re.search(
            r"tx\.origin\s*==\s*(?:owner\(\)|_owner)\b|"
            r"(?:owner\(\)|_owner)\s*==\s*tx\.origin",
            source_text,
        )
        if txo_phish:
            findings["has_tx_origin_auth"] = True
            snippet = StaticVulnerabilityAuditor._extract_snippet(source_text, txo_phish.start())
            evidence_list.append({
                "type": "TX_ORIGIN_AUTH",
                "user_exploitable": True,
                "title": "Autenticación vía tx.origin (phishing / spoofing de contrato)",
                "severity": "HIGH",
                "exploiter": "Contrato malicioso llamado por el owner/víctima",
                "victim": "Owner / usuario que firma la tx",
                "payoff": "Bypass de msg.sender y ejecución de funciones privilegiadas.",
                "snippet": snippet
            })

        # 16. Unprotected AMM router/pair setter
        setter_match = re.search(
            r"function\s+set(?:Router|Pair|AMM|AutomatedMarketMakerPair|UniswapPair)\s*\(",
            source_text,
        )
        if setter_match and StaticVulnerabilityAuditor._header_lacks_auth(source_text, setter_match):
            findings["has_unprotected_router_setter"] = True
            snippet = StaticVulnerabilityAuditor._extract_snippet(source_text, setter_match.start())
            evidence_list.append({
                "type": "UNPROTECTED_ROUTER_SETTER",
                "user_exploitable": True,
                "title": "setRouter/setPair sin control de acceso",
                "severity": "CRITICAL",
                "exploiter": "Cualquier Usuario Externo",
                "victim": "Auto-liq / tesorería del token",
                "payoff": "Redirigir swaps de comisiones a un par controlado por el atacante.",
                "snippet": snippet
            })

        # 17. permit() without nonce accounting (live implementation, not IERC20 iface)
        permit_match = re.search(
            r"^\s*function\s+permit\s*\([^;]{0,500}\)\s*(?:public|external)(?:\s+\w+)*\s*\{",
            source_text,
            re.MULTILINE,
        )
        has_nonce_acct = (
            "nonces[" in source_text
            or "permitNonces[" in source_text
            or "_useNonce" in source_text
            or "_nonces[" in source_text
            or "function nonces(" in source_text
        )
        if permit_match and not has_nonce_acct:
            findings["has_permit_no_nonce"] = True
            snippet = StaticVulnerabilityAuditor._extract_snippet(source_text, permit_match.start())
            evidence_list.append({
                "type": "PERMIT_NO_NONCE",
                "user_exploitable": True,
                "title": "EIP-2612 permit() sin incremento de nonce",
                "severity": "HIGH",
                "exploiter": "Observador de mempool",
                "victim": "Firmante de permit",
                "payoff": "Replay de aprobación y drenaje vía transferFrom.",
                "snippet": snippet
            })

        # 18. multicall that forwards the same msg.value inside a loop.
        # Bound the body to the next top-level `function` so we don't absorb
        # later helpers (e.g. tip() with call{value: msg.value}).
        mc_match = re.search(
            r"function\s+multicall\s*\([^)]*\)\s*(?:public|external|virtual)[^{]*\{"
            r"(.*?)(?=\n\s*function\s|\Z)",
            source_text,
            re.IGNORECASE | re.DOTALL,
        )
        if mc_match:
            body = mc_match.group(1)
            has_loop = re.search(r"\b(?:for|while)\s*\(", body) is not None
            reuses_value = re.search(
                r"\.(?:call|delegatecall)\s*\{[^}]*value\s*:\s*msg\.value",
                body,
                re.IGNORECASE,
            ) is not None
            if has_loop and reuses_value:
                findings["has_multicall_msgvalue"] = True
                snippet = StaticVulnerabilityAuditor._extract_snippet(
                    source_text, mc_match.start()
                )
                evidence_list.append({
                    "type": "MULTICALL_MSGVALUE_REUSE",
                    "user_exploitable": True,
                    "title": "multicall reusa msg.value en subcalls",
                    "severity": "HIGH",
                    "exploiter": "Cualquier Usuario Externo",
                    "victim": "Router / vault que interpreta msg.value por iteración",
                    "payoff": "Contabilizar el mismo ETH varias veces y extraer valor.",
                    "snippet": snippet,
                })

        # 19. Public swapBack / swapAndLiquify trigger
        pub_swap = re.search(
            r"function\s+(swapBack|swapAndLiquify)\s*\([^)]*\)\s*(?:public|external)",
            source_text,
        )
        if pub_swap and StaticVulnerabilityAuditor._header_lacks_auth(source_text, pub_swap):
            findings["has_public_swapback"] = True
            snippet = StaticVulnerabilityAuditor._extract_snippet(source_text, pub_swap.start())
            evidence_list.append({
                "type": "PUBLIC_SWAPBACK_TRIGGER",
                "user_exploitable": True,
                "title": "swapBack/swapAndLiquify público (trigger de sandwich)",
                "severity": "HIGH",
                "exploiter": "Cualquier Usuario / Bot MEV",
                "victim": "Tesorería de comisiones",
                "payoff": "Forzar la venta del tesoro contra un pool manipulado.",
                "snippet": snippet
            })

        # 20. Solana missing signer (only when Rust source is present)
        if "solana_program" in source_text or "anchor_lang" in source_text:
            if re.search(r"invoke\s*\(", source_text) and "is_signer" not in source_text:
                findings["has_unprotected_critical_function"] = True
                evidence_list.append({
                    "type": "BROKEN_ACCESS_CONTROL",
                    "user_exploitable": True,
                    "title": "Solana invoke() sin chequeo is_signer",
                    "severity": "HIGH",
                    "exploiter": "Cualquier cuenta que arme el instruction",
                    "victim": "Programa / vault SPL",
                    "payoff": "CPI con cuentas no firmadas.",
                    "snippet": source_text[:500],
                })

        return findings, evidence_list

    @staticmethod
    def _header_lacks_auth(source: str, match: re.Match) -> bool:
        tail = source[match.start(): match.start() + 450]
        header = tail.split("{", 1)[0]
        return AUTH_HINT.search(header) is None

    @staticmethod
    def _extract_snippet(source: str, index: int, context_lines: int = 6) -> str:
        lines = source[:index].split("\n")
        start_line_num = max(0, len(lines) - context_lines)
        all_lines = source.split("\n")
        end_line_num = min(len(all_lines), len(lines) + context_lines)
        return "\n".join(f"{i+1}: {all_lines[i]}" for i in range(start_line_num, end_line_num))

class TriageReportGenerator:
    """
    Generates structured Markdown triage documents for researcher manual verification.
    """

    @staticmethod
    def generate_triage_file(contract_data: Dict, user_exploits: List[Dict], output_dir: str = TRIAGE_DIR) -> str:
        os.makedirs(output_dir, exist_ok=True)
        addr = contract_data["address"].lower()
        chain = contract_data.get("chain", "base")
        name = contract_data.get("name", "Unknown")
        eth_bal = contract_data.get("eth_balance", 0.0)

        file_name = f"triage_{chain}_{addr}.md"
        full_path = os.path.join(output_dir, file_name)

        md = []
        md.append("# 🛡️ Triage Card: User-Exploitable Vulnerability Assessment\n")
        md.append(f"**Contract Name:** `{name}`  \n")
        md.append(
            f"**Address:** [`{addr}`]({explorer_address_url(chain, addr)})  \n"
        )
        md.append(f"**Blockchain:** `{chain.upper()}` | **Compiler:** `{contract_data.get('compiler', 'Unknown')}`  \n")
        md.append(f"**Live On-Chain Balance:** `{eth_bal:.4f} ETH`  \n")
        md.append(f"**Dynamic Verification Status:** `{contract_data.get('dynamic_status', 'CONFIRMED')}`  \n")
        md.append(f"**Category:** `{contract_data.get('category', 'CUSTOM_LOGIC')}`  \n")
        md.append(f"**Detected Timestamp:** `{datetime.now(timezone.utc).isoformat()}`  \n\n")

        profit = contract_data.get("profit")
        if not profit and user_exploits:
            profit = user_exploits[0].get("profit")
        if profit:
            gate = profit.get("gate") or ("PASS" if profit.get("actionable") else "FAIL")
            md.append("## Profit Gate\n")
            md.append(
                f"**Expected Profit (ETH):** `{float(profit.get('expected_profit_eth') or 0):.4f}`  \n"
            )
            md.append(f"**Pool ETH:** `{float(profit.get('pool_eth') or 0):.4f}`  \n")
            md.append(f"**Gate:** `{gate}`  \n")
            md.append(f"**Method:** `{profit.get('method', 'none')}`  \n\n")

        md.append("## 1. Executive Vulnerability Summary\n")
        md.append("Esta tarjeta fue generada porque la vulnerabilidad fue detectada estáticamente y **el stage dinámico no la filtró** (swapBack reachable, pool oficial delgado).\n\n")

        for idx, exp in enumerate(user_exploits, 1):
            evidence = exp.get("onchain_evidence", "Confirmado on-chain")
            md.append(f"### {idx}. [{exp['severity']}] {exp['title']}\n")
            md.append(f"* **Evidencia On-Chain:** `{evidence}`\n")
            md.append(f"* **Perfil del Atacante:** {exp['exploiter']}\n")
            md.append(f"* **Víctima Afectada:** {exp['victim']}\n")
            md.append(f"* **Beneficio / Payoff Esperado:** {exp['payoff']}\n\n")
            md.append(f"#### Fragmento de Código Relevante:\n```solidity\n{exp['snippet']}\n```\n")

        md.append("\n---\n")
        md.append("## 2. Checklist de Verificación y Triage Manual (Researcher Evaluation)\n")
        md.append("- [ ] **Paso 1: Verificación de Parámetros On-Chain** (Fondos en balance, pair con liquidez)\n")
        md.append("- [ ] **Paso 2: Confirmación de Lógica y Parámetros Vulnerables**\n")
        md.append("### Veredicto del Triage:\n")
        md.append("- **Resultado:** `[ ] True Positive (TP)` | `[ ] False Positive (FP)`\n")
        md.append("- **Confianza:** `[ ] Alta` | `[ ] Media` | `[ ] Baja`\n")

        content = "\n".join(md)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)

        return full_path

class ChainScannerWorker:
    """
    Worker that independently monitors a specific chain with Two-Stage validation.
    """

    def __init__(self, chain: str, output_dir: str = "./contracts"):
        self.chain = chain.lower().strip()
        self.output_dir = output_dir
        self.db = TokenScannerDB()
        self.analyzer = ContractAnalyzer()
        # Addresses that failed mid-scan due to DB lock — retried next cycle.
        self.pending_retry: deque = deque(maxlen=200)
        self._pending_seen: Set[str] = set()

        if self.chain == "solana":
            self.solana_extractor = SolanaExtractor()
            self.evm_extractor = None
        else:
            self.evm_extractor = EVMExtractor(chain=self.chain)
            self.solana_extractor = None

    def _enqueue_retry(self, address: str) -> None:
        addr = address.lower().strip()
        if addr and addr not in self._pending_seen:
            self.pending_retry.append(addr)
            self._pending_seen.add(addr)

    def fetch_recent_contracts(self, limit: int = 25) -> List[str]:
        if self.chain == "solana":
            recent_addrs = set()
            for prog_id in ["6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P", "675kPX9Mtx55nit54vq3eThNuH47TXJkzF6fU83osv24"]:
                sigs = self.solana_extractor.get_wallet_signatures(prog_id, limit=limit)
                for sig in sigs[:5]:
                    recent_addrs.add(sig)
            return list(recent_addrs)

        bs_v2 = self.evm_extractor.config.get("blockscout_v2")
        if not bs_v2:
            return []

        url = f"{bs_v2}/smart-contracts"
        try:
            resp = self.evm_extractor.session.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                items = data.get("items", [])
                addresses = []
                for item in items[:limit]:
                    addr = item.get("address", {}).get("hash")
                    if addr:
                        addresses.append(addr.lower())
                return addresses
        except Exception:
            pass
        return []

    def scan_contract(self, address: str) -> Optional[Dict]:
        address = address.lower().strip()
        if self.db.is_scanned(address):
            return None

        console.print(f"[bold cyan]🔍 [{self.chain.upper()}][/] Scanning: {address}")

        if self.chain == "solana":
            scan_result = {
                "address": address,
                "name": f"Solana_TX_{address[:8]}",
                "chain": "solana",
                "compiler": "BPF/LLVM",
                "category": "SOLANA_PROGRAM",
                "verified": True,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "is_user_exploitable": False,
                "onchain_verified": False,
                "dynamic_status": "SOLANA_LOG",
                "eth_balance": 0.0,
                "has_zero_slippage": False,
                "has_dynamic_taxes": False,
                "has_conditional_honeypot": False,
                "has_unlimited_mint": False,
                "has_unprotected_critical_function": False,
                "has_vault_inflation": False,
                "has_fee_on_transfer_flaw": False,
                "has_flash_staking_flaw": False,
                "has_arbitrary_call": False,
                "has_reflection_ratio_flaw": False,
                "has_reentrancy_flaw": False,
                "has_unprotected_initializer": False,
                "has_spot_oracle_flaw": False,
                "has_signature_replay_flaw": False,
                "slither_high": 0,
                "slither_medium": 0,
                "slither_low": 0,
                "triage_file_path": None,
                "raw_metadata": {"signature": address}
            }
            self.db.save_scan(scan_result)
            return scan_result

        # EVM Chain Execution
        verified, path, meta = self.evm_extractor.save_contract(address, self.output_dir)

        scan_result = {
            "address": address,
            "name": meta.get("contract_name", "Unknown"),
            "chain": self.chain,
            "compiler": meta.get("compiler_version", "Unknown"),
            "category": meta.get("category", "CUSTOM_LOGIC"),
            "verified": verified,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "is_user_exploitable": False,
            "onchain_verified": False,
            "dynamic_status": "UNVERIFIED",
            "eth_balance": 0.0,
            "has_zero_slippage": False,
            "has_dynamic_taxes": False,
            "has_conditional_honeypot": False,
            "has_unlimited_mint": False,
            "has_unprotected_critical_function": False,
            "has_vault_inflation": False,
            "has_fee_on_transfer_flaw": False,
            "has_flash_staking_flaw": False,
            "has_arbitrary_call": False,
            "has_reflection_ratio_flaw": False,
            "has_reentrancy_flaw": False,
            "has_unprotected_initializer": False,
            "has_spot_oracle_flaw": False,
            "has_signature_replay_flaw": False,
            "has_tx_origin_auth": False,
            "has_unprotected_router_setter": False,
            "has_permit_no_nonce": False,
            "has_multicall_msgvalue": False,
            "has_public_swapback": False,
            "slither_high": 0,
            "slither_medium": 0,
            "slither_low": 0,
            "triage_file_path": None,
            "raw_metadata": meta
        }

        if verified:
            src_dir = os.path.join(path, "src")
            all_source = load_saved_source(self.chain, address)

            # Stage 1: Static AST Audit
            findings, evidence_list = StaticVulnerabilityAuditor.audit_source(all_source)
            scan_result.update(findings)

            # Filter for potential user-exploitable vulnerabilities
            user_exploits = [e for e in evidence_list if e.get("user_exploitable", False)]

            # Stage 2: Deep Automated Dynamic On-Chain Verification
            if user_exploits:
                is_active_onchain, dynamic_status, eth_balance, confirmed_exploits, profit_payload = OnChainStateVerifier.verify_onchain_liveness(
                    address, self.chain, user_exploits, all_source
                )
                scan_result["eth_balance"] = eth_balance
                scan_result["onchain_verified"] = is_active_onchain
                scan_result["dynamic_status"] = dynamic_status
                if profit_payload:
                    scan_result["profit"] = profit_payload
                    scan_result["expected_profit_eth"] = profit_payload.get("expected_profit_eth")

                if is_active_onchain and confirmed_exploits:
                    fork_res = run_fork_profit_test(address, self.chain)
                    if not should_emit_triage(
                        is_active=True,
                        confirmed=confirmed_exploits,
                        fork_result=fork_res,
                    ):
                        scan_result["dynamic_status"] = (
                            f"{dynamic_status} | FORK_GATE_{fork_res.reason.upper()}"
                        )
                        console.print(
                            f"[dim yellow]  ↳ Fork gate blocked triage ({fork_res.reason}).[/]"
                        )
                    else:
                        scan_result["is_user_exploitable"] = True
                        triage_path = TriageReportGenerator.generate_triage_file(
                            scan_result, confirmed_exploits
                        )
                        scan_result["triage_file_path"] = triage_path
                        AlertDispatcher.emit_triage_alert(
                            scan_result, confirmed_exploits, triage_path
                        )
                else:
                    console.print(f"[dim yellow]  ↳ On-Chain Status: {dynamic_status} (Balance: {eth_balance:.4f} ETH). Filtered from Triage Queue.[/]")

            # Slither analysis
            try:
                report = self.analyzer.run_slither(src_dir if os.path.exists(src_dir) else path, output_report_dir=path)
                sum_rep = report.get("findings_summary", {})
                scan_result["slither_high"] = sum_rep.get("High", 0)
                scan_result["slither_medium"] = sum_rep.get("Medium", 0)
                scan_result["slither_low"] = sum_rep.get("Low", 0)
            except Exception:
                pass

        self.db.save_scan(scan_result)
        return scan_result

    def poll_cycle(self) -> int:
        # Drain prior DB-lock failures first so they are not lost.
        retry_batch: List[str] = []
        while self.pending_retry:
            addr = self.pending_retry.popleft()
            self._pending_seen.discard(addr)
            retry_batch.append(addr)
        if retry_batch:
            console.print(
                f"[dim yellow][{self.chain.upper()}] Retrying {len(retry_batch)} "
                f"DB-deferred address(es)[/]"
            )

        fresh = self.fetch_recent_contracts(limit=25)
        # Preserve retry order, then new explorer hits (deduped).
        seen: Set[str] = set()
        contracts: List[str] = []
        for addr in retry_batch + fresh:
            a = addr.lower().strip()
            if a and a not in seen:
                seen.add(a)
                contracts.append(a)

        new_count = 0
        for addr in contracts:
            try:
                if not self.db.is_scanned(addr):
                    self.scan_contract(addr)
                    new_count += 1
                    time.sleep(1)
            except sqlite3.OperationalError as e:
                if _is_db_locked(e):
                    self._enqueue_retry(addr)
                    console.print(
                        f"[dim red][{self.chain.upper()}] DB locked — queued {addr} for retry "
                        f"(pending={len(self.pending_retry)})[/]"
                    )
                else:
                    raise
        return new_count

class MultiChainScannerDaemon:
    """
    Concurrent multi-chain daemon coordinator with Deep Dynamic validation.
    """

    def __init__(self, chains: List[str], interval_seconds: int = 60):
        self.chains = [c.strip().lower() for c in chains if c.strip()]
        self.interval_seconds = interval_seconds
        self.workers = [ChainScannerWorker(chain=c) for c in self.chains]
        self.running = False

    def _worker_loop(self, worker: ChainScannerWorker):
        while self.running:
            try:
                new_cnt = worker.poll_cycle()
                if new_cnt > 0:
                    console.print(f"[dim][{worker.chain.upper()}] Processed {new_cnt} contracts.[/]")
            except sqlite3.OperationalError as e:
                if _is_db_locked(e):
                    console.print(
                        f"[dim red][{worker.chain.upper()}] Worker DB locked — will retry next cycle "
                        f"(pending={len(worker.pending_retry)})[/]"
                    )
                else:
                    console.print(f"[dim red][{worker.chain.upper()}] Worker error: {e}[/]")
            except Exception as e:
                console.print(f"[dim red][{worker.chain.upper()}] Worker error: {e}[/]")
            time.sleep(self.interval_seconds)

    def start(self):
        self.running = True
        console.print(Panel(
            f"[bold green]🚀 Multi-Chain Deep Invariant Security Daemon Active[/]\n\n"
            f"[bold yellow]Active Chains ({len(self.chains)}):[/] {', '.join([c.upper() for c in self.chains])}\n"
            f"[bold yellow]Stage 1:[/] Static AST / Regex Auditing (attacker + owner classes)\n"
            f"[bold yellow]Stage 2:[/] Automated Dynamic Verification (Storage Slots, Seeded Ratios, Balances)\n"
            f"[bold yellow]Triage Directory:[/] {os.path.abspath(TRIAGE_DIR)}\n"
            f"[bold yellow]Real-Time Alert Log:[/] {os.path.abspath(ALERTS_LOG)}\n\n"
            f"[bold cyan]Press Ctrl+C to stop.[/]",
            title="Multi-Chain Security & Invariant Verification Daemon",
            border_style="green bold"
        ))

        if not self.workers:
            console.print("[red]No chains configured (use --chains).[/]")
            self.running = False
            return

        with ThreadPoolExecutor(max_workers=len(self.workers)) as executor:
            for worker in self.workers:
                executor.submit(self._worker_loop, worker)

            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                console.print("\n[yellow]Stopping multi-chain daemon workers...[/]")
                self.running = False

def display_db_stats(as_json: bool = False):
    if not os.path.exists(DB_PATH):
        if as_json:
            print(json.dumps({"error": "No database found", "total_scanned": 0}))
        else:
            console.print("[yellow]No database found yet.[/]")
        return

    db_instance = TokenScannerDB(DB_PATH)

    with db_lock:
        with db_instance.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM tokens")
            total = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM tokens WHERE verified = 1")
            verified_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM tokens WHERE is_user_exploitable = 1")
            user_exploitable_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM tokens WHERE is_user_exploitable = 1 AND onchain_verified = 1")
            active_triage_count = cursor.fetchone()[0]

            cursor.execute("""
            SELECT COUNT(*) FROM tokens
            WHERE verified = 1 AND is_user_exploitable = 0 AND eth_balance = 0.0 AND (
                has_unprotected_initializer = 1 OR
                has_unprotected_critical_function = 1 OR
                has_reentrancy_flaw = 1 OR
                has_signature_replay_flaw = 1 OR
                has_vault_inflation = 1 OR
                has_flash_staking_flaw = 1 OR
                has_arbitrary_call = 1 OR
                has_fee_on_transfer_flaw = 1 OR
                has_spot_oracle_flaw = 1 OR
                has_tx_origin_auth = 1 OR
                has_unprotected_router_setter = 1 OR
                has_permit_no_nonce = 1 OR
                has_multicall_msgvalue = 1 OR
                has_public_swapback = 1
            )
            """)
            dormant_count = cursor.fetchone()[0]

            cursor.execute("""
            SELECT COUNT(*) FROM tokens
            WHERE dynamic_status LIKE '%MITIGATED%' OR dynamic_status LIKE '%PROTECTED%' OR dynamic_status LIKE '%SEALED%' OR dynamic_status LIKE '%ISOLATED%' OR dynamic_status LIKE '%FACET%'
            """)
            mitigated_count = cursor.fetchone()[0]

            # Metrics counts
            cursor.execute("SELECT COUNT(*) FROM tokens WHERE has_zero_slippage = 1")
            slippage_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM tokens WHERE has_unprotected_critical_function = 1")
            broken_access_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM tokens WHERE has_vault_inflation = 1")
            vault_inflation_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM tokens WHERE has_fee_on_transfer_flaw = 1")
            fot_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM tokens WHERE has_flash_staking_flaw = 1")
            flash_staking_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM tokens WHERE has_arbitrary_call = 1")
            arb_call_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM tokens WHERE has_reflection_ratio_flaw = 1")
            reflection_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM tokens WHERE has_reentrancy_flaw = 1")
            reentrancy_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM tokens WHERE has_unprotected_initializer = 1")
            initializer_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM tokens WHERE has_spot_oracle_flaw = 1")
            spot_oracle_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM tokens WHERE has_signature_replay_flaw = 1")
            sig_replay_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM tokens WHERE has_tx_origin_auth = 1")
            tx_origin_count = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM tokens WHERE has_unprotected_router_setter = 1")
            router_setter_count = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM tokens WHERE has_permit_no_nonce = 1")
            permit_count = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM tokens WHERE has_multicall_msgvalue = 1")
            multicall_count = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM tokens WHERE has_public_swapback = 1")
            public_swapback_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM tokens WHERE has_conditional_honeypot = 1")
            honeypot_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM tokens WHERE has_dynamic_taxes = 1")
            tax_count = cursor.fetchone()[0]

            # Chain breakdown
            cursor.execute("SELECT chain, COUNT(*) FROM tokens GROUP BY chain")
            chain_counts = dict(cursor.fetchall())

    tot_calc = max(1, verified_count)

    pending_cards = []
    if os.path.exists(TRIAGE_DIR):
        pending_cards = [os.path.abspath(os.path.join(TRIAGE_DIR, f)) for f in os.listdir(TRIAGE_DIR) if f.endswith(".md")]

    if as_json:
        stats_payload = {
            "total_scanned": total,
            "verified_contracts": verified_count,
            "chains_breakdown": chain_counts,
            "triage_lifecycle": {
                "active_triage_queue_count": len(pending_cards),
                "dormant_monitored_count": dormant_count,
                "mitigated_false_positives_count": mitigated_count,
                "owner_centralization_risks_count": tax_count + honeypot_count
            },
            "user_exploitable_count": user_exploitable_count,
            "onchain_confirmed_count": active_triage_count,
            "user_exploitable_percentage": round((user_exploitable_count / tot_calc) * 100, 2),
            "metrics": {
                "zero_slippage_liquidation": {"count": slippage_count, "prevalence_percent": round((slippage_count / tot_calc) * 100, 2)},
                "broken_access_control": {"count": broken_access_count, "prevalence_percent": round((broken_access_count / tot_calc) * 100, 2)},
                "erc4626_vault_inflation": {"count": vault_inflation_count, "prevalence_percent": round((vault_inflation_count / tot_calc) * 100, 2)},
                "fee_on_transfer_flaw": {"count": fot_count, "prevalence_percent": round((fot_count / tot_calc) * 100, 2)},
                "flash_staking_flaw": {"count": flash_staking_count, "prevalence_percent": round((flash_staking_count / tot_calc) * 100, 2)},
                "arbitrary_external_call": {"count": arb_call_count, "prevalence_percent": round((arb_call_count / tot_calc) * 100, 2)},
                "reflection_ratio_flaw": {"count": reflection_count, "prevalence_percent": round((reflection_count / tot_calc) * 100, 2)},
                "checks_effects_reentrancy": {"count": reentrancy_count, "prevalence_percent": round((reentrancy_count / tot_calc) * 100, 2)},
                "unprotected_proxy_initializer": {"count": initializer_count, "prevalence_percent": round((initializer_count / tot_calc) * 100, 2)},
                "spot_oracle_manipulation": {"count": spot_oracle_count, "prevalence_percent": round((spot_oracle_count / tot_calc) * 100, 2)},
                "signature_replay_flaw": {"count": sig_replay_count, "prevalence_percent": round((sig_replay_count / tot_calc) * 100, 2)},
                "tx_origin_auth": {"count": tx_origin_count, "prevalence_percent": round((tx_origin_count / tot_calc) * 100, 2)},
                "unprotected_router_setter": {"count": router_setter_count, "prevalence_percent": round((router_setter_count / tot_calc) * 100, 2)},
                "permit_no_nonce": {"count": permit_count, "prevalence_percent": round((permit_count / tot_calc) * 100, 2)},
                "multicall_msgvalue_reuse": {"count": multicall_count, "prevalence_percent": round((multicall_count / tot_calc) * 100, 2)},
                "public_swapback_trigger": {"count": public_swapback_count, "prevalence_percent": round((public_swapback_count / tot_calc) * 100, 2)},
                "conditional_honeypot": {"count": honeypot_count, "prevalence_percent": round((honeypot_count / tot_calc) * 100, 2)},
                "dynamic_taxes": {"count": tax_count, "prevalence_percent": round((tax_count / tot_calc) * 100, 2)}
            },
            "pending_triage_cards_count": len(pending_cards),
            "triage_queue_files": pending_cards
        }
        print(json.dumps(stats_payload, indent=2))
        return

    table = Table(title="Multi-Chain Security Dataset & Empirical Triage Summary")
    table.add_column("Triage Category / Metric", style="yellow")
    table.add_column("Count", style="red bold", justify="right")
    table.add_column("Prevalence (%)", style="cyan", justify="right")

    table.add_row("Total Scanned Contracts (All Chains)", str(total), "100.0%")
    table.add_row("Verified Source Code Contracts", str(verified_count), f"{(verified_count/max(1,total))*100:.1f}%")
    table.add_row("🚨 ACTIVE TRIAGE QUEUE (Actionable)", str(len(pending_cards)), f"{(len(pending_cards)/tot_calc)*100:.1f}%")
    table.add_row("💤 DORMANT VULNERABILITIES (Monitored 0 ETH)", str(dormant_count), f"{(dormant_count/tot_calc)*100:.1f}%")
    table.add_row("🛡️ MITIGATED / PROTECTED (Filtered FPs)", str(mitigated_count), f"{(mitigated_count/tot_calc)*100:.1f}%")
    table.add_row("👑 OWNER-CENTRALIZATION (Taxes/Honeypots)", str(tax_count + honeypot_count), f"{((tax_count+honeypot_count)/tot_calc)*100:.1f}%")
    table.add_row("• Checks-Effects Reentrancy (ETH Drain)", str(reentrancy_count), f"{(reentrancy_count/tot_calc)*100:.1f}%")
    table.add_row("• Unprotected Proxy Initializer Hijack", str(initializer_count), f"{(initializer_count/tot_calc)*100:.1f}%")
    table.add_row("• Spot AMM Oracle Dependence", str(spot_oracle_count), f"{(spot_oracle_count/tot_calc)*100:.1f}%")
    table.add_row("• Signature Replay / Nonce-less Verification", str(sig_replay_count), f"{(sig_replay_count/tot_calc)*100:.1f}%")
    table.add_row("• tx.origin Authentication", str(tx_origin_count), f"{(tx_origin_count/tot_calc)*100:.1f}%")
    table.add_row("• Unprotected setRouter/setPair", str(router_setter_count), f"{(router_setter_count/tot_calc)*100:.1f}%")
    table.add_row("• permit() without nonce", str(permit_count), f"{(permit_count/tot_calc)*100:.1f}%")
    table.add_row("• multicall msg.value reuse", str(multicall_count), f"{(multicall_count/tot_calc)*100:.1f}%")
    table.add_row("• Public swapBack trigger", str(public_swapback_count), f"{(public_swapback_count/tot_calc)*100:.1f}%")
    table.add_row("• Broken Access Control on Financial Funcs", str(broken_access_count), f"{(broken_access_count/tot_calc)*100:.1f}%")
    table.add_row("• ERC-4626 Vault Inflation Attack", str(vault_inflation_count), f"{(vault_inflation_count/tot_calc)*100:.1f}%")
    table.add_row("• Fee-on-Transfer Invariant Flaw", str(fot_count), f"{(fot_count/tot_calc)*100:.1f}%")
    table.add_row("• Flash-Staking Instant Reward Drain", str(flash_staking_count), f"{(flash_staking_count/tot_calc)*100:.1f}%")
    table.add_row("• Unconstrained Arbitrary Call (`.call()`)", str(arb_call_count), f"{(arb_call_count/tot_calc)*100:.1f}%")
    table.add_row("• Reflection / Rebase Ratio Flaw", str(reflection_count), f"{(reflection_count/tot_calc)*100:.1f}%")
    table.add_row("• Conditional Honeypot / Whitelists (Owner)", str(honeypot_count), f"{(honeypot_count/tot_calc)*100:.1f}%")
    table.add_row("• Dynamic Fee / Tax Manipulations (Owner)", str(tax_count), f"{(tax_count/tot_calc)*100:.1f}%")

    console.print(table)

    if chain_counts:
        ch_table = Table(title="Scanned Contracts by Blockchain")
        ch_table.add_column("Blockchain", style="green bold")
        ch_table.add_column("Contracts", style="white", justify="right")
        for ch, cnt in chain_counts.items():
            ch_table.add_row(ch.upper(), str(cnt))
        console.print(ch_table)

    if pending_cards:
        console.print(f"\n[bold magenta]📁 Pending Triage Cards for Researcher Review ({len(pending_cards)}):[/]")
        for c in pending_cards:
            console.print(f"  • [cyan]{c}[/]")

def main():
    parser = argparse.ArgumentParser(description="Multi-Chain Token Security Scanner with Deep Dynamic On-Chain Verification")
    parser.add_argument("--daemon", action="store_true", help="Run in continuous background multi-chain polling mode")
    parser.add_argument("--interval", type=int, default=60, help="Polling interval in seconds per chain (default: 60)")
    parser.add_argument("--chains", default="base,arbitrum,ethereum,solana", help="Comma-separated chains to scan (default: base,arbitrum,ethereum,solana)")
    parser.add_argument("--once", action="store_true", help="Run a single scan cycle across selected chains and exit")
    parser.add_argument("--scan-address", help="Directly scan a specific contract address")
    parser.add_argument("--chain", default="base", help="Target chain for --scan-address (default: base)")
    parser.add_argument("--stats", action="store_true", help="Display aggregated statistical summary and list triage queue")
    parser.add_argument("--json", action="store_true", help="Output stats and findings in machine-readable JSON format")

    args = parser.parse_args()

    if args.stats:
        display_db_stats(as_json=args.json)
        return

    if args.scan_address:
        worker = ChainScannerWorker(chain=args.chain)
        worker.scan_contract(args.scan_address)
        display_db_stats(as_json=args.json)
        return

    chain_list = [c.strip() for c in args.chains.split(",") if c.strip()]

    if args.once:
        if not args.json:
            console.print(f"[cyan]Running single Deep Dynamic verification cycle across: {', '.join(chain_list)}...[/]")
        for ch in chain_list:
            worker = ChainScannerWorker(chain=ch)
            worker.poll_cycle()
        display_db_stats(as_json=args.json)
    elif args.daemon:
        multi_daemon = MultiChainScannerDaemon(chains=chain_list, interval_seconds=args.interval)
        multi_daemon.start()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
