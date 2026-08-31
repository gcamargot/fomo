import json
import os
import subprocess
import requests
from typing import Dict, List, Optional, Set, Tuple

SOLANA_RPC_DEFAULT = "https://api.mainnet-beta.solana.com"

# Known Solana Core / Protocol Programs mapping
KNOWN_PROGRAMS = {
    "11111111111111111111111111111111": "System Program",
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA": "SPL Token Program",
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb": "Token-2022 Program",
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL": "Associated Token Account Program",
    "675kPX9Mtx55nit54vq3eThNuH47TXJkzF6fU83osv24": "Raydium Liquidity Pool V4",
    "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK": "Raydium CLMM",
    "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C": "Raydium CPMM",
    "JUP6LkbZbjS1j56vu5ncg73o7n84m5J96L4nCgS88f2": "Jupiter v6 Aggregator",
    "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc": "Orca Whirlpool",
    "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P": "Pump.fun Bonding Curve",
    "ComputeBudget111111111111111111111111111111": "Compute Budget Program",
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr": "Memo Program",
}

class SolanaExtractor:
    def __init__(self, rpc_url: str = SOLANA_RPC_DEFAULT):
        self.rpc_url = rpc_url
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

    def _rpc_call(self, method: str, params: list) -> Optional[dict]:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        }
        try:
            resp = self.session.post(self.rpc_url, json=payload, timeout=20)
            if resp.status_code == 200:
                data = resp.json()
                if "result" in data:
                    return data["result"]
                elif "error" in data:
                    print(f"[!] Solana RPC Error: {data['error']}")
        except Exception as e:
            print(f"[!] Solana RPC Request failed: {e}")
        return None

    def get_wallet_signatures(self, wallet_address: str, limit: int = 50) -> List[str]:
        """Fetches recent transaction signatures for an address."""
        result = self._rpc_call("getSignaturesForAddress", [wallet_address, {"limit": limit}])
        if result and isinstance(result, list):
            return [tx["signature"] for tx in result if "signature" in tx]
        return []

    def inspect_wallet_interactions(self, wallet_address: str, tx_limit: int = 30) -> Dict:
        """
        Parses recent transactions to find all programs and tokens the wallet interacted with.
        """
        wallet_address = wallet_address.strip()
        signatures = self.get_wallet_signatures(wallet_address, limit=tx_limit)
        
        programs_found: Set[str] = set()
        token_mints: Set[str] = set()
        tx_summaries: List[Dict] = []

        for sig in signatures:
            tx_data = self._rpc_call("getTransaction", [
                sig,
                {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}
            ])
            if not tx_data:
                continue

            meta = tx_data.get("meta", {})
            transaction = tx_data.get("transaction", {})
            message = transaction.get("message", {})
            
            # Extract instructions
            instructions = message.get("instructions", [])
            inner_instructions = meta.get("innerInstructions", [])

            for ix in instructions:
                prog_id = ix.get("programId")
                if prog_id:
                    programs_found.add(prog_id)

            for inner in inner_instructions:
                for ix in inner.get("instructions", []):
                    prog_id = ix.get("programId")
                    if prog_id:
                        programs_found.add(prog_id)

            # Extract Token Balances (Mints)
            pre_tokens = meta.get("preTokenBalances", [])
            post_tokens = meta.get("postTokenBalances", [])
            for t in pre_tokens + post_tokens:
                mint = t.get("mint")
                if mint:
                    token_mints.add(mint)

            tx_summaries.append({
                "signature": sig,
                "slot": tx_data.get("slot"),
                "blockTime": tx_data.get("blockTime"),
                "fee": meta.get("fee"),
                "err": meta.get("err"),
            })

        return {
            "wallet": wallet_address,
            "programs": list(programs_found),
            "token_mints": list(token_mints),
            "transactions_analyzed": len(tx_summaries),
            "recent_txs": tx_summaries,
        }

    def dump_program_binary(self, program_id: str, output_base_dir: str) -> Tuple[bool, str, Dict]:
        """
        Dumps the executable ELF binary (.so) for a Solana on-chain program using solana CLI or RPC.
        """
        program_id = program_id.strip()
        target_dir = os.path.join(output_base_dir, "solana", program_id)
        os.makedirs(target_dir, exist_ok=True)
        
        output_so_path = os.path.join(target_dir, f"{program_id}.so")
        metadata = {
            "program_id": program_id,
            "chain": "solana",
            "known_name": KNOWN_PROGRAMS.get(program_id, "Custom / Third-party Program"),
            "dumped_binary": False,
            "binary_path": None,
        }

        # Try using solana CLI first if available
        try:
            cmd = ["solana", "program", "dump", program_id, output_so_path, "--url", self.rpc_url]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if res.returncode == 0 and os.path.exists(output_so_path):
                metadata["dumped_binary"] = True
                metadata["binary_path"] = output_so_path
                with open(os.path.join(target_dir, "metadata.json"), "w") as f:
                    json.dump(metadata, f, indent=2)
                return True, target_dir, metadata
        except Exception:
            pass

        # Fallback to getAccountInfo via RPC
        acc_info = self._rpc_call("getAccountInfo", [program_id, {"encoding": "base64"}])
        if acc_info and acc_info.get("value"):
            val = acc_info["value"]
            metadata["executable"] = val.get("executable", False)
            metadata["owner"] = val.get("owner", "")
            metadata["lamports"] = val.get("lamports", 0)

        with open(os.path.join(target_dir, "metadata.json"), "w") as f:
            json.dump(metadata, f, indent=2)

        return False, target_dir, metadata
