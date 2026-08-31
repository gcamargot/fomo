import json
import os
import re
import time
import requests
from typing import Dict, List, Optional, Tuple, Set

EXPLORER_CONFIGS = {
    "base": {
        "name": "Base Mainnet",
        "chain_id": 8453,
        "blockscout_v2": "https://base.blockscout.com/api/v2",
        "explorer_api": "https://api.basescan.org/api",
        "env_key": "BASESCAN_API_KEY",
        "rpc": "https://mainnet.base.org",
    },
    "ethereum": {
        "name": "Ethereum Mainnet",
        "chain_id": 1,
        "blockscout_v2": "https://eth.blockscout.com/api/v2",
        "explorer_api": "https://api.etherscan.io/api",
        "env_key": "ETHERSCAN_API_KEY",
        "rpc": "https://cloudflare-eth.com",
    },
    "arbitrum": {
        "name": "Arbitrum One",
        "chain_id": 42161,
        "blockscout_v2": "https://arbitrum.blockscout.com/api/v2",
        "explorer_api": "https://api.arbiscan.io/api",
        "env_key": "ARBISCAN_API_KEY",
        "rpc": "https://arb1.arbitrum.io/rpc",
    },
    "optimism": {
        "name": "OP Mainnet",
        "chain_id": 10,
        "blockscout_v2": "https://optimism.blockscout.com/api/v2",
        "explorer_api": "https://api-optimistic.etherscan.io/api",
        "env_key": "OPTIMISTIC_API_KEY",
        "rpc": "https://mainnet.optimism.io",
    },
    "polygon": {
        "name": "Polygon PoS",
        "chain_id": 137,
        "blockscout_v2": "https://polygon.blockscout.com/api/v2",
        "explorer_api": "https://api.polygonscan.com/api",
        "env_key": "POLYGONSCAN_API_KEY",
        "rpc": "https://polygon-rpc.com",
    },
    "bsc": {
        "name": "BNB Smart Chain",
        "chain_id": 56,
        "blockscout_v2": "https://bsc.blockscout.com/api/v2",
        "explorer_api": "https://api.bscscan.com/api",
        "env_key": "BSCSCAN_API_KEY",
        "rpc": "https://binance.llamarpc.com",
    },
}

class EVMExtractor:
    def __init__(self, chain: str = "base", api_key: Optional[str] = None):
        chain_lower = chain.lower()
        if chain_lower not in EXPLORER_CONFIGS:
            raise ValueError(f"Unsupported chain: {chain}. Supported: {list(EXPLORER_CONFIGS.keys())}")
        
        self.chain = chain_lower
        self.config = EXPLORER_CONFIGS[chain_lower]
        self.api_key = api_key or os.getenv(self.config["env_key"], "")
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        })

    def get_wallet_contract_interactions(self, wallet_address: str, max_txs: int = 100) -> Set[str]:
        """
        Fetches transactions and token transfers to identify smart contracts.
        Uses Blockscout v2 REST API (no key needed) or explorer API fallback.
        """
        wallet_address = wallet_address.strip()
        contracts_found: Set[str] = set()

        # 1. Try Blockscout v2 API
        bs_v2 = self.config.get("blockscout_v2")
        if bs_v2:
            try:
                tx_url = f"{bs_v2}/addresses/{wallet_address}/transactions"
                resp = self.session.get(tx_url, timeout=15)
                if resp.status_code == 200:
                    data = resp.json()
                    items = data.get("items", [])
                    for item in items:
                        to_item = item.get("to")
                        if to_item and isinstance(to_item, dict):
                            if to_item.get("is_contract"):
                                contracts_found.add(to_item.get("hash", "").lower())
                            elif to_item.get("hash"):
                                contracts_found.add(to_item.get("hash", "").lower())
                        
                        created_contract = item.get("created_contract")
                        if created_contract and isinstance(created_contract, dict):
                            contracts_found.add(created_contract.get("hash", "").lower())

                # Token transfers
                token_tx_url = f"{bs_v2}/addresses/{wallet_address}/token-transfers"
                resp = self.session.get(token_tx_url, timeout=15)
                if resp.status_code == 200:
                    data = resp.json()
                    items = data.get("items", [])
                    for item in items:
                        token = item.get("token")
                        if token and isinstance(token, dict) and token.get("address"):
                            contracts_found.add(token.get("address", "").lower())
            except Exception:
                pass

        # 2. Try Explorer API if API key is present and contracts not found
        if not contracts_found and self.api_key:
            try:
                params = {
                    "module": "account",
                    "action": "txlist",
                    "address": wallet_address,
                    "startblock": 0,
                    "endblock": 99999999,
                    "page": 1,
                    "offset": max_txs,
                    "sort": "desc",
                    "apikey": self.api_key
                }
                resp = self.session.get(self.config["explorer_api"], params=params, timeout=15)
                data = resp.json()
                if data.get("status") == "1" and isinstance(data.get("result"), list):
                    for tx in data["result"]:
                        to_addr = tx.get("to")
                        contract_addr = tx.get("contractAddress")
                        if contract_addr and contract_addr != "0x":
                            contracts_found.add(contract_addr.lower())
                        elif to_addr and to_addr != "0x":
                            contracts_found.add(to_addr.lower())
            except Exception:
                pass

        contracts_found.discard(wallet_address.lower())
        contracts_found.discard("")
        return contracts_found

    def get_runtime_bytecode(self, address: str) -> Optional[str]:
        """Fetches runtime bytecode via RPC."""
        try:
            payload = {
                "jsonrpc": "2.0",
                "method": "eth_getCode",
                "params": [address, "latest"],
                "id": 1
            }
            resp = self.session.post(self.config["rpc"], json=payload, timeout=10)
            res = resp.json().get("result")
            if res and res != "0x":
                return res
        except Exception:
            pass
        return None

    def fetch_verified_source(self, contract_address: str) -> Optional[Dict]:
        """
        Retrieves verified Solidity/Vyper source code and metadata.
        Uses Blockscout v2 REST API -> Explorer API -> Sourcify.
        """
        contract_address = contract_address.lower().strip()
        
        # 1. Blockscout v2 REST API (Reliable & No rate-limit/key)
        bs_v2 = self.config.get("blockscout_v2")
        if bs_v2:
            try:
                url = f"{bs_v2}/smart-contracts/{contract_address}"
                resp = self.session.get(url, timeout=15)
                if resp.status_code == 200:
                    data = resp.json()
                    is_verified = data.get("is_verified") or data.get("is_fully_verified") or data.get("is_partially_verified")
                    if is_verified or data.get("source_code") or data.get("additional_sources"):
                        sources = {}
                        main_file = data.get("file_path") or f"{data.get('name', 'Contract')}.sol"
                        if data.get("source_code"):
                            sources[main_file] = data.get("source_code")
                        
                        # Additional sources for multi-file contracts
                        for add_src in data.get("additional_sources", []):
                            file_path = add_src.get("file_path") or "Additional.sol"
                            sources[file_path] = add_src.get("source_code", "")

                        # Secondary sources
                        for sec_src in data.get("secondary_sources", []):
                            file_path = sec_src.get("file_path") or "Secondary.sol"
                            sources[file_path] = sec_src.get("source_code", "")

                        impl_addr = ""
                        if data.get("implementations") and len(data["implementations"]) > 0:
                            impl_addr = data["implementations"][0].get("address", "")
                        elif data.get("implementation_address"):
                            impl_addr = data.get("implementation_address", "")

                        return {
                            "ContractName": data.get("name") or "Contract",
                            "CompilerVersion": data.get("compiler_version", ""),
                            "OptimizationUsed": str(data.get("optimization_enabled", "")),
                            "Runs": str(data.get("optimization_runs", "")),
                            "EVMVersion": data.get("evm_version", ""),
                            "ABI": json.dumps(data.get("abi", [])) if data.get("abi") else "",
                            "IsProxy": data.get("is_proxy", False) or bool(impl_addr),
                            "Implementation": impl_addr,
                            "sources_dict": sources,
                            "raw_source": data.get("source_code", "")
                        }
            except Exception:
                pass

        # 2. Explorer API with API Key (Etherscan/Basescan)
        if self.api_key:
            try:
                params = {
                    "module": "contract",
                    "action": "getsourcecode",
                    "address": contract_address,
                    "apikey": self.api_key
                }
                resp = self.session.get(self.config["explorer_api"], params=params, timeout=15)
                data = resp.json()
                if data.get("status") == "1" and data.get("result"):
                    res = data["result"][0]
                    if res.get("SourceCode"):
                        return {
                            "ContractName": res.get("ContractName") or "Contract",
                            "CompilerVersion": res.get("CompilerVersion", ""),
                            "OptimizationUsed": res.get("OptimizationUsed", ""),
                            "Runs": res.get("Runs", ""),
                            "EVMVersion": res.get("EVMVersion", ""),
                            "ABI": res.get("ABI", ""),
                            "IsProxy": res.get("Proxy") == "1",
                            "Implementation": res.get("Implementation", ""),
                            "raw_source": res.get("SourceCode", "")
                        }
            except Exception:
                pass

        # 3. Fallback to Sourcify
        sourcify_data = self.fetch_sourcify_source(contract_address)
        if sourcify_data:
            return sourcify_data

        return None

    def fetch_sourcify_source(self, contract_address: str) -> Optional[Dict]:
        """Fallback to Sourcify open repository."""
        chain_id = self.config["chain_id"]
        url = f"https://sourcify.dev/server/files/any/{chain_id}/{contract_address}"
        try:
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                files = data.get("files", [])
                if files:
                    sources = {}
                    for f in files:
                        sources[f["name"]] = f.get("content", "")
                    return {
                        "ContractName": f"Sourcify_{contract_address[:8]}",
                        "CompilerVersion": "unknown",
                        "OptimizationUsed": "unknown",
                        "Runs": "unknown",
                        "EVMVersion": "",
                        "ABI": "",
                        "IsProxy": False,
                        "Implementation": "",
                        "sources_dict": sources,
                        "raw_source": ""
                    }
        except Exception:
            pass
        return None

    def detect_proxy_implementation(self, contract_address: str, source_data: Optional[Dict] = None) -> Optional[str]:
        """Detects proxy implementation address."""
        if source_data and source_data.get("Implementation"):
            impl = source_data.get("Implementation")
            if impl and impl != "0x0000000000000000000000000000000000000000":
                return impl

        slot_1967 = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
        try:
            payload = {
                "jsonrpc": "2.0",
                "method": "eth_getStorageAt",
                "params": [contract_address, slot_1967, "latest"],
                "id": 1
            }
            resp = self.session.post(self.config["rpc"], json=payload, timeout=10)
            val = resp.json().get("result", "")
            if val and val != "0x" and int(val, 16) != 0:
                impl_addr = "0x" + val[-40:]
                return impl_addr
        except Exception:
            pass

        return None

    def save_contract(self, contract_address: str, output_base_dir: str) -> Tuple[bool, str, Dict]:
        """Downloads and extracts Solidity code, ABI, and metadata."""
        contract_address = contract_address.strip().lower()
        source_data = self.fetch_verified_source(contract_address)
        
        target_dir = os.path.join(output_base_dir, self.chain, contract_address)
        os.makedirs(target_dir, exist_ok=True)

        metadata = {
            "address": contract_address,
            "chain": self.chain,
            "verified": False,
            "contract_name": "Unknown",
            "compiler_version": "",
            "optimization": "",
            "proxy": False,
            "implementation": None,
        }

        if not source_data:
            bytecode = self.get_runtime_bytecode(contract_address)
            if bytecode:
                with open(os.path.join(target_dir, "runtime_bytecode.bin"), "w") as f:
                    f.write(bytecode)
                metadata["has_bytecode"] = True
            with open(os.path.join(target_dir, "metadata.json"), "w") as f:
                json.dump(metadata, f, indent=2)
            return False, target_dir, metadata

        metadata["verified"] = True
        contract_name = source_data.get("ContractName") or "Contract"
        metadata["contract_name"] = contract_name
        metadata["compiler_version"] = source_data.get("CompilerVersion", "")
        metadata["optimization"] = source_data.get("OptimizationUsed", "")
        metadata["runs"] = source_data.get("Runs", "")
        metadata["evm_version"] = source_data.get("EVMVersion", "")
        
        impl = self.detect_proxy_implementation(contract_address, source_data)
        if impl:
            metadata["proxy"] = True
            metadata["implementation"] = impl
        elif source_data.get("IsProxy"):
            metadata["proxy"] = True

        # Classification
        from classifier import ContractClassifier
        abi_str = source_data.get("ABI", "")
        abi_parsed = None
        if abi_str and abi_str.startswith("["):
            try:
                abi_parsed = json.loads(abi_str)
            except Exception:
                pass
        
        category, tags, conf = ContractClassifier.classify(metadata, abi=abi_parsed, source_code=source_data.get("raw_source", ""))
        metadata["category"] = category
        metadata["tags"] = tags
        metadata["classification_confidence"] = conf

        # Save ABI
        if abi_parsed:
            with open(os.path.join(target_dir, "abi.json"), "w") as f:
                json.dump(abi_parsed, f, indent=2)
        elif abi_str:
            with open(os.path.join(target_dir, "abi.json"), "w") as f:
                f.write(abi_str)

        # Save Source Code files
        src_dir = os.path.join(target_dir, "src")
        os.makedirs(src_dir, exist_ok=True)

        if "sources_dict" in source_data and source_data["sources_dict"]:
            for file_path, code in source_data["sources_dict"].items():
                full_path = os.path.join(src_dir, file_path)
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                with open(full_path, "w", encoding="utf-8") as f:
                    f.write(code)
        else:
            raw_source = source_data.get("raw_source", "").strip()
            if raw_source.startswith("{{") and raw_source.endswith("}}"):
                raw_source = raw_source[1:-1]
                self._unpack_standard_json(raw_source, src_dir)
            elif raw_source.startswith("{") and "sources" in raw_source:
                self._unpack_standard_json(raw_source, src_dir)
            else:
                out_file = os.path.join(src_dir, f"{contract_name}.sol")
                with open(out_file, "w", encoding="utf-8") as f:
                    f.write(raw_source)

        with open(os.path.join(target_dir, "metadata.json"), "w") as f:
            json.dump(metadata, f, indent=2)

        return True, target_dir, metadata

    def _unpack_standard_json(self, json_str: str, output_dir: str):
        try:
            data = json.loads(json_str)
            sources = data.get("sources", {})
            for file_path, file_data in sources.items():
                content = file_data.get("content", "")
                full_path = os.path.join(output_dir, file_path)
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                with open(full_path, "w", encoding="utf-8") as f:
                    f.write(content)
        except Exception:
            with open(os.path.join(output_dir, "sources.json"), "w", encoding="utf-8") as f:
                f.write(json_str)
