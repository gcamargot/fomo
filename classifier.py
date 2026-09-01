from typing import Dict, List, Optional, Tuple

class ContractClassifier:
    """
    Classifies smart contracts based on ABI function selectors, events,
    source code interfaces, and bytecode inspection for academic dataset categorization.
    """

    # Function signature heuristics
    SIGNATURES = {
        "ERC20_TOKEN": {
            "functions": {"totalSupply", "balanceOf", "transfer", "transferFrom", "approve", "allowance"},
            "events": {"Transfer", "Approval"},
            "min_match": 4
        },
        "ERC721_NFT": {
            "functions": {"ownerOf", "safeTransferFrom", "transferFrom", "approve", "setApprovalForAll", "isApprovedForAll"},
            "events": {"Transfer", "Approval", "ApprovalForAll"},
            "min_match": 4
        },
        "ERC1155_MULTI_TOKEN": {
            "functions": {"balanceOf", "balanceOfBatch", "setApprovalForAll", "isApprovedForAll", "safeTransferFrom", "safeBatchTransferFrom"},
            "events": {"TransferSingle", "TransferBatch", "ApprovalForAll"},
            "min_match": 4
        },
        "ERC4626_VAULT": {
            "functions": {"asset", "totalAssets", "convertToShares", "convertToAssets", "maxDeposit", "previewDeposit", "deposit", "maxMint", "previewMint", "mint", "maxWithdraw", "previewWithdraw", "withdraw", "maxRedeem", "previewRedeem", "redeem"},
            "events": {"Deposit", "Withdraw"},
            "min_match": 6
        },
        "DEX_ROUTER_AGGREGATOR": {
            "functions": {
                "swapExactTokensForTokens", "swapTokensForExactTokens", "swapExactETHForTokens",
                "swapTokensForExactETH", "swapExactTokensForETH", "exactInputSingle",
                "exactInput", "exactOutputSingle", "exactOutput", "swap", "multicall", "route",
                "uniswapV3SwapCallback", "pancakeV3SwapCallback", "execute"
            },
            "events": set(),
            "min_match": 2
        },
        "DEX_LIQUIDITY_POOL": {
            "functions": {"token0", "token1", "getReserves", "mint", "burn", "swap", "skim", "sync", "slot0", "liquidity", "ticks", "positions"},
            "events": {"Swap", "Sync", "Mint", "Burn"},
            "min_match": 3
        },
        "LENDING_BORROWING": {
            "functions": {"borrow", "repayBorrow", "liquidateBorrow", "redeem", "borrowBalanceCurrent", "exchangeRateCurrent", "supply", "withdraw", "flashLoan"},
            "events": {"Borrow", "RepayBorrow", "LiquidateBorrow", "Supply"},
            "min_match": 2
        },
        "SMART_WALLET_ACCOUNT_ABSTRACTION": {
            "functions": {"validateUserOp", "executeUserOp", "entryPoint", "execTransaction", "nonce", "isValidSignature"},
            "events": {"ExecutionSuccess", "ExecutionFailure", "UserOperationEvent"},
            "min_match": 2
        },
        "GOVERNANCE_TIMELOCK": {
            "functions": {"propose", "queue", "execute", "cancel", "castVote", "castVoteWithReason", "getVotes", "quorum", "delay", "gracePeriod"},
            "events": {"ProposalCreated", "ProposalExecuted", "ProposalCanceled", "VoteCast"},
            "min_match": 3
        },
        "PROXY_FACTORY": {
            "functions": {"upgradeTo", "upgradeToAndCall", "implementation", "admin", "changeAdmin", "createClone", "deploy", "createContract"},
            "events": {"Upgraded", "AdminChanged"},
            "min_match": 1
        }
    }

    @classmethod
    def classify(cls, metadata: Dict, abi: Optional[List[Dict]] = None, source_code: str = "") -> Tuple[str, List[str], float]:
        """
        Classifies a contract and returns:
        - primary_category (str)
        - tags (List[str])
        - confidence score (0.0 to 1.0)
        """
        tags = []
        is_proxy = metadata.get("proxy", False) or metadata.get("is_proxy", False)
        if is_proxy:
            tags.append("PROXY")

        # Extract functions and events from ABI
        abi_functions = set()
        abi_events = set()
        if abi and isinstance(abi, list):
            for item in abi:
                if isinstance(item, dict):
                    if item.get("type") == "function" and "name" in item:
                        abi_functions.add(item["name"])
                    elif item.get("type") == "event" and "name" in item:
                        abi_events.add(item["name"])

        # Fallback regex search on source code if ABI is empty
        if not abi_functions and source_code:
            import re
            fn_matches = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\(", source_code)
            abi_functions.update(fn_matches)
            ev_matches = re.findall(r"event\s+([a-zA-Z0-9_]+)\s*\(", source_code)
            abi_events.update(ev_matches)

        scores: Dict[str, float] = {}

        for category, rules in cls.SIGNATURES.items():
            matched_fn = abi_functions.intersection(rules["functions"])
            matched_ev = abi_events.intersection(rules["events"])
            total_matches = len(matched_fn) + len(matched_ev)
            min_required = rules["min_match"]

            if total_matches >= min_required:
                confidence = min(1.0, total_matches / (len(rules["functions"]) * 0.7 + 1))
                scores[category] = confidence
                tags.append(category)

        # Disambiguation / Priority Rules
        if "ERC4626_VAULT" in scores:
            primary_category = "ERC4626_VAULT"
        elif "DEX_ROUTER_AGGREGATOR" in scores:
            primary_category = "DEX_ROUTER_AGGREGATOR"
        elif "DEX_LIQUIDITY_POOL" in scores:
            primary_category = "DEX_LIQUIDITY_POOL"
        elif "LENDING_BORROWING" in scores:
            primary_category = "LENDING_BORROWING"
        elif "SMART_WALLET_ACCOUNT_ABSTRACTION" in scores:
            primary_category = "SMART_WALLET_ACCOUNT_ABSTRACTION"
        elif "ERC20_TOKEN" in scores:
            primary_category = "ERC20_TOKEN"
        elif "ERC721_NFT" in scores:
            primary_category = "ERC721_NFT"
        elif "ERC1155_MULTI_TOKEN" in scores:
            primary_category = "ERC1155_MULTI_TOKEN"
        elif "GOVERNANCE_TIMELOCK" in scores:
            primary_category = "GOVERNANCE_TIMELOCK"
        elif is_proxy or "PROXY_FACTORY" in scores:
            primary_category = "PROXY_FACTORY"
        else:
            primary_category = "CUSTOM_LOGIC"

        confidence = scores.get(primary_category, 0.5 if primary_category != "CUSTOM_LOGIC" else 0.3)
        return primary_category, list(set(tags)), round(confidence, 2)
