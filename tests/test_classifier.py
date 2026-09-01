from classifier import ContractClassifier

def test_classify_erc20_abi():
    erc20_abi = [
        {"type": "function", "name": "totalSupply"},
        {"type": "function", "name": "balanceOf"},
        {"type": "function", "name": "transfer"},
        {"type": "function", "name": "transferFrom"},
        {"type": "function", "name": "approve"},
        {"type": "function", "name": "allowance"},
        {"type": "event", "name": "Transfer"},
        {"type": "event", "name": "Approval"},
    ]
    category, tags, confidence = ContractClassifier.classify(
        metadata={"chain": "base"},
        abi=erc20_abi
    )
    assert category == "ERC20_TOKEN"
    assert "ERC20_TOKEN" in tags
    assert confidence >= 0.7

def test_classify_erc4626_vault():
    vault_abi = [
        {"type": "function", "name": "asset"},
        {"type": "function", "name": "totalAssets"},
        {"type": "function", "name": "deposit"},
        {"type": "function", "name": "withdraw"},
        {"type": "function", "name": "redeem"},
        {"type": "function", "name": "convertToShares"},
        {"type": "function", "name": "convertToAssets"},
        {"type": "event", "name": "Deposit"},
        {"type": "event", "name": "Withdraw"},
    ]
    category, tags, confidence = ContractClassifier.classify(
        metadata={"chain": "ethereum"},
        abi=vault_abi
    )
    assert category == "ERC4626_VAULT"
    assert "ERC4626_VAULT" in tags
    assert confidence > 0.5

def test_classify_dex_router():
    router_abi = [
        {"type": "function", "name": "swapExactTokensForETH"},
        {"type": "function", "name": "swapExactETHForTokens"},
        {"type": "function", "name": "exactInputSingle"},
    ]
    category, tags, confidence = ContractClassifier.classify(
        metadata={"chain": "arbitrum"},
        abi=router_abi
    )
    assert category == "DEX_ROUTER_AGGREGATOR"
    assert "DEX_ROUTER_AGGREGATOR" in tags

def test_classify_proxy_metadata():
    category, tags, confidence = ContractClassifier.classify(
        metadata={"chain": "base", "proxy": True},
        abi=[]
    )
    assert "PROXY" in tags
    assert category == "PROXY_FACTORY"

def test_classify_source_fallback():
    source_code = """
    contract Token {
        function totalSupply() external view returns (uint256);
        function balanceOf(address account) external view returns (uint256);
        function transfer(address to, uint256 amount) external returns (bool);
        function transferFrom(address from, address to, uint256 amount) external returns (bool);
        event Transfer(address indexed from, address indexed to, uint256 value);
    }
    """
    category, tags, confidence = ContractClassifier.classify(
        metadata={"chain": "base"},
        abi=[],
        source_code=source_code
    )
    assert category == "ERC20_TOKEN"
    assert "ERC20_TOKEN" in tags
