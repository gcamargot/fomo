"""Replay published incident *patterns* through audit_source.

These are not live payloads. Each snippet is the vulnerable shape cited in
OWASP / post-mortems. If a type is missing, the detector is wrong — waiting
on live Base will not fix it.

Citations:
- OWASP SCWE-135 ERC4626 share inflation via donations (2025-08)
- Sonne Finance empty Compound V2 market, CertiK 2024-05-14 (~$20M);
  same class: Hundred 2023, Onyx 2023
- Curve/Yearn read-only reentrancy (get_virtual_price in a view used by deposit)
- Kyber Elastic tick-boundary mint, Nov 2023 (~$48M)
- FlashDeFier / Warp-style spot AMM: getReserves used as collateral price
- Fei Rari ETH CEI (2022); Penpie harvest callback (2024)
- Euler donate without health (2023)
- Dexible aggregator `transferFrom(from)` (2023)
- Tax-token public swapBack; EIP-2612 permit without nonce
"""

from token_scanner_daemon import StaticVulnerabilityAuditor


def _types(src: str):
    _flags, evidence = StaticVulnerabilityAuditor.audit_source(src)
    return {e["type"] for e in evidence}


# OWASP SCWE-135 — first depositor / donation share formula, no virtual offset.
SCWE135_ERC4626 = """
contract Vault is ERC4626 {
    function previewDeposit(uint256 assets) public view returns (uint256) {
        return assets * totalSupply() / totalAssets();
    }
    function deposit(uint256 assets, address receiver) public returns (uint256) {
        uint256 shares = previewDeposit(assets);
        _mint(receiver, shares);
        asset.transferFrom(msg.sender, address(this), assets);
    }
}
"""

# Sonne / Hundred / Onyx — Compound V2 exchangeRate from cash/supply.
# CertiK: exchangeRate = (totalCash + totalBorrows - totalReserves) / totalSupply
SONNE_COMPOUND_EMPTY_MARKET = """
contract CToken {
    function getCashPrior() internal view returns (uint) {
        return EIP20Interface(underlying).balanceOf(address(this));
    }
    function exchangeRateStoredInternal() internal view returns (uint) {
        uint _totalSupply = totalSupply;
        if (_totalSupply == 0) {
            return initialExchangeRateMantissa;
        }
        uint cashPlusBorrowsMinusReserves = getCashPrior() + totalBorrows - totalReserves;
        return cashPlusBorrowsMinusReserves * expScale / _totalSupply;
    }
    function exchangeRateStored() public view returns (uint) {
        return exchangeRateStoredInternal();
    }
}
"""

# Curve LP vault: view virtual price, deposit has no reentrancy lock.
CURVE_READONLY_REENTRANCY = """
contract CurveLpVault {
    function totalAssets() public view returns (uint256) {
        return ICurve(pool).get_virtual_price() * lp.balanceOf(address(this)) / 1e18;
    }
    function deposit(uint256 assets) external {
        uint256 shares = assets * totalSupply() / totalAssets();
        _mint(msg.sender, shares);
        lp.transferFrom(msg.sender, address(this), assets);
    }
}
"""

# Kyber Elastic / Algebra-style CLMM mint with zero mins (ghost liquidity class).
KYBER_TICK_MINT = """
library TickMath {
    function getSqrtRatioAtTick(int24 tick) internal pure returns (uint160) {}
}
contract ElasticPool {
    uint160 public sqrtPriceX96;
    int24 public tickSpacing;
    function mint(
        address recipient,
        int24 tickLower,
        int24 tickUpper,
        uint128 qty,
        bytes calldata data
    ) external returns (uint256 qty0, uint256 qty1) {
        uint160 sa = TickMath.getSqrtRatioAtTick(tickLower);
        amount0Min = 0;
        amount1Min = 0;
        (qty0, qty1) = _mint(recipient, tickLower, tickUpper, qty);
    }
}
"""

# Warp/Bonq-adjacent: lending prices collateral from a UniV2 pair spot.
# FlashDeFier 2024: getReserves as taint source into borrow/liquidate.
SPOT_AMM_ORACLE_LENDING = """
contract LendingPair {
    function liquidate(address user) external {
        (uint112 r0, uint112 r1,) = IUniswapV2Pair(collateralPair).getReserves();
        uint256 collateral = uint256(r0) * shares[user] / uint256(r1);
        _seize(user, collateral);
        _borrow(msg.sender, debt[user]);
    }
}
"""

# Control: OZ virtual offset must still be a negative (mitigated SCWE-135).
OZ_VIRTUAL_OFFSET = """
contract Vault is ERC4626 {
    uint8 private constant _decimalsOffset = 3;
    function previewDeposit(uint256 assets) public view returns (uint256) {
        return assets * (totalSupply() + 10 ** _decimalsOffset) / (totalAssets() + 1);
    }
}
"""


def test_replay_owasp_scwe135_erc4626():
    assert "ERC4626_INFLATION_ATTACK" in _types(SCWE135_ERC4626)


def test_replay_sonne_compound_empty_market():
    assert "COMPOUND_EMPTY_MARKET" in _types(SONNE_COMPOUND_EMPTY_MARKET)


def test_replay_curve_read_only_reentrancy():
    assert "READ_ONLY_REENTRANCY" in _types(CURVE_READONLY_REENTRANCY)


def test_replay_kyber_elastic_tick_mint():
    assert "CLMM_TICK_ROUNDING" in _types(KYBER_TICK_MINT)


def test_replay_spot_amm_oracle_lending():
    assert "SPOT_ORACLE_MANIPULATION" in _types(SPOT_AMM_ORACLE_LENDING)


def test_replay_oz_virtual_offset_is_negative():
    assert "ERC4626_INFLATION_ATTACK" not in _types(OZ_VIRTUAL_OFFSET)


# Fei Rari / classic ETH CEI (2022): send value then update balances.
FEI_RARI_ETH_REENTRANCY = """
contract EthPool {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
"""

# Penpie (2024): harvest/withdraw callback before zeroing pending rewards.
PENPIE_HARVEST_REENTRANCY = """
contract PendleStaking {
    mapping(address => uint256) public pending;
    function harvest() public {
        uint256 amt = pending[msg.sender];
        IPool(pool).withdraw(amt);
        pending[msg.sender] = 0;
    }
}
"""

# Euler donate (2023): credit eToken without a solvency/health check.
EULER_DONATE = """
contract EToken {
    function donateToReserves(uint subAccountId, uint amount) external {
        require(amount <= MAX_SANE_AMOUNT);
        eTokenBalance[msg.sender] -= amount;
        reserveBalance += amount;
    }
    function donate(uint subAccountId, uint amount) external {
        increaseBalance(msg.sender, amount);
    }
}
"""

# Dexible (2023): aggregator swap uses caller-supplied `from` in transferFrom.
DEXIBLE_ARBITRARY_FROM = """
contract DexibleRouter {
    function simpleSwap(address from, address token, uint256 amount, bytes calldata data)
        public payable
    {
        IERC20(token).transferFrom(from, address(this), amount);
        (bool ok,) = router.call(data);
        require(ok);
    }
}
"""

# Tax token public swapBack (sandwich trigger we already hunt).
TAX_TOKEN_SWAPBACK = """
contract TaxToken {
    function swapBack() public {
        uint256 bal = balanceOf(address(this));
        _swapTokensForETH(bal);
    }
}
"""

# EIP-2612 permit without nonce increment (mempool replay).
PERMIT_NO_NONCE = """
contract Token {
    function permit(address owner, address spender, uint256 value, uint256 deadline,
        uint8 v, bytes32 r, bytes32 s) public {
        require(deadline >= block.timestamp);
        bytes32 hash = keccak256(abi.encode(owner, spender, value, deadline));
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner);
        allowance[owner][spender] = value;
    }
}
"""


def test_replay_fei_rari_eth_reentrancy():
    assert "CHECKS_EFFECTS_REENTRANCY" in _types(FEI_RARI_ETH_REENTRANCY)


def test_replay_penpie_harvest_reentrancy():
    assert "CHECKS_EFFECTS_REENTRANCY" in _types(PENPIE_HARVEST_REENTRANCY)


def test_replay_euler_donate():
    types = _types(EULER_DONATE)
    assert "EULER_DONATE_UNCHECKED" in types or "ERC4626_INFLATION_ATTACK" in types


def test_replay_dexible_arbitrary_from():
    types = _types(DEXIBLE_ARBITRARY_FROM)
    assert "UNCONSTRAINED_ARBITRARY_CALL" in types or "DEXIBLE_ARBITRARY_FROM" in types


OZ_ERC721_SAFE_TRANSFER = """
contract ERC721 {
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) public payable virtual {
        transferFrom(from, to, tokenId);
        require(_checkOnERC721Received(from, to, tokenId, _data));
    }
}
"""


def test_replay_oz_erc721_safe_transfer_is_not_arbitrary_call():
    assert "UNCONSTRAINED_ARBITRARY_CALL" not in _types(OZ_ERC721_SAFE_TRANSFER)


def test_replay_tax_token_public_swapback():
    assert "PUBLIC_SWAPBACK_TRIGGER" in _types(TAX_TOKEN_SWAPBACK)


def test_replay_permit_without_nonce():
    assert "PERMIT_NO_NONCE" in _types(PERMIT_NO_NONCE)
