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
