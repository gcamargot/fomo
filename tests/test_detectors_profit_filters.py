"""Profit-relevant detector filters: replay FPs and public swapBack triggers."""

from token_scanner_daemon import StaticVulnerabilityAuditor


def _types(src: str):
    _flags, evidence = StaticVulnerabilityAuditor.audit_source(src)
    return {e["type"] for e in evidence}


def test_oz_ecdsa_library_is_not_signature_replay():
    src = """
    library ECDSA {
        enum RecoverError { NoError, InvalidSignature, InvalidSignatureLength }
        function tryRecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s)
            internal pure returns (address, RecoverError, bytes32) {
            // secp256k1n ÷ 2 + 1
            return ecrecover(hash, v, r, s);
        }
    }
    """
    assert "SIGNATURE_REPLAY_FLAW" not in _types(src)


def test_eip712_released_nonce_is_not_replay():
    src = """
    bytes32 public DOMAIN_SEPARATOR;
    bytes32 public constant RELEASE_TYPEHASH = keccak256("Release(uint256 nonce)");
    mapping(uint256 => bool) public released;
    function release(uint256 nonce, bytes memory sig) external {
        require(!released[nonce]);
        address s = ecrecover(DOMAIN_SEPARATOR, 27, bytes32(0), bytes32(0));
        released[nonce] = true;
    }
    """
    assert "SIGNATURE_REPLAY_FLAW" not in _types(src)


def test_raw_ecrecover_withdraw_without_nonce_is_replay():
    src = """
    function claim(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {
        address signer = ecrecover(hash, v, r, s);
        payable(signer).transfer(address(this).balance);
    }
    """
    assert "SIGNATURE_REPLAY_FLAW" in _types(src)


def test_public_swapback_still_flags():
    src = """
    function swapBack() public {
        _swapTokensForETH(balanceOf(address(this)));
    }
    """
    assert "PUBLIC_SWAPBACK_TRIGGER" in _types(src)


def test_public_manual_swap_without_auth_flags():
    src = """
    function manualSwap() external {
        uint256 bal = balanceOf(address(this));
        swapTokensForEth(bal);
    }
    """
    assert "PUBLIC_SWAPBACK_TRIGGER" in _types(src)


def test_manual_swap_tax_wallet_is_not_public_trigger():
    src = """
    function manualSwap() external {
        require(msg.sender == _taxWallet);
        swapTokensForEth(balanceOf(address(this)));
    }
    """
    assert "PUBLIC_SWAPBACK_TRIGGER" not in _types(src)


def test_public_collect_without_auth_flags():
    src = """
    contract Vault {
        function collect(uint256 tokenId, address recipient, uint128 a0, uint128 a1)
            external returns (uint256, uint256) {
            npm.collect(tokenId, recipient, a0, a1);
        }
    }
    """
    assert "V3_COLLECT_UNPROTECTED" in _types(src)


def test_interface_collect_is_ignored():
    src = """
    interface INonfungiblePositionManager {
        function collect(uint256 tokenId) external returns (uint256, uint256);
    }
    """
    assert "V3_COLLECT_UNPROTECTED" not in _types(src)


def test_erc4626_share_formula_without_virtual_flags():
    src = """
    contract Vault is ERC4626 {
        function previewDeposit(uint256 assets) public view returns (uint256) {
            return assets * totalSupply() / totalAssets();
        }
    }
    """
    assert "ERC4626_INFLATION_ATTACK" in _types(src)


def test_erc4626_virtual_offset_is_ignored():
    src = """
    contract Vault is ERC4626 {
        uint8 private constant _decimalsOffset = 3;
        function previewDeposit(uint256 assets) public view returns (uint256) {
            return assets * (totalSupply() + 10 ** _decimalsOffset) / (totalAssets() + 1);
        }
    }
    """
    assert "ERC4626_INFLATION_ATTACK" not in _types(src)


def test_spot_oracle_get_reserves_plus_liquidate_flags():
    src = """
    contract Lending {
        function liquidate(address user) external {
            (uint112 r0, uint112 r1,) = pair.getReserves();
            uint256 collateral = r0 * shares[user] / r1;
            _seize(user, collateral);
        }
    }
    """
    assert "SPOT_ORACLE_MANIPULATION" in _types(src)


def test_spot_oracle_get_amounts_out_plus_borrow_flags():
    src = """
    function borrow(uint256 amount) external {
        uint256[] memory out = router.getAmountsOut(amount, path);
        uint256 collateral = out[1];
        _borrow(msg.sender, amount);
    }
    """
    assert "SPOT_ORACLE_MANIPULATION" in _types(src)


def test_chainlink_latest_round_is_not_spot_oracle():
    src = """
    function liquidate(address user) external {
        (, int256 px,,,) = feed.latestRoundData();
        (uint112 r0, uint112 r1,) = pair.getReserves();
        uint256 collateral = uint256(px) * r0 / r1;
        _seize(user, collateral);
    }
    """
    assert "SPOT_ORACLE_MANIPULATION" not in _types(src)


def test_pair_interface_get_reserves_is_not_spot_oracle():
    src = """
    interface IUniswapV2Pair {
        function getReserves() external view returns (uint112, uint112, uint32);
    }
    """
    assert "SPOT_ORACLE_MANIPULATION" not in _types(src)


def test_only_owner_collect_is_ignored():
    src = """
    function collect() external onlyOwner {
        payable(owner()).transfer(address(this).balance);
    }
    """
    assert "V3_COLLECT_UNPROTECTED" not in _types(src)
