"""Regression corpus: human-triaged FPs must not re-enter the queue.

Cases are the cards marked FP via the LAN API (not live RPC). Replay the
same source / reserve-vs-balance snapshot through the detectors.
"""

from unittest.mock import MagicMock

from factory_listener import process_factory_pair
from profit_estimator import ProfitEstimate, estimate_skim_profit
from token_scanner_daemon import StaticVulnerabilityAuditor


def _types(src: str):
    _flags, evidence = StaticVulnerabilityAuditor.audit_source(src)
    return {e["type"] for e in evidence}


def _run_factory(*, reserves, balances, probe="success"):
    db = MagicMock()
    gen = MagicMock(return_value="/tmp/fp.md")
    ev = {
        "token": "0x1111111111111111111111111111111111111111",
        "pair": "0x2222222222222222222222222222222222222222",
        "weth": "0x4200000000000000000000000000000000000006",
    }
    process_factory_pair(
        db,
        "base",
        ev,
        load_source=lambda *a: "",
        audit=lambda src: ({}, []),
        verify=lambda *a: (False, "X", 0.0, [], None),
        generate_triage=gen,
        estimate=lambda **k: ProfitEstimate(
            expected_profit_eth=0.0,
            pool_eth=float(reserves[0] or 0.0),
            treasury_token_raw=0,
            sell_fraction=0.25,
            gas_eth=0.002,
            method="xyk_spot",
            actionable=False,
        ),
        reserves=lambda: reserves,
        treasury_raw=lambda: 0,
        pair_balances=lambda: balances,
        skim_probe=lambda: probe,
    )
    flags = db.update_token_flags.call_args[0][1]
    return gen, flags


# --- GuCoin (Arbitrum): IERC20.transferFrom is not Dexible ---
# triage_arbitrum_0x60c1b1bc… / 0xd8d31de9…  verdict FP_IERC20_TRANSFERFROM_NOT_DEXIBLE

IERC20_INTERFACE = """
interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
"""

OZ_ERC20_TRANSFERFROM = """
contract ERC20 {
    function transfer(address to, uint256 value) public virtual returns (bool) {
        address owner = _msgSender();
        _transfer(owner, to, value);
        return true;
    }
    function approve(address spender, uint256 value) public virtual returns (bool) {
        address owner = _msgSender();
        _approve(owner, spender, value);
        return true;
    }
    function transferFrom(address from, address to, uint256 value) public virtual returns (bool) {
        address spender = _msgSender();
        _spendAllowance(from, spender, value);
        _transfer(from, to, value);
        return true;
    }
}
"""

# Still must catch Dexible-style routers (positive control).
DEXIBLE_ROUTER = """
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


def test_fp_gucoin_ierc20_interface_is_not_arbitrary_call():
    assert "UNCONSTRAINED_ARBITRARY_CALL" not in _types(IERC20_INTERFACE)


def test_fp_gucoin_oz_erc20_transferfrom_is_not_arbitrary_call():
    assert "UNCONSTRAINED_ARBITRARY_CALL" not in _types(OZ_ERC20_TRANSFERFROM)


def test_dexible_router_still_flags_arbitrary_from():
    assert "UNCONSTRAINED_ARBITRARY_CALL" in _types(DEXIBLE_ROUTER)


# --- PAIR_SKIM FPs: skim() always succeeds on UniV2; excess was gone or token-only ---

def test_fp_spacex_live_zero_excess_does_not_emit():
    """base:0xd9aa7a6215496bd1ceaaaab28c93a2e04c5d0354 FP_SKIM_NO_LIVE_EXCESS.

    Live UniV2 pair 0x61b83e…: getReserves WETH == WETH.balanceOf(pair) == dust.
    """
    res = (5.3227260423e-08, 2645979137.6921473)
    gen, flags = _run_factory(reserves=res, balances=res, probe="success")
    gen.assert_not_called()
    assert flags.get("is_user_exploitable") != 1
    assert flags.get("dynamic_status") != "PAIR_SKIM_ACTIONABLE"


def test_fp_factory_pair_pulled_liquidity_does_not_emit():
    """Earlier FactoryPairToken PAIR_SKIM cards: live res=0 bal=0, skim success."""
    gen, flags = _run_factory(reserves=(0.0, 0.0), balances=(0.0, 0.0), probe="success")
    gen.assert_not_called()
    assert flags.get("is_user_exploitable") != 1
    assert "PAIR_SKIM_ACTIONABLE" not in str(flags.get("dynamic_status") or "")


def test_fp_skim_token_side_surplus_is_not_actionable():
    """SpaceX-class: WETH reserve matches pair WETH, ~2.3% extra tokens.

    Old estimator sold leftover tokens into the pool (~0.058 ETH on a 2.60
    WETH reserve) and emitted PAIR_SKIM. That is not donated WETH.
    """
    reserve_eth = 2.60
    reserve_tok = 1_000_000.0
    # Chosen so xyk_amount_out(excess_tok, reserve_tok, reserve_eth) ~ 0.06 ETH.
    pair_tok = 1_023_666.0
    est = estimate_skim_profit(
        pair_eth=reserve_eth,
        pair_token=pair_tok,
        reserve_eth=reserve_eth,
        reserve_token=reserve_tok,
    )
    assert est.actionable is False
    assert est.expected_profit_eth < 0.05

    gen, flags = _run_factory(
        reserves=(reserve_eth, reserve_tok),
        balances=(reserve_eth, pair_tok),
        probe="success",
    )
    gen.assert_not_called()
    assert flags.get("is_user_exploitable") != 1


def test_real_weth_donation_still_emits_skim():
    gen, flags = _run_factory(
        reserves=(1.0, 1000.0),
        balances=(1.25, 1000.0),
        probe="success",
    )
    gen.assert_called_once()
    assert flags["dynamic_status"] == "PAIR_SKIM_ACTIONABLE"
    assert flags.get("is_user_exploitable") == 1
