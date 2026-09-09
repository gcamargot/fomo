"""Live skim/collect probes: only emit when the selector actually succeeds."""

from unittest.mock import MagicMock

from token_scanner_daemon import OnChainStateVerifier


def test_v3_collect_gate_ignores_funded_revert():
    ok, note = OnChainStateVerifier.v3_collect_gate("revert", 1.5)
    assert ok is False
    assert note == "V3_COLLECT_REVERT_OR_UNKNOWN"


def test_v3_collect_gate_confirms_only_success():
    ok, note = OnChainStateVerifier.v3_collect_gate("success", 0.0)
    assert ok is True
    assert note == "V3_COLLECT_CALLABLE"


def test_v3_collect_gate_auth():
    ok, note = OnChainStateVerifier.v3_collect_gate("auth", 1.0)
    assert ok is False
    assert note == "V3_COLLECT_AUTH_REVERTED"


def test_collect_probe_plan_no_args():
    plan = OnChainStateVerifier.collect_probe_plan(
        "function collect() external { payable(msg.sender).transfer(address(this).balance); }"
    )
    assert plan is not None
    sig, args = plan
    assert sig == "collect()"
    assert args == b""


def test_collect_probe_plan_protocol():
    src = """
    function collectProtocol(address recipient, uint128 a0, uint128 a1) external
        returns (uint128, uint128) { }
    """
    plan = OnChainStateVerifier.collect_probe_plan(src)
    assert plan is not None
    sig, args = plan
    assert sig == "collectProtocol(address,uint128,uint128)"
    assert len(args) == 96


def test_collect_probe_plan_pool_ticks():
    src = """
    function collect(address recipient, int24 tickLower, int24 tickUpper,
        uint128 amount0Requested, uint128 amount1Requested) external returns (uint128, uint128) {}
    """
    plan = OnChainStateVerifier.collect_probe_plan(src)
    assert plan is not None
    sig, args = plan
    assert sig == "collect(address,int24,int24,uint128,uint128)"
    assert len(args) == 160


def test_collect_probe_plan_skips_interface():
    src = """
    interface INonfungiblePositionManager {
        function collect(uint256 tokenId) external returns (uint256, uint256);
    }
    function collect(uint256 tokenId, address recipient, uint128 a0, uint128 a1)
        external returns (uint256, uint256) {}
    """
    plan = OnChainStateVerifier.collect_probe_plan(src)
    assert plan is not None
    sig, _args = plan
    assert sig == "collect(uint256,address,uint128,uint128)"


def test_collect_probe_plan_struct():
    src = """
    function collect(CollectParams calldata params) external payable
        returns (uint256 amount0, uint256 amount1) {}
    """
    plan = OnChainStateVerifier.collect_probe_plan(src)
    assert plan is not None
    sig, args = plan
    assert sig == "collect((uint256,address,uint128,uint128))"
    assert len(args) == 128


def _pair_w3():
    w3 = MagicMock()
    w3.to_checksum_address.side_effect = lambda a: a
    return w3


def test_pair_skim_exploit_requires_skim_success(monkeypatch):
    w3 = _pair_w3()
    pair = "0x" + "22" * 20
    token = "0x" + "11" * 20
    monkeypatch.setattr(
        OnChainStateVerifier,
        "evaluate_amm_slippage_reserves",
        staticmethod(
            lambda *a, **k: {
                "eth_reserve": 1.0,
                "token_reserve": 1000.0,
                "primary_pool": {"pair": pair},
            }
        ),
    )

    def _bal(_w3, asset, _holder):
        if str(asset).lower().endswith("0006"):
            return int(1.25 * 10**18)
        return int(1000 * 10**18)

    monkeypatch.setattr("factory_listener.erc20_balance_raw", _bal)
    monkeypatch.setattr(
        OnChainStateVerifier,
        "probe_unauth_selector",
        staticmethod(lambda *a, **k: "revert"),
    )
    assert OnChainStateVerifier.pair_skim_exploit(w3, "base", token) is None

    monkeypatch.setattr(
        OnChainStateVerifier,
        "probe_unauth_selector",
        staticmethod(lambda *a, **k: "success"),
    )
    hit = OnChainStateVerifier.pair_skim_exploit(w3, "base", token)
    assert hit is not None
    assert hit["type"] == "PAIR_SKIM"
    assert hit["profit"]["actionable"] is True
