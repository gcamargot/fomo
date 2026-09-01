"""PairCreated decode and WETH-only filter (no RPC)."""

from factory_listener import PAIR_CREATED_TOPIC0, decode_pair_created, should_emit_factory_triage
from profit_estimator import ProfitEstimate


WETH = "0x4200000000000000000000000000000000000006"
TOKEN = "0x1111111111111111111111111111111111111111"
PAIR = "0x2222222222222222222222222222222222222222"


def _pad_addr(addr: str) -> str:
    return "0x" + addr.lower().replace("0x", "").rjust(64, "0")


def _log(token0: str, token1: str, pair: str = PAIR):
    pair_hex = pair.lower().replace("0x", "").rjust(64, "0")
    index_hex = "1".rjust(64, "0")
    return {
        "topics": [
            PAIR_CREATED_TOPIC0,
            _pad_addr(token0),
            _pad_addr(token1),
        ],
        "data": "0x" + pair_hex + index_hex,
        "address": "0x8909dc15e40173ff4699343b6eb8132c65e18ec6",
    }


def test_decode_weth_token1():
    ev = decode_pair_created(_log(TOKEN, WETH), weth=WETH)
    assert ev is not None
    assert ev["token"] == TOKEN
    assert ev["pair"] == PAIR
    assert ev["weth"] == WETH.lower()


def test_decode_weth_token0():
    ev = decode_pair_created(_log(WETH, TOKEN), weth=WETH)
    assert ev is not None
    assert ev["token"] == TOKEN


def test_skip_non_weth_pair():
    other = "0x3333333333333333333333333333333333333333"
    assert decode_pair_created(_log(TOKEN, other), weth=WETH) is None


def test_wrong_topic_returns_none():
    log = _log(TOKEN, WETH)
    log["topics"][0] = "0x" + "ab" * 32
    assert decode_pair_created(log, weth=WETH) is None


def test_unverified_not_actionable_no_triage():
    est = ProfitEstimate(
        expected_profit_eth=0.0,
        pool_eth=0.001,
        treasury_token_raw=0,
        sell_fraction=0.25,
        gas_eth=0.002,
        method="xyk_spot",
        actionable=False,
    )
    assert should_emit_factory_triage(
        verified=False, has_source=False, flags={}, estimate=est
    ) is False


def test_verified_swapback_fat_pool_emits():
    est = ProfitEstimate(
        expected_profit_eth=0.5,
        pool_eth=20.0,
        treasury_token_raw=10**18,
        sell_fraction=0.25,
        gas_eth=0.002,
        method="xyk_spot",
        actionable=True,
    )
    assert should_emit_factory_triage(
        verified=True,
        has_source=True,
        flags={"has_public_swapback": True},
        estimate=est,
    ) is True


def test_unverified_even_if_fat_pool_no_auto_tp():
    est = ProfitEstimate(
        expected_profit_eth=1.0,
        pool_eth=50.0,
        treasury_token_raw=10**24,
        sell_fraction=0.25,
        gas_eth=0.002,
        method="xyk_spot",
        actionable=True,
    )
    assert should_emit_factory_triage(
        verified=False, has_source=False, flags={}, estimate=est
    ) is False
