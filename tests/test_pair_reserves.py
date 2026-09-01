"""UniV2 reserve helper (no RPC)."""

from types import SimpleNamespace

from factory_listener import erc20_balance_raw, pair_reserves_eth_token

WETH = "0x4200000000000000000000000000000000000006"
PAIR = "0x2222222222222222222222222222222222222222"


class _Fns:
    def __init__(self, r0, r1, t0):
        self._r0 = r0
        self._r1 = r1
        self._t0 = t0

    def getReserves(self):
        return SimpleNamespace(call=lambda: (self._r0, self._r1, 0))

    def token0(self):
        return SimpleNamespace(call=lambda: self._t0)

    def balanceOf(self, _holder):
        return SimpleNamespace(call=lambda: 10**18)


class _Eth:
    def contract(self, address, abi):
        return SimpleNamespace(functions=_Fns(20 * 10**18, 1000 * 10**18, WETH))


def test_pair_reserves_weth_token0():
    w3 = SimpleNamespace(eth=_Eth(), to_checksum_address=lambda a: a)
    eth, tok = pair_reserves_eth_token(w3, PAIR, WETH)
    assert eth == 20.0
    assert tok == 1000.0


def test_pair_reserves_none_w3():
    assert pair_reserves_eth_token(None, PAIR, WETH) == (0.0, 0.0)


def test_erc20_balance_raw():
    w3 = SimpleNamespace(eth=_Eth(), to_checksum_address=lambda a: a)
    assert erc20_balance_raw(w3, PAIR, PAIR) == 10**18
    assert erc20_balance_raw(None, PAIR, PAIR) == 0
