"""Factory listener cycle: getLogs + cursor (fake RPC)."""

from factory_listener import PAIR_CREATED_TOPIC0, run_factory_cycle
from log_sync import cursor_key
from token_scanner_daemon import DEX_CONFIG, TokenScannerDB


WETH = DEX_CONFIG["base"]["weth"]
FACTORY = DEX_CONFIG["base"]["factories"][0][1]
TOKEN = "0x1111111111111111111111111111111111111111"
PAIR = "0x2222222222222222222222222222222222222222"


def _pad_addr(addr: str) -> str:
    return "0x" + addr.lower().replace("0x", "").rjust(64, "0")


def _pair_log(token=TOKEN, weth=WETH, pair=PAIR, factory=FACTORY):
    pair_hex = pair.lower().replace("0x", "").rjust(64, "0")
    return {
        "topics": [PAIR_CREATED_TOPIC0, _pad_addr(token), _pad_addr(weth)],
        "data": "0x" + pair_hex + "1".rjust(64, "0"),
        "address": factory,
    }


class _Eth:
    def __init__(self, head, logs):
        self.block_number = head
        self.logs = logs
        self.filters = []

    def get_logs(self, filt):
        self.filters.append(filt)
        addr = str(filt.get("address") or "").lower()
        return [
            lg for lg in self.logs
            if str(lg.get("address") or "").lower() == addr
        ]


class _W3:
    def __init__(self, head, logs):
        self.eth = _Eth(head, logs)


def test_factory_cycle_ingests_weth_pair_and_advances_cursor(tmp_path):
    db = TokenScannerDB(str(tmp_path / "t.db"))
    seen = []
    w3 = _W3(head=500, logs=[_pair_log()])
    n = run_factory_cycle(
        db,
        {"base": w3},
        lookback=50,
        max_span=2000,
        on_pair=lambda chain, ev: seen.append((chain, ev)),
    )
    assert n == 1
    assert seen[0][0] == "base"
    assert seen[0][1]["token"] == TOKEN
    key = cursor_key("base", FACTORY, "PairCreated")
    assert db.get_cursor(key) == 500
    with db.get_connection() as conn:
        row = conn.execute(
            "SELECT address, verified FROM tokens WHERE address = ?", (TOKEN,)
        ).fetchone()
    assert row is not None and row[0] == TOKEN
    assert int(row[1]) == 0
    assert w3.eth.filters
    assert w3.eth.filters[0]["fromBlock"] == 451  # 500-50+1


def test_factory_cycle_skips_when_cursor_caught_up(tmp_path):
    db = TokenScannerDB(str(tmp_path / "t.db"))
    key = cursor_key("base", FACTORY, "PairCreated")
    db.set_cursor(key, 500)
    w3 = _W3(head=500, logs=[_pair_log()])
    n = run_factory_cycle(db, {"base": w3}, lookback=50)
    assert n == 0
    uni_key = cursor_key("base", FACTORY, "PairCreated")
    assert db.get_cursor(uni_key) == 500
    # Other factories may still catch up; this factory must not re-fetch.
    for filt in w3.eth.filters:
        assert str(filt.get("address") or "").lower() != FACTORY.lower()
