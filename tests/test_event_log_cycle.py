"""Log watcher cycle advances cursor and enqueues swap tokens."""

from event_log_watcher import (
    MARKET_LISTED_TOPIC0,
    SWAP_TOPIC0,
    ctokens_from_market_listed,
    run_log_watch_cycle,
)
from log_sync import cursor_key
from token_scanner_daemon import TokenScannerDB

PAIR = "0x2222222222222222222222222222222222222222"
TOKEN = "0x1111111111111111111111111111111111111111"


class _Eth:
    def __init__(self, head, logs):
        self.block_number = head
        self.logs = logs
        self.filters = []

    def get_logs(self, filt):
        self.filters.append(filt)
        return list(self.logs)


class _W3:
    def __init__(self, head, logs):
        self.eth = _Eth(head, logs)


def test_log_cycle_enqueues_token_and_advances(tmp_path):
    db = TokenScannerDB(str(tmp_path / "t.db"))
    woken = []
    w3 = _W3(head=80, logs=[{"topics": [SWAP_TOPIC0], "address": PAIR}])
    n = run_log_watch_cycle(
        db,
        {"base": w3},
        pair_to_token_by_chain={"base": {PAIR: TOKEN}},
        liq_pools_by_chain={"base": []},
        lookback=20,
        on_swap_token=lambda chain, tok: woken.append((chain, tok)),
    )
    assert n == 1
    assert woken == [("base", TOKEN)]
    key = cursor_key("base", PAIR, "Swap")
    assert db.get_cursor(key) == 80


def test_log_cycle_empty_still_moves_cursor(tmp_path):
    db = TokenScannerDB(str(tmp_path / "t.db"))
    w3 = _W3(head=30, logs=[])
    n = run_log_watch_cycle(
        db,
        {"base": w3},
        pair_to_token_by_chain={"base": {PAIR: TOKEN}},
        liq_pools_by_chain={},
        lookback=10,
    )
    assert n == 0
    assert db.get_cursor(cursor_key("base", PAIR, "Swap")) == 30


COMPTROLLER = "0x3333333333333333333333333333333333333333"
CTOKEN = "0x4444444444444444444444444444444444444444"


def test_ctokens_from_market_listed_reads_data():
    logs = [
        {
            "address": COMPTROLLER,
            "topics": [MARKET_LISTED_TOPIC0],
            "data": "0x" + CTOKEN[2:].rjust(64, "0"),
        }
    ]
    assert ctokens_from_market_listed(logs, [COMPTROLLER]) == [CTOKEN]


def test_log_cycle_market_listed_enqueues_ctoken(tmp_path):
    db = TokenScannerDB(str(tmp_path / "t.db"))
    woken = []
    w3 = _W3(
        head=90,
        logs=[
            {
                "address": COMPTROLLER,
                "topics": [MARKET_LISTED_TOPIC0],
                "data": "0x" + CTOKEN[2:].rjust(64, "0"),
            }
        ],
    )
    n = run_log_watch_cycle(
        db,
        {"base": w3},
        pair_to_token_by_chain={},
        liq_pools_by_chain={},
        lookback=20,
        comptrollers_by_chain={"base": [COMPTROLLER]},
        on_market_listed=lambda chain, tok: woken.append((chain, tok)),
    )
    assert n == 1
    assert woken == [("base", CTOKEN)]
    assert db.get_cursor(cursor_key("base", COMPTROLLER, "MarketListed")) == 90
