"""Log watcher cycle advances cursor and enqueues swap tokens."""

from event_log_watcher import SWAP_TOPIC0, run_log_watch_cycle
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
