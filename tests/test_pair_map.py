"""Build pair→token maps from watchlist snapshots."""

import json

from event_log_watcher import load_pair_maps, pair_map_from_rows, wakeup_from_swap
from token_scanner_daemon import TokenScannerDB


def test_pair_map_from_snapshot_json():
    rows = [
        {
            "address": "0x" + "1" * 40,
            "chain": "base",
            "has_public_swapback": 1,
            "state_snapshot": '{"pair": "0x2222222222222222222222222222222222222222"}',
        },
        {
            "address": "0x" + "3" * 40,
            "chain": "base",
            "has_zero_slippage": 1,
            "state_snapshot": None,
        },
    ]
    m = pair_map_from_rows(rows)
    assert "base" in m
    pair = "0x2222222222222222222222222222222222222222"
    assert m["base"][pair] == "0x" + "1" * 40


def test_load_pair_maps_from_db(tmp_path):
    db = TokenScannerDB(str(tmp_path / "t.db"))
    addr = "0x" + "1" * 40
    pair = "0x2222222222222222222222222222222222222222"
    db.ensure_token_row(address=addr, chain="base", name="T", verified=True)
    db.update_token_flags(
        addr,
        {
            "has_public_swapback": 1,
            "state_snapshot": json.dumps({"pair": pair, "pool_eth": 1.0}),
        },
    )
    m = load_pair_maps(db)
    assert m["base"][pair] == addr


def test_wakeup_from_swap_passes_row_to_checker(tmp_path):
    db = TokenScannerDB(str(tmp_path / "t.db"))
    addr = "0x" + "a" * 40
    db.ensure_token_row(address=addr, chain="base", name="T", verified=True)
    db.update_token_flags(addr, {"has_zero_slippage": 1})
    seen = []
    ok = wakeup_from_swap(db, "base", addr, lambda row: seen.append(row) or True)
    assert ok is True
    assert seen[0]["address"] == addr
    assert seen[0]["chain"] == "base"


def test_wakeup_from_swap_swallows_checker_errors():
    assert wakeup_from_swap(None, "base", "0x" + "b" * 40, lambda r: (_ for _ in ()).throw(RuntimeError("x"))) is False
