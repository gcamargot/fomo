"""Schema migrations for watchlist / profit columns."""

import os
import tempfile

from token_scanner_daemon import TokenScannerDB


def test_init_db_adds_watchlist_columns():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        db = TokenScannerDB(path)
        with db.get_connection() as conn:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(tokens)")}
        for col in (
            "expected_profit_eth",
            "last_checked_at",
            "next_check_at",
            "watch_bucket",
            "state_snapshot",
            "eth_balance",
            "has_public_swapback",
        ):
            assert col in cols, col
        db.save_scan({
            "address": "0x" + "f" * 40,
            "expected_profit_eth": 0.42,
            "verified": True,
        })
        with db.get_connection() as conn:
            row = conn.execute(
                "SELECT expected_profit_eth FROM tokens WHERE address = ?",
                ("0x" + "f" * 40,),
            ).fetchone()
        assert row is not None
        assert abs(float(row[0]) - 0.42) < 1e-9
        tables = {r[0] for r in db.get_connection().execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        assert "sync_cursors" in tables
        db.set_cursor("base:univ2:PairCreated", 123)
        assert db.get_cursor("base:univ2:PairCreated") == 123
        assert db.get_cursor("missing", default=7) == 7
    finally:
        os.unlink(path)
        for extra in (path + "-wal", path + "-shm"):
            if os.path.exists(extra):
                os.unlink(extra)
