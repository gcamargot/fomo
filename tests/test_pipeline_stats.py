"""Pipeline dashboard stats: hits / watchlist / factory — not detector soup."""

import json

from pipeline_stats import collect_pipeline_stats
from token_scanner_daemon import TokenScannerDB


def _row(db, addr, chain="base", verified=True, **flags):
    db.ensure_token_row(address=addr, chain=chain, name="T", verified=verified)
    if flags:
        db.update_token_flags(addr, flags)


def test_empty_db_has_zero_hits_and_no_detector_metrics(tmp_path):
    db = TokenScannerDB(str(tmp_path / "t.db"))
    qdir = tmp_path / "queue"
    qdir.mkdir()
    with db.get_connection() as conn:
        stats = collect_pipeline_stats(conn, triage_dir=str(qdir))
    assert stats["corpus"]["total"] == 0
    assert stats["hits"]["pending_review"] == 0
    assert stats["hits"]["confirmed"] == 0
    assert stats["watchlist"] == {
        "near_miss": 0,
        "sleeping_tax": 0,
        "unfunded_drain": 0,
    }
    assert "metrics" not in stats
    assert "honeypot" not in json.dumps(stats).lower()


def test_dashboard_splits_hit_watchlist_factory(tmp_path):
    db = TokenScannerDB(str(tmp_path / "t.db"))
    qdir = tmp_path / "queue"
    qdir.mkdir()
    hit = "0x" + "1" * 40
    miss = "0x" + "2" * 40
    sleep = "0x" + "3" * 40
    drain = "0x" + "4" * 40
    dust = "0x" + "5" * 40
    _row(
        db,
        hit,
        is_user_exploitable=1,
        onchain_verified=1,
        expected_profit_eth=0.4,
        dynamic_status="PUBLIC_SWAPBACK_ACTIVE",
        has_public_swapback=1,
        triage_file_path=str(qdir / f"triage_base_{hit}.md"),
    )
    (qdir / f"triage_base_{hit}.md").write_text("# card\n")
    _row(
        db,
        miss,
        expected_profit_eth=0.02,
        dynamic_status="PROFIT_BELOW_THRESHOLD_XYK_0.0200ETH",
        has_public_swapback=1,
    )
    _row(db, sleep, has_zero_slippage=1, dynamic_status="SWAPBACK_DISABLED")
    _row(db, drain, has_unprotected_critical_function=1, eth_balance=0.0)
    _row(
        db,
        dust,
        verified=False,
        dynamic_status="FACTORY_NEW_PAIR_DUST",
        expected_profit_eth=0.0,
    )

    with db.get_connection() as conn:
        stats = collect_pipeline_stats(conn, triage_dir=str(qdir), min_profit_eth=0.05)

    assert stats["hits"]["pending_review"] == 1
    assert stats["hits"]["confirmed"] == 1
    assert stats["hits"]["profit_pass"] == 1
    assert stats["watchlist"]["near_miss"] == 1
    assert stats["watchlist"]["sleeping_tax"] == 1
    assert stats["watchlist"]["unfunded_drain"] == 1
    assert stats["factory"]["dust"] == 1
    assert stats["factory"]["no_source"] == 0
    assert stats["inventory"] == {"public_swapback": 2, "zero_slippage": 1}
    top = stats["top_expected_profit"]
    assert top[0]["address"] == hit
    assert abs(top[0]["expected_profit_eth"] - 0.4) < 1e-9
    assert stats["hits"]["queue"][0]["address"] == hit
    assert stats["hits"]["queue"][0]["expected_profit_eth"] == 0.4


def test_factory_status_buckets(tmp_path):
    db = TokenScannerDB(str(tmp_path / "t.db"))
    _row(db, "0x" + "a" * 40, verified=False, dynamic_status="FACTORY_NEW_PAIR_NO_SOURCE")
    _row(db, "0x" + "b" * 40, verified=False, dynamic_status="FACTORY_NEW_PAIR_DUST")
    _row(
        db,
        "0x" + "c" * 40,
        dynamic_status="FACTORY_NEW_PAIR_ACTIONABLE",
        expected_profit_eth=0.2,
        has_public_swapback=1,
    )
    with db.get_connection() as conn:
        stats = collect_pipeline_stats(conn, triage_dir=str(tmp_path / "empty"))
    assert stats["factory"] == {"no_source": 1, "dust": 1, "actionable": 1, "total": 3}


def test_dashboard_ignores_tx_origin_permit_inventory(tmp_path):
    db = TokenScannerDB(str(tmp_path / "t.db"))
    _row(db, "0x" + "d" * 40, has_tx_origin_auth=1, has_permit_no_nonce=1)
    _row(db, "0x" + "e" * 40, has_unprotected_initializer=1)
    with db.get_connection() as conn:
        stats = collect_pipeline_stats(conn, triage_dir=str(tmp_path / "q"))
    assert stats["watchlist"]["unfunded_drain"] == 1
