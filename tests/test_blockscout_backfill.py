"""Blockscout verified-contract pagination for corpus rebuild."""

from token_scanner_daemon import (
    BLOCKSCOUT_BACKFILL_DONE,
    addresses_from_blockscout_page,
    blockscout_backfill_enabled,
)


def test_parse_page_and_next_id():
    payload = {
        "items": [
            {"address": {"hash": "0x" + "aa" * 20}},
            {"address_hash": "0x" + "bb" * 20},
        ],
        "next_page_params": {"items_count": 50, "smart_contract_id": 99},
    }
    addrs, nxt = addresses_from_blockscout_page(payload)
    assert addrs == ["0x" + "aa" * 20, "0x" + "bb" * 20]
    assert nxt == 99


def test_parse_limit_and_end_of_history():
    payload = {
        "items": [{"address": {"hash": "0x" + "11" * 20}} for _ in range(5)],
        "next_page_params": None,
    }
    addrs, nxt = addresses_from_blockscout_page(payload, limit=2)
    assert len(addrs) == 2
    assert nxt is None


def test_backfill_env_default_on(monkeypatch):
    monkeypatch.delenv("FOMO_BLOCKSCOUT_BACKFILL", raising=False)
    assert blockscout_backfill_enabled() is True
    monkeypatch.setenv("FOMO_BLOCKSCOUT_BACKFILL", "0")
    assert blockscout_backfill_enabled() is False


class _FakeResp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def json(self):
        return self._payload


def test_worker_backfill_walks_pages_and_stops(monkeypatch, tmp_path):
    from token_scanner_daemon import ChainScannerWorker, TokenScannerDB

    monkeypatch.setenv("FOMO_BLOCKSCOUT_BACKFILL", "1")
    monkeypatch.setenv("FOMO_BACKFILL_PAGES", "2")
    db = TokenScannerDB(str(tmp_path / "t.db"))
    pages = {
        None: {
            "items": [{"address": {"hash": "0x" + "01" * 20}}],
            "next_page_params": {"smart_contract_id": 50, "items_count": 50},
        },
        50: {
            "items": [{"address": {"hash": "0x" + "02" * 20}}],
            "next_page_params": {"smart_contract_id": 10, "items_count": 50},
        },
        10: {
            "items": [{"address": {"hash": "0x" + "03" * 20}}],
            "next_page_params": None,
        },
    }

    class _Sess:
        def get(self, url, params=None, timeout=15):
            scid = (params or {}).get("smart_contract_id")
            return _FakeResp(pages.get(scid, pages[None]))

    worker = ChainScannerWorker.__new__(ChainScannerWorker)
    worker.chain = "base"
    worker.db = db
    worker.evm_extractor = type("E", (), {"config": {"blockscout_v2": "http://bs"}, "session": _Sess()})()
    worker.solana_extractor = None

    first = worker.fetch_backfill_contracts(pages=2)
    assert "0x" + "02" * 20 in first
    assert "0x" + "03" * 20 in first
    assert db.get_cursor("base:blockscout:verified") == BLOCKSCOUT_BACKFILL_DONE
    assert worker.fetch_backfill_contracts() == []
