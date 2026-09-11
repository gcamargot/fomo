"""LAN dashboard + triage POST."""

import json

import http_api
from token_scanner_daemon import TokenScannerDB


def test_health_needs_no_db(monkeypatch, tmp_path):
    monkeypatch.setattr(http_api, "API_TOKEN", "")
    status, body, ctype = http_api.dispatch("GET", "/health")
    assert status == 200
    assert b'"ok": true' in body
    assert "json" in ctype


def test_stats_and_triage_from_tmp_db(monkeypatch, tmp_path):
    monkeypatch.setattr(http_api, "API_TOKEN", "")
    dbp = str(tmp_path / "t.db")
    qdir = tmp_path / "queue"
    qdir.mkdir()
    addr = "0x" + "ab" * 20
    db = TokenScannerDB(dbp)
    db.ensure_token_row(address=addr, chain="base", name="T", verified=True)
    db.update_token_flags(
        addr,
        {
            "is_user_exploitable": 1,
            "onchain_verified": 1,
            "expected_profit_eth": 0.4,
            "dynamic_status": "PUBLIC_SWAPBACK_ACTIVE",
        },
    )
    (qdir / f"triage_base_{addr}.md").write_text("# card\nprofit\n")
    monkeypatch.setattr(http_api, "DB_PATH", dbp)
    monkeypatch.setattr(http_api, "TRIAGE_DIR", str(qdir))
    monkeypatch.setattr(http_api, "ARCHIVE_DIR", str(tmp_path / "missing"))

    st, raw, _ = http_api.dispatch("GET", "/stats")
    assert st == 200
    assert b'"pending_review": 1' in raw

    st, raw, _ = http_api.dispatch("GET", "/triage")
    assert st == 200
    assert addr.encode() in raw

    st, raw, ctype = http_api.dispatch("GET", f"/triage/base/{addr}")
    assert st == 200
    assert "markdown" in ctype
    assert b"# card" in raw


def test_token_required(monkeypatch):
    monkeypatch.setattr(http_api, "API_TOKEN", "secret")
    st, _, _ = http_api.dispatch("GET", "/health", token="")
    assert st == 401
    st, _, _ = http_api.dispatch("GET", "/health", token="secret")
    assert st == 200


def test_dashboard_html(monkeypatch):
    monkeypatch.setattr(http_api, "API_TOKEN", "")
    st, body, ctype = http_api.dispatch("GET", "/")
    assert st == 200
    assert "text/html" in ctype
    assert b"FOMO profit pipeline" in body
    assert b"Contratos por red" in body
    assert b"setInterval(load, 30000)" in body
    assert b"by_chain" in body


def test_post_fp_archives_card_and_updates_db(monkeypatch, tmp_path):
    monkeypatch.setattr(http_api, "API_TOKEN", "")
    dbp = str(tmp_path / "t.db")
    qdir = tmp_path / "queue"
    adir = tmp_path / "archive"
    qdir.mkdir()
    addr = "0x" + "cd" * 20
    db = TokenScannerDB(dbp)
    db.ensure_token_row(address=addr, chain="base", name="T", verified=True)
    db.update_token_flags(
        addr,
        {
            "is_user_exploitable": 1,
            "expected_profit_eth": 0.4,
            "dynamic_status": "PAIR_SKIM_ACTIONABLE",
        },
    )
    (qdir / f"triage_base_{addr}.md").write_text("# hit\n")
    monkeypatch.setattr(http_api, "DB_PATH", dbp)
    monkeypatch.setattr(http_api, "TRIAGE_DIR", str(qdir))
    monkeypatch.setattr(http_api, "ARCHIVE_DIR", str(adir))
    payload = json.dumps({"verdict": "FP", "note": "phantom reserves"}).encode()
    st, raw, _ = http_api.dispatch("POST", f"/triage/base/{addr}", body=payload)
    assert st == 200
    data = json.loads(raw)
    assert data["ok"] is True
    assert data["archived"] is True
    assert data["status"].startswith("FP_")
    assert not (qdir / f"triage_base_{addr}.md").exists()
    assert (adir / f"triage_base_{addr}.md").exists()
    import sqlite3
    row = sqlite3.connect(dbp).execute(
        "SELECT dynamic_status, is_user_exploitable, expected_profit_eth FROM tokens WHERE address=?",
        (addr,),
    ).fetchone()
    assert row[0].startswith("FP_")
    assert row[1] == 0
    assert row[2] is None


def test_post_tp_keeps_exploitable(monkeypatch, tmp_path):
    monkeypatch.setattr(http_api, "API_TOKEN", "")
    dbp = str(tmp_path / "t.db")
    qdir = tmp_path / "queue"
    adir = tmp_path / "archive"
    qdir.mkdir()
    addr = "0x" + "11" * 20
    db = TokenScannerDB(dbp)
    db.ensure_token_row(address=addr, chain="base", name="T", verified=True)
    db.update_token_flags(addr, {"is_user_exploitable": 1, "expected_profit_eth": 1.2})
    (qdir / f"triage_base_{addr}.md").write_text("# tp\n")
    monkeypatch.setattr(http_api, "DB_PATH", dbp)
    monkeypatch.setattr(http_api, "TRIAGE_DIR", str(qdir))
    monkeypatch.setattr(http_api, "ARCHIVE_DIR", str(adir))
    st, raw, _ = http_api.dispatch(
        "POST", f"/triage/base/{addr}", body=b'{"verdict":"TP"}'
    )
    assert st == 200
    import sqlite3
    row = sqlite3.connect(dbp).execute(
        "SELECT dynamic_status, is_user_exploitable, expected_profit_eth FROM tokens WHERE address=?",
        (addr,),
    ).fetchone()
    assert row[0] == "TRIAGED_TP"
    assert row[1] == 1
    assert row[2] == 1.2


def test_path_traversal_rejected(monkeypatch, tmp_path):
    monkeypatch.setattr(http_api, "API_TOKEN", "")
    monkeypatch.setattr(http_api, "TRIAGE_DIR", str(tmp_path))
    monkeypatch.setattr(http_api, "ARCHIVE_DIR", str(tmp_path))
    st, _, _ = http_api.dispatch("GET", "/triage/base/../etc/passwd")
    assert st == 404
