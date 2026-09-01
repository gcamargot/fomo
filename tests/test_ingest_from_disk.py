"""Ingest on-disk contract folders into the research DB."""

import json
from pathlib import Path

from cleanup_and_reverify_dataset import discover_disk_contracts, ingest_disk_contracts
from token_scanner_daemon import TokenScannerDB


def _tree(tmp: Path):
    eth = tmp / "ethereum" / ("0x" + "a" * 40)
    (eth / "src").mkdir(parents=True)
    (eth / "src" / "T.sol").write_text("contract T {}")
    (eth / "metadata.json").write_text(json.dumps({
        "contract_name": "T",
        "compiler_version": "0.8.20",
        "category": "ERC20_TOKEN",
        "verified": True,
    }))
    arb = tmp / "arbitrum" / ("0x" + "b" * 40)
    (arb / "src").mkdir(parents=True)
    (arb / "src" / "A.sol").write_text("// hi")
    junk = tmp / "ethereum" / "not-an-address"
    junk.mkdir(parents=True)
    (junk / "src").mkdir()
    return eth, arb


def test_discover_disk_contracts(tmp_path):
    _tree(tmp_path)
    rows = discover_disk_contracts(str(tmp_path))
    addrs = {r[0] for r in rows}
    chains = {r[1] for r in rows}
    assert "0x" + "a" * 40 in addrs
    assert "0x" + "b" * 40 in addrs
    assert "ethereum" in chains and "arbitrum" in chains
    names = {r[0]: r[2] for r in rows}
    assert names["0x" + "a" * 40] == "T"


def test_ingest_disk_contracts_inserts_verified(tmp_path):
    _tree(tmp_path)
    db_path = str(tmp_path / "t.db")
    db = TokenScannerDB(db_path)
    n = ingest_disk_contracts(db, str(tmp_path))
    assert n == 2
    rows = db.fetch_verified_rows()
    assert len(rows) == 2
    # second ingest is idempotent
    assert ingest_disk_contracts(db, str(tmp_path)) == 2
    assert len(db.fetch_verified_rows()) == 2
