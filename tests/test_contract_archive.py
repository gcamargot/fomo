"""Contract source rotation: hot dirs stay raw, cold dirs stay readable."""

from pathlib import Path

from contract_archive import (
    ARCHIVE_NAME,
    archive_contract_dir,
    is_archived,
    prepare_contract_dir,
    read_contract_sources,
    rotate_sources,
    uncompressed_bytes,
)
def _write_contract(root: Path, chain: str, addr: str, src: str, *, mtime: float | None = None) -> Path:
    d = root / chain / addr.lower()
    (d / "src").mkdir(parents=True, exist_ok=True)
    sol = d / "src" / "Token.sol"
    sol.write_text(src, encoding="utf-8")
    (d / "metadata.json").write_text('{"name":"Token"}', encoding="utf-8")
    if mtime is not None:
        os_utime = __import__("os").utime
        os_utime(sol, (mtime, mtime))
        os_utime(d, (mtime, mtime))
    return d


def test_archive_then_read_without_extract(tmp_path: Path):
    src = "pragma solidity ^0.8.0; contract T { function x() external {} }"
    d = _write_contract(tmp_path, "base", "0xabc", src)
    assert archive_contract_dir(d) is True
    assert is_archived(d)
    assert (d / ARCHIVE_NAME).is_file()
    assert not (d / "src" / "Token.sol").exists()
    assert uncompressed_bytes(d) == 0
    got = read_contract_sources("base", "0xabc", base=str(tmp_path))
    assert "contract T" in got
    assert "function x" in got


def test_load_saved_source_reads_archive(tmp_path, monkeypatch):
    import contract_archive as ca
    import token_scanner_daemon as tsd

    monkeypatch.setattr(ca, "DEFAULT_CONTRACTS", str(tmp_path))
    src = "pragma solidity ^0.8.20; contract Hot {}"
    d = _write_contract(tmp_path, "ethereum", "0xdead", src)
    archive_contract_dir(d)
    assert "contract Hot" in tsd.load_saved_source("ethereum", "0xdead")


def test_prepare_extracts_for_rewrite(tmp_path: Path):
    src = "contract Old {}"
    d = _write_contract(tmp_path, "base", "0x111", src)
    archive_contract_dir(d)
    prepare_contract_dir(str(d))
    assert not is_archived(d)
    assert (d / "src" / "Token.sol").read_text() == src


def test_rotate_archives_oldest_until_hot_cap(tmp_path: Path):
    now = 2_000_000_000.0
    old = now - 10 * 86400
    young = now - 60
    a = _write_contract(tmp_path, "base", "0xaaa", "contract A { uint256 x; }" * 50, mtime=old)
    b = _write_contract(tmp_path, "base", "0xbbb", "contract B { uint256 y; }" * 50, mtime=old)
    c = _write_contract(tmp_path, "base", "0xccc", "contract C { uint256 z; }" * 50, mtime=young)
    hot = uncompressed_bytes(a)  # keep about one dir
    stats = rotate_sources(
        str(tmp_path),
        hot_bytes=hot + 10,
        min_age_seconds=3600,
        keep_addrs=set(),
        now=now,
    )
    assert stats["archived"] >= 1
    assert is_archived(a) or is_archived(b)
    assert not is_archived(c)
    # still readable
    for addr in ("0xaaa", "0xbbb", "0xccc"):
        text = read_contract_sources("base", addr, base=str(tmp_path))
        assert "contract" in text


def test_resolve_skips_missing_host_bind_path(tmp_path, monkeypatch):
    import contract_archive as ca

    monkeypatch.setenv("FOMO_CONTRACTS_DIR", "/data/fomo/contracts")
    monkeypatch.delenv("FOMO_CONTRACTS_INNER", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "contracts").mkdir()
    assert ca._resolve_contracts_dir() == "./contracts"


def test_rotate_skips_triage_queue_addrs(tmp_path: Path):
    now = 2_000_000_000.0
    old = now - 10 * 86400
    d = _write_contract(tmp_path, "base", "0xkeepme", "contract Keep {}", mtime=old)
    q = tmp_path / "triage_queue"
    q.mkdir()
    (q / "triage_base_0xkeepme.md").write_text("x")
    stats = rotate_sources(
        str(tmp_path),
        hot_bytes=1,
        min_age_seconds=3600,
        now=now,
    )
    assert stats["skipped_keep"] >= 1
    assert not is_archived(d)
    assert uncompressed_bytes(d) > 0
