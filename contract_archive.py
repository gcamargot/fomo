"""Cold-store verified sources as tar.gz so the corpus can run for years.

Hot set stays uncompressed under ``FOMO_SOURCE_HOT_GB`` (default 15).
Older address dirs become ``sources.tar.gz`` in place; readers open the
archive without extracting. A later save extracts first, then writes.
"""

from __future__ import annotations

import os
import tarfile
import time
from pathlib import Path
from typing import Iterable, Iterator, Optional, Set

ARCHIVE_NAME = "sources.tar.gz"
DEFAULT_HOT_GB = float(os.environ.get("FOMO_SOURCE_HOT_GB", "15"))
DEFAULT_MIN_AGE_HOURS = float(os.environ.get("FOMO_SOURCE_MIN_AGE_HOURS", "24"))


def _resolve_contracts_dir() -> str:
    """In-container corpus is /app/contracts (compose bind).

    ``FOMO_CONTRACTS_DIR`` on the host is the bind *source* (e.g. /data/fomo/contracts)
    and must not be used inside the image — that path does not exist there.
    """
    for cand in (
        os.environ.get("FOMO_CONTRACTS_INNER"),
        "./contracts",
        "/app/contracts",
    ):
        if cand and os.path.isdir(cand):
            return cand
    return os.environ.get("FOMO_CONTRACTS_INNER") or "./contracts"


DEFAULT_CONTRACTS = _resolve_contracts_dir()

SKIP_TOP = {
    "triage_queue",
    "triage_archive",
    "apps",
    "catconomics",
    "contracts",
    "rh-launchpad-contracts",
    "lost+found",
}
SOURCE_SUFFIXES = (".sol", ".rs")


def _contracts_root(base: Optional[str] = None) -> Path:
    return Path(base or DEFAULT_CONTRACTS)


def archive_path(contract_dir: Path) -> Path:
    return contract_dir / ARCHIVE_NAME


def is_archived(contract_dir: Path) -> bool:
    return archive_path(contract_dir).is_file()


def iter_contract_dirs(base: Optional[str] = None) -> Iterator[Path]:
    root = _contracts_root(base)
    if not root.is_dir():
        return
    for chain in sorted(root.iterdir()):
        if not chain.is_dir() or chain.name in SKIP_TOP or chain.name.startswith("."):
            continue
        try:
            kids = list(chain.iterdir())
        except OSError:
            continue
        for child in kids:
            if child.is_dir() and not child.name.startswith("."):
                yield child


def _file_bytes(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def uncompressed_bytes(contract_dir: Path) -> int:
    """Bytes that count toward the hot budget (not the archive itself)."""
    total = 0
    if not contract_dir.is_dir():
        return 0
    for dirpath, dirnames, filenames in os.walk(contract_dir):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fn in filenames:
            if fn == ARCHIVE_NAME or fn.startswith("."):
                continue
            total += _file_bytes(Path(dirpath) / fn)
    return total


def _mtime(contract_dir: Path) -> float:
    latest = 0.0
    try:
        latest = contract_dir.stat().st_mtime
    except OSError:
        pass
    for dirpath, dirnames, filenames in os.walk(contract_dir):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fn in filenames:
            try:
                latest = max(latest, (Path(dirpath) / fn).stat().st_mtime)
            except OSError:
                pass
    return latest


def _iter_source_files(contract_dir: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(contract_dir):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fn in filenames:
            if fn == ARCHIVE_NAME or fn.startswith("."):
                continue
            yield Path(dirpath) / fn


def archive_contract_dir(contract_dir: Path) -> bool:
    """Pack uncompressed files into sources.tar.gz and delete the originals."""
    contract_dir = Path(contract_dir)
    if not contract_dir.is_dir() or is_archived(contract_dir):
        # Already archived: still drop leftover uncompressed copies if any.
        files = list(_iter_source_files(contract_dir))
        if is_archived(contract_dir) and files:
            for p in files:
                try:
                    p.unlink()
                except OSError:
                    pass
            _prune_empty(contract_dir)
            return True
        return False
    files = list(_iter_source_files(contract_dir))
    if not files:
        return False
    dest = archive_path(contract_dir)
    tmp = contract_dir / f".{ARCHIVE_NAME}.tmp"
    try:
        with tarfile.open(tmp, "w:gz") as tar:
            for p in files:
                tar.add(p, arcname=str(p.relative_to(contract_dir)))
        os.replace(tmp, dest)
    except Exception:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    for p in files:
        try:
            p.unlink()
        except OSError:
            pass
    _prune_empty(contract_dir)
    return True


def _prune_empty(contract_dir: Path) -> None:
    for dirpath, dirnames, filenames in os.walk(contract_dir, topdown=False):
        if Path(dirpath) == contract_dir:
            continue
        try:
            os.rmdir(dirpath)
        except OSError:
            pass


def extract_archive(contract_dir: Path) -> bool:
    arch = archive_path(contract_dir)
    if not arch.is_file():
        return False
    with tarfile.open(arch, "r:gz") as tar:
        try:
            tar.extractall(contract_dir, filter="data")
        except TypeError:
            tar.extractall(contract_dir)
    try:
        arch.unlink()
    except OSError:
        pass
    return True


def prepare_contract_dir(target_dir: str) -> None:
    """Make ``target_dir`` writable (extract archive if present)."""
    p = Path(target_dir)
    p.mkdir(parents=True, exist_ok=True)
    if is_archived(p):
        extract_archive(p)


def _read_from_tar(arch: Path) -> str:
    chunks = []
    with tarfile.open(arch, "r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            name = member.name.replace("\\", "/").lower()
            if not name.endswith(SOURCE_SUFFIXES):
                continue
            fh = tar.extractfile(member)
            if fh is None:
                continue
            try:
                chunks.append(fh.read().decode("utf-8", errors="ignore"))
            except Exception:
                pass
    return "\n".join(chunks)


def _read_from_tree(contract_dir: Path) -> str:
    chunks = []
    for p in _iter_source_files(contract_dir):
        if not p.name.lower().endswith(SOURCE_SUFFIXES):
            continue
        try:
            chunks.append(p.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            pass
    return "\n".join(chunks)


def read_contract_sources(chain: str, address: str, base: Optional[str] = None) -> str:
    contract_dir = _contracts_root(base) / chain.lower() / address.lower()
    if not contract_dir.exists():
        return ""
    if is_archived(contract_dir):
        text = _read_from_tar(archive_path(contract_dir))
        if text:
            return text
    return _read_from_tree(contract_dir)


def triage_keep_addrs(base: Optional[str] = None) -> Set[str]:
    """Addresses currently in triage_queue should stay hot."""
    keep: Set[str] = set()
    qdir = _contracts_root(base) / "triage_queue"
    if not qdir.is_dir():
        return keep
    try:
        names = os.listdir(qdir)
    except OSError:
        return keep
    for name in names:
        if not name.startswith("triage_") or not name.endswith(".md"):
            continue
        stem = name[len("triage_") : -3]
        # triage_<chain>_<0xaddr>
        if "_0x" in stem:
            keep.add("0x" + stem.rsplit("_0x", 1)[-1].lower())
        else:
            keep.add(stem.lower())
    return keep


def rotate_sources(
    base: Optional[str] = None,
    *,
    hot_bytes: Optional[int] = None,
    min_age_seconds: Optional[float] = None,
    keep_addrs: Optional[Iterable[str]] = None,
    now: Optional[float] = None,
) -> dict:
    """Archive oldest uncompressed dirs until hot set fits ``hot_bytes``."""
    if hot_bytes is None:
        hot_bytes = int(DEFAULT_HOT_GB * (1024**3))
    if min_age_seconds is None:
        min_age_seconds = DEFAULT_MIN_AGE_HOURS * 3600
    now = time.time() if now is None else now
    keep = {a.lower() for a in (keep_addrs if keep_addrs is not None else triage_keep_addrs(base))}

    candidates = []
    hot_total = 0
    archived_already = 0
    for d in iter_contract_dirs(base):
        size = uncompressed_bytes(d)
        if size <= 0:
            archived_already += 1
            continue
        hot_total += size
        addr = d.name.lower()
        age = now - _mtime(d)
        candidates.append((age, size, d, addr))

    candidates.sort()  # oldest first: large age first? age is first field, small age = newer
    # We want oldest (largest age) first for archival.
    candidates.sort(key=lambda t: t[0], reverse=True)

    archived = 0
    freed = 0
    skipped_young = 0
    skipped_keep = 0
    for age, size, d, addr in candidates:
        if hot_total <= hot_bytes:
            break
        if addr in keep:
            skipped_keep += 1
            continue
        if age < min_age_seconds:
            skipped_young += 1
            continue
        if archive_contract_dir(d):
            archived += 1
            freed += size
            hot_total -= size

    return {
        "hot_bytes": hot_total,
        "hot_limit": hot_bytes,
        "archived": archived,
        "freed_bytes": freed,
        "already_archived": archived_already,
        "skipped_young": skipped_young,
        "skipped_keep": skipped_keep,
    }
