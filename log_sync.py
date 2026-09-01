"""HTTP log-range helpers: chunked from/to blocks and cursor advance."""

from __future__ import annotations

from typing import Iterator, Tuple


def chunk_block_range(
    from_block: int,
    to_block: int,
    *,
    max_span: int = 2000,
) -> Iterator[Tuple[int, int]]:
    """Yield inclusive [start, end] chunks covering [from_block, to_block]."""
    if from_block > to_block or max_span < 1:
        return
    start = from_block
    while start <= to_block:
        end = min(to_block, start + max_span - 1)
        yield start, end
        start = end + 1


def next_cursor(current: int, to_block: int) -> int:
    """Cursor is the last processed block (inclusive)."""
    return max(int(current), int(to_block))


def cursor_key(chain: str, factory: str, event: str) -> str:
    return f"{chain.lower()}:{factory.lower()}:{event}"


def normalize_log(log) -> dict:
    """Coerce web3 AttributeDict / HexBytes logs into plain hex strings."""
    if not isinstance(log, dict):
        try:
            log = dict(log)
        except Exception:
            log = {"topics": getattr(log, "topics", []), "address": getattr(log, "address", ""), "data": getattr(log, "data", "0x")}

    def _hex(val) -> str:
        if val is None:
            return "0x"
        if hasattr(val, "hex") and not isinstance(val, str):
            h = val.hex()
            return h if str(h).startswith("0x") else "0x" + str(h)
        s = str(val)
        return s if s.startswith("0x") else "0x" + s

    topics = [_hex(t) for t in (log.get("topics") or [])]
    addr = _hex(log.get("address") or "0x")
    if len(addr) > 42:
        addr = "0x" + addr[-40:]
    return {
        "topics": topics,
        "address": addr.lower(),
        "data": _hex(log.get("data") or "0x"),
    }
