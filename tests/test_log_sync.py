"""Chunked eth_getLogs ranges and cursor math (no RPC)."""

from log_sync import chunk_block_range, next_cursor


def test_chunk_respects_max_span():
    chunks = list(chunk_block_range(100, 350, max_span=100))
    assert chunks == [(100, 199), (200, 299), (300, 350)]


def test_chunk_single_when_small():
    assert list(chunk_block_range(10, 15, max_span=2000)) == [(10, 15)]


def test_chunk_empty_when_from_after_to():
    assert list(chunk_block_range(50, 40, max_span=10)) == []


def test_next_cursor_advances_past_to_block():
    assert next_cursor(current=99, to_block=150) == 150


def test_next_cursor_does_not_go_backwards():
    assert next_cursor(current=200, to_block=150) == 200
