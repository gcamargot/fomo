"""Fork profit-gate orchestrator (subprocess mocked; no live RPC)."""

import subprocess
from types import SimpleNamespace

import fork_profit_gate as fpg


def _proc(code, stdout="ok", stderr=""):
    return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)


def test_fork_gate_disabled_is_skipped(monkeypatch):
    monkeypatch.setenv("FOMO_FORK_GATE", "0")
    result = fpg.run_fork_profit_test("0xabc", "ethereum", runner=lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not run")))
    assert result.skipped is True
    assert result.passed is True
    assert result.reason == "disabled"


def test_fork_gate_pass(monkeypatch):
    monkeypatch.setenv("FOMO_FORK_GATE", "1")
    calls = []

    def runner(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return _proc(0, stdout="PASS")

    result = fpg.run_fork_profit_test(
        "0x" + "1" * 40,
        "base",
        rpc_url="https://example.invalid",
        runner=runner,
    )
    assert result.passed is True
    assert result.skipped is False
    assert "testProfitPositive" in " ".join(calls[0][0])
    assert calls[0][1]["env"]["FOMO_TARGET"].startswith("0x")
    assert calls[0][1]["env"]["FOMO_FORK_URL"] == "https://example.invalid"


def test_fork_gate_fail_nonzero(monkeypatch):
    monkeypatch.setenv("FOMO_FORK_GATE", "1")
    result = fpg.run_fork_profit_test(
        "0xabc", "ethereum", rpc_url="https://rpc",
        runner=lambda *a, **k: _proc(1, stderr="revert"),
    )
    assert result.passed is False
    assert "fail" in result.reason.lower() or result.reason == "forge_exit_1"


def test_fork_gate_timeout(monkeypatch):
    monkeypatch.setenv("FOMO_FORK_GATE", "1")

    def runner(*a, **k):
        raise subprocess.TimeoutExpired(cmd="forge", timeout=1)

    result = fpg.run_fork_profit_test("0xabc", "ethereum", rpc_url="https://rpc", runner=runner)
    assert result.passed is False
    assert result.reason == "timeout"


def test_should_emit_triage_requires_fork_pass():
    ok = SimpleNamespace(passed=True, skipped=False, reason="ok")
    bad = SimpleNamespace(passed=False, skipped=False, reason="forge_exit_1")
    skip = SimpleNamespace(passed=True, skipped=True, reason="disabled")
    assert fpg.should_emit_triage(is_active=True, confirmed=[{}], fork_result=ok) is True
    assert fpg.should_emit_triage(is_active=True, confirmed=[{}], fork_result=bad) is False
    assert fpg.should_emit_triage(is_active=True, confirmed=[{}], fork_result=skip) is True
    assert fpg.should_emit_triage(is_active=False, confirmed=[], fork_result=ok) is False
