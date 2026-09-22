"""Optional Foundry fork profit gate (off in CI unless FOMO_FORK_GATE=1)."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

SIMULATIONS_DIR = Path(__file__).resolve().parent / "simulations"

_FALLBACK_RPC = {
    "base": "https://mainnet.base.org",
    "arbitrum": "https://arb1.arbitrum.io/rpc",
    "ethereum": "https://ethereum-rpc.publicnode.com",
}


@dataclass(frozen=True)
class ForkGateResult:
    passed: bool
    skipped: bool
    reason: str
    stdout: str = ""
    stderr: str = ""


def fork_gate_enabled() -> bool:
    raw = os.environ.get("FOMO_FORK_GATE", "0").strip().lower()
    return raw not in {"0", "false", "no", "off", ""}


def _pick_rpc(chain: str, rpc_url: Optional[str]) -> str:
    if rpc_url:
        return rpc_url
    env_key = f"{chain.upper()}_RPC_URL"
    if os.environ.get(env_key):
        return os.environ[env_key]
    return _FALLBACK_RPC.get(chain.lower(), "")


def run_fork_profit_test(
    address: str,
    chain: str,
    *,
    rpc_url: Optional[str] = None,
    runner: Optional[Callable[..., Any]] = None,
    timeout: int = 120,
    cwd: Optional[Path] = None,
    match_test: str = "testProfitPositive",
) -> ForkGateResult:
    """Run `forge test --match-test testProfitPositive` against a fork.

    `runner` is injectable (tests pass a fake). Default: subprocess.run.
    """
    if not fork_gate_enabled():
        return ForkGateResult(passed=True, skipped=True, reason="disabled")

    rpc = _pick_rpc(chain, rpc_url)
    if not rpc:
        return ForkGateResult(passed=False, skipped=False, reason="no_rpc")

    run = runner or subprocess.run
    env = os.environ.copy()
    env["FOMO_TARGET"] = address
    env["FOMO_FORK_URL"] = rpc
    env["FOMO_CHAIN"] = chain
    cmd = [
        "forge",
        "test",
        "--match-test",
        match_test,
        "--fork-url",
        rpc,
        "-vv",
    ]
    workdir = str(cwd or SIMULATIONS_DIR)
    try:
        proc = run(
            cmd,
            cwd=workdir,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return ForkGateResult(passed=False, skipped=False, reason="timeout")
    except FileNotFoundError:
        return ForkGateResult(passed=False, skipped=False, reason="forge_missing")

    code = getattr(proc, "returncode", 1)
    stdout = getattr(proc, "stdout", "") or ""
    stderr = getattr(proc, "stderr", "") or ""
    if code == 0:
        return ForkGateResult(passed=True, skipped=False, reason="ok", stdout=stdout, stderr=stderr)
    return ForkGateResult(
        passed=False,
        skipped=False,
        reason=f"forge_exit_{code}",
        stdout=stdout,
        stderr=stderr,
    )


def run_fork_overflow_test(
    address: str,
    chain: str,
    *,
    rpc_url: Optional[str] = None,
    runner: Optional[Callable[..., Any]] = None,
    timeout: int = 120,
    cwd: Optional[Path] = None,
) -> ForkGateResult:
    """Fork-only probe: ``transfer(max)`` credits the caller. Not a swap-out."""
    return run_fork_profit_test(
        address,
        chain,
        rpc_url=rpc_url,
        runner=runner,
        timeout=timeout,
        cwd=cwd,
        match_test="testOverflowCandidate",
    )


def split_fork_gated(
    confirmed: List[Dict],
    plain_fork: ForkGateResult,
    overflow_fork: ForkGateResult,
) -> Tuple[List[Dict], List[str]]:
    """Keep plain hits when the generic fork is off. Overflow needs a real run.

    ``requires_live_fork`` items stay out of the queue when the overflow test
    was skipped (``FOMO_FORK_GATE`` off) or failed.
    """
    emit: List[Dict] = []
    notes: List[str] = []
    for exp in confirmed:
        if exp.get("requires_live_fork"):
            if overflow_fork.passed and not overflow_fork.skipped:
                emit.append(exp)
            else:
                note = f"OVERFLOW_FORK_{(overflow_fork.reason or 'disabled').upper()}"
                if note not in notes:
                    notes.append(note)
        elif plain_fork.passed:
            emit.append(exp)
        else:
            note = f"FORK_GATE_{(plain_fork.reason or 'fail').upper()}"
            if note not in notes:
                notes.append(note)
    return emit, notes


def should_emit_triage(
    *,
    is_active: bool,
    confirmed: List[Dict],
    fork_result: ForkGateResult,
) -> bool:
    if not (is_active and confirmed):
        return False
    return bool(fork_result.passed)
