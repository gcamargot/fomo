"""Optional Foundry fork profit gate (off in CI unless FOMO_FORK_GATE=1)."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

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
        "testProfitPositive",
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


def should_emit_triage(
    *,
    is_active: bool,
    confirmed: List[Dict],
    fork_result: ForkGateResult,
) -> bool:
    if not (is_active and confirmed):
        return False
    return bool(fork_result.passed)
