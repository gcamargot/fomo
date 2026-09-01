// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// Hook for FOMO_FORK_GATE. simulations/ has no forge-std, so this is a
/// no-op that always passes in CI. The Python orchestrator (`fork_profit_gate.py`)
/// treats a non-zero `forge test` exit as FAIL. Swap in a per-target PoC when
/// FOMO_FORK_GATE=1 on a machine with a fork RPC.
contract ProfitGateTemplate {
    function testProfitPositive() public pure {
        // Intentionally empty: default CI must stay deterministic / offline.
    }
}
