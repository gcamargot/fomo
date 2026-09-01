// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// Foundry Vm subset (simulations/ has no forge-std).
interface Vm {
    function envOr(string calldata name, address defaultValue) external view returns (address);
    function envOr(string calldata name, uint256 defaultValue) external view returns (uint256);
}

/// Hook for FOMO_FORK_GATE (`forge test --match-test testProfitPositive`).
///
/// CI / offline: FOMO_TARGET unset → no-op pass.
/// Fork: FOMO_TARGET must have code. Optional FOMO_MIN_PROFIT_WEI requires
/// attacker ETH after `_runAttack` to be at least that floor.
contract ProfitGateTemplate {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function testProfitPositive() public {
        address target = vm.envOr("FOMO_TARGET", address(0));
        if (target == address(0)) {
            return;
        }
        require(target.code.length > 0, "FOMO_TARGET has no code");

        address attacker = vm.envOr("FOMO_ATTACKER", address(this));
        uint256 ethBefore = attacker.balance;
        _runAttack(target, attacker);
        uint256 ethAfter = attacker.balance;
        uint256 profit = ethAfter > ethBefore ? ethAfter - ethBefore : 0;
        uint256 minProfit = vm.envOr("FOMO_MIN_PROFIT_WEI", uint256(0));
        if (minProfit > 0) {
            require(profit >= minProfit, "attacker ETH profit below FOMO_MIN_PROFIT_WEI");
        }
    }

    /// Override in a per-target PoC. Default is a no-op measurement hook.
    function _runAttack(address target, address attacker) internal virtual {}
}
