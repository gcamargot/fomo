// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// Foundry Vm subset (simulations/ has no forge-std).
interface Vm {
    function envOr(string calldata name, address defaultValue) external view returns (address);
    function envOr(string calldata name, uint256 defaultValue) external view returns (uint256);
    function prank(address msgSender) external;
}

/// Pre-0.8 style balance update, compiled with unchecked math so the probe
/// can run under 0.8. Not a swap-out.
contract RawOverflowToken {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 value) public returns (bool) {
        unchecked {
            balances[msg.sender] -= value;
            balances[to] += value;
        }
        return true;
    }
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

    /// Fork probe for BALANCE_OVERFLOW. No target → pass (CI).
    /// transfer(other, 1) from an empty EOA must underflow the caller.
    /// It does not sell into a pair.
    function testOverflowCandidate() public {
        address target = vm.envOr("FOMO_TARGET", address(0));
        if (target == address(0)) {
            return;
        }
        require(target.code.length > 0, "FOMO_TARGET has no code");
        address attacker = address(0x00000000000000000000000000000000000A11cE);
        address bob = address(0x0000000000000000000000000000000000000B0b);
        vm.prank(attacker);
        (bool ok,) = target.call(
            abi.encodeWithSignature("transfer(address,uint256)", bob, uint256(1))
        );
        require(ok, "transfer(1) reverted");
        (bool bok, bytes memory ret) = target.staticcall(
            abi.encodeWithSignature("balanceOf(address)", attacker)
        );
        require(bok && ret.length >= 32, "balanceOf failed");
        require(abi.decode(ret, (uint256)) > 1000 ether, "caller balance did not underflow");
    }

    function testLocalOverflowProbe() public {
        RawOverflowToken token = new RawOverflowToken();
        address attacker = address(0x00000000000000000000000000000000000A11cE);
        address bob = address(0x0000000000000000000000000000000000000B0b);
        vm.prank(attacker);
        require(token.transfer(bob, 1), "local transfer failed");
        require(token.balances(attacker) == type(uint256).max, "local underflow missing");
    }
}
