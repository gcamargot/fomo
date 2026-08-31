// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "../src/MockAMM.sol";

contract SlippageComparisonTest {
    MockAMM public amm;
    
    event TestResult(string scenario, uint256 tokensSold, uint256 ethReceived, string securityStatus);

    function setUp() public {
        amm = new MockAMM();
        payable(address(amm)).transfer(50 ether);
    }

    receive() external payable {}

    // Case 1: Normal Swap (Baseline)
    function test_01_NormalSwap() public {
        uint256 tokensToSell = 1_000 ether; // Selling 1,000 tokens
        uint256 ethBefore = address(this).balance;
        
        address[] memory path = new address[](2);
        path[0] = address(0x123);
        path[1] = amm.WETH();

        // Standard swap with normal pool state
        amm.swapExactTokensForETHSupportingFeeOnTransferTokens(
            tokensToSell,
            0, // amountOutMin = 0
            path,
            address(this),
            block.timestamp
        );

        uint256 received = address(this).balance - ethBefore;
        emit TestResult("Normal Market Conditions", tokensToSell, received, "Expected Market Price");
        require(received > 0.09 ether, "Normal swap yielded less than expected");
    }

    // Case 2: Unprotected Swap during High Price Impact (Vulnerable: amountOutMin = 0)
    function test_02_VulnerableSwap_ZeroSlippageProtection() public {
        uint256 tokensToSell = 1_000 ether;
        
        // Simulate altered pool reserves (e.g. temporary imbalance)
        amm.setReserves(1_000_000 ether, 1 ether); // Price collapsed 100x

        uint256 ethBefore = address(this).balance;
        address[] memory path = new address[](2);
        path[0] = address(0x123);
        path[1] = amm.WETH();

        // Contract executes with amountOutMin = 0
        amm.swapExactTokensForETHSupportingFeeOnTransferTokens(
            tokensToSell,
            0, // <-- VULNERABLE: accepts any price
            path,
            address(this),
            block.timestamp
        );

        uint256 received = address(this).balance - ethBefore;
        emit TestResult("High Price Impact (No Slippage Bound)", tokensToSell, received, "SEVERE VALUE LOSS (99% Drained)");
        // Contract lost ~99% of its expected value for the treasury!
        require(received < 0.002 ether, "Expected severe value loss due to zero slippage bound");
    }

    // Case 3: Protected Swap with Enforced Minimum Out (Defensive Mitigation)
    function test_03_ProtectedSwap_RevertsOnExcessiveSlippage() public {
        uint256 tokensToSell = 1_000 ether;
        amm.setReserves(1_000_000 ether, 1 ether); // Pool is desynchronized

        address[] memory path = new address[](2);
        path[0] = address(0x123);
        path[1] = amm.WETH();

        // Enforce TWAP-derived floor: expect at least 0.08 ETH (allowing max 20% variance)
        uint256 minAcceptableEth = 0.08 ether;

        try amm.swapExactTokensForETHSupportingFeeOnTransferTokens(
            tokensToSell,
            minAcceptableEth, // <-- DEFENSIVE: slippage threshold enforced
            path,
            address(this),
            block.timestamp
        ) {
            revert("Should not have executed at bad price");
        } catch Error(string memory reason) {
            emit TestResult("Protected Swap Attempt", tokensToSell, 0, string.concat("REVERTED SAFELY: ", reason));
        }
    }
}
