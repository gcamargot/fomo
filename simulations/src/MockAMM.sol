// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract MockWETH {
    string public name = "Wrapped Ether";
    uint8 public decimals = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
    }

    function mint(address to, uint256 amount) public {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Balance low");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        if (msg.sender != from && allowance[from][msg.sender] != type(uint256).max) {
            require(allowance[from][msg.sender] >= amount, "Allowance low");
            allowance[from][msg.sender] -= amount;
        }
        require(balanceOf[from] >= amount, "Balance low");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract MockAMM {
    uint256 public reserveToken;
    uint256 public reserveETH;
    address public immutable WETH;

    constructor() {
        MockWETH weth = new MockWETH();
        WETH = address(weth);
        reserveToken = 100_000 ether;
        reserveETH = 10 ether; // Initial price: 1 ETH = 10,000 Tokens
    }

    receive() external payable {}

    function setReserves(uint256 _tokenRes, uint256 _ethRes) external {
        reserveToken = _tokenRes;
        reserveETH = _ethRes;
    }

    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut) public pure returns (uint256) {
        uint256 amountInWithFee = amountIn * 997;
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = (reserveIn * 1000) + amountInWithFee;
        return numerator / denominator;
    }

    // Vulnerable execution without enforcing price boundary
    function swapExactTokensForETHSupportingFeeOnTransferTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 /* deadline */
    ) external {
        uint256 ethOut = getAmountOut(amountIn, reserveToken, reserveETH);
        require(ethOut >= amountOutMin, "Slippage: amountOutMin violated");
        
        reserveToken += amountIn;
        reserveETH -= ethOut;
        
        (bool success, ) = payable(to).call{value: ethOut}("");
        require(success, "ETH transfer failed");
    }
}
