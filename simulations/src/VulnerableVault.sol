// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "./MockAMM.sol";

// Minimal ERC-4626 style vault without virtual shares (VULNERABLE TO INFLATION ATTACK)
contract VulnerableVault {
    MockWETH public immutable asset;
    uint256 public totalShares;

    mapping(address => uint256) public balanceOf;

    constructor(address _asset) {
        asset = MockWETH(_asset);
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
        if (totalShares == 0) {
            shares = assets;
        } else {
            // Integer division truncation vulnerability
            shares = (assets * totalShares) / totalAssets();
        }

        require(shares > 0, "Zero shares minted");

        require(asset.transferFrom(msg.sender, address(this), assets), "Transfer in failed");
        
        totalShares += shares;
        balanceOf[receiver] += shares;
    }

    function redeem(uint256 shares, address receiver) public returns (uint256 assets) {
        require(balanceOf[msg.sender] >= shares, "Insufficient shares");
        
        assets = (shares * totalAssets()) / totalShares;
        
        totalShares -= shares;
        balanceOf[msg.sender] -= shares;

        require(asset.transfer(receiver, assets), "Transfer out failed");
    }
}

// SECURE VAULT IMPLEMENTING VIRTUAL SHARES / VIRTUAL ASSETS OFFSET
contract SecureVault {
    MockWETH public immutable asset;
    uint256 public totalShares;
    uint256 private constant VIRTUAL_OFFSET = 1e3; // Virtual shares & assets offset

    mapping(address => uint256) public balanceOf;

    constructor(address _asset) {
        asset = MockWETH(_asset);
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
        // Enforce virtual shares offset to eliminate inflation rounding exploit
        shares = (assets * (totalShares + VIRTUAL_OFFSET)) / (totalAssets() + 1);

        require(shares > 0, "Zero shares minted");
        require(asset.transferFrom(msg.sender, address(this), assets), "Transfer in failed");
        
        totalShares += shares;
        balanceOf[receiver] += shares;
    }

    function redeem(uint256 shares, address receiver) public returns (uint256 assets) {
        require(balanceOf[msg.sender] >= shares, "Insufficient shares");
        
        assets = (shares * (totalAssets() + 1)) / (totalShares + VIRTUAL_OFFSET);
        
        totalShares -= shares;
        balanceOf[msg.sender] -= shares;

        require(asset.transfer(receiver, assets), "Transfer out failed");
    }
}
