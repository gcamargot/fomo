// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// Local invariant: a stale view price during a callback over-values collateral.
/// Not a mainnet payload — anvil-only, no FOMO_TARGET.
contract StaleVirtualPricePool {
    uint256 public vp = 1e18;
    bool public stale;

    function setStale(bool v) external {
        stale = v;
    }

    function get_virtual_price() external view returns (uint256) {
        return stale ? 2e18 : vp;
    }
}

contract UnlockedLpVault {
    StaleVirtualPricePool public pool;

    constructor(StaleVirtualPricePool p) payable {
        pool = p;
    }

    function totalAssets() public view returns (uint256) {
        return pool.get_virtual_price();
    }

    function borrow() external {
        uint256 credit = totalAssets() / 2;
        payable(msg.sender).transfer(credit);
    }

    receive() external payable {}
}

interface Vm {
    function deal(address who, uint256 amount) external;
}

contract ReadOnlyReentrancyTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function test_stale_view_lets_borrow_more_than_fair() public {
        vm.deal(address(this), 2 ether);
        StaleVirtualPricePool pool = new StaleVirtualPricePool();
        UnlockedLpVault vault = new UnlockedLpVault{value: 1 ether}(pool);

        pool.setStale(false);
        uint256 fair = address(vault).balance;
        require(fair == 1 ether, "prefund");

        pool.setStale(true);
        uint256 before = address(this).balance;
        vault.borrow();
        uint256 got = address(this).balance - before;
        // stale vp=2e18 → credit = 1 ether (double the fair 0.5)
        require(got == 1 ether, "stale view should double borrowable ETH");
    }

    receive() external payable {}
}
