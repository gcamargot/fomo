from web3 import Web3

w3 = Web3(Web3.HTTPProvider("https://mainnet.base.org"))

PAIR_ABI = [
    {"constant":True,"inputs":[],"name":"getReserves","outputs":[{"name":"_reserve0","type":"uint112"},{"name":"_reserve1","type":"uint112"},{"name":"_blockTimestampLast","type":"uint32"}],"type":"function"},
    {"constant":True,"inputs":[],"name":"token0","outputs":[{"name":"","type":"address"}],"type":"function"},
    {"constant":True,"inputs":[],"name":"token1","outputs":[{"name":"","type":"address"}],"type":"function"}
]

WETH_BASE = w3.to_checksum_address("0x4200000000000000000000000000000000000006")
FACTORY_ABI = [{"constant":True,"inputs":[{"name":"tokenA","type":"address"},{"name":"tokenB","type":"address"}],"name":"getPair","outputs":[{"name":"pair","type":"address"}],"type":"function"}]

# Uniswap V2 / Aerodrome / BaseSwap Factory
FACTORIES = [
    ("Uniswap V2 Fork / BaseSwap", w3.to_checksum_address("0xFDa619b6d20975be80A10332cD39b9a4b0FAa8BB")),
    ("Uniswap V2 Factory", w3.to_checksum_address("0x8909Dc15e40173Ff4699343b6eB8132c65e18eC6"))
]

tokens = [
    ("ToshiToken", "0xac1bd2486aaf3b5c0fc3fd868558b082a531b2b4"),
    ("BrettToken", "0x532f27101965dd16442e59d40670faf5ebb142e4")
]

for name, t_addr in tokens:
    c_tkn = w3.to_checksum_address(t_addr)
    print(f"\n--- Analyzing AMM Reserves for {name} ({t_addr}) ---")
    pair_found = None
    for f_name, f_addr in FACTORIES:
        try:
            fc = w3.eth.contract(address=f_addr, abi=FACTORY_ABI)
            p = fc.functions.getPair(c_tkn, WETH_BASE).call()
            if p and p != "0x0000000000000000000000000000000000000000":
                pair_found = (f_name, p)
                break
        except Exception:
            pass

    if pair_found:
        f_name, p_addr = pair_found
        print(f"✓ Found Pair on {f_name}: {p_addr}")
        pair_c = w3.eth.contract(address=w3.to_checksum_address(p_addr), abi=PAIR_ABI)
        r0, r1, _ = pair_c.functions.getReserves().call()
        t0 = pair_c.functions.token0().call()
        eth_reserve = (r0 if t0.lower() == WETH_BASE.lower() else r1) / 1e18
        token_reserve = (r1 if t0.lower() == WETH_BASE.lower() else r0) / 1e18

        # Batch size estimation (default 0.05% of supply or 0.1 ETH)
        batch_val_eth = 0.10
        critical_threshold = batch_val_eth / 0.006 # ~16.6 ETH

        ratio = (batch_val_eth / eth_reserve) * 100
        print(f"  • Live Pool ETH Reserves: {eth_reserve:.2f} ETH")
        print(f"  • Estimated Swap Batch Value: {batch_val_eth:.2f} ETH ({ratio:.4f}% of Pool)")
        print(f"  • Critical Threat Threshold (R_eth*): {critical_threshold:.2f} ETH")
        if eth_reserve <= critical_threshold:
            print("  🚨 STATUS: CRITICAL THREAT (Extractable Slippage > 0.6% fee hurdle)")
        elif eth_reserve <= critical_threshold * 2.0:
            print(f"  ⚠️ STATUS: WARNING (Approaching critical threshold < {critical_threshold*2:.1f} ETH)")
        else:
            print(f"  🛡️ STATUS: PROTECTED BY LIQUIDITY BUFFER (Reserves {eth_reserve:.1f} ETH >> {critical_threshold:.1f} ETH)")
    else:
        print("  Could not locate standard V2 pair with factory query.")
