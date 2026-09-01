from web3 import Web3

w3 = Web3(Web3.HTTPProvider("https://mainnet.base.org"))

PAIR_ABI = [
    {"constant":True,"inputs":[],"name":"getReserves","outputs":[{"name":"_reserve0","type":"uint112"},{"name":"_reserve1","type":"uint112"},{"name":"_blockTimestampLast","type":"uint32"}],"type":"function"},
    {"constant":True,"inputs":[],"name":"token0","outputs":[{"name":"","type":"address"}],"type":"function"}
]
FACTORY_ABI = [{"constant":True,"inputs":[{"name":"tokenA","type":"address"},{"name":"tokenB","type":"address"}],"name":"getPair","outputs":[{"name":"pair","type":"address"}],"type":"function"}]

WETH_BASE = w3.to_checksum_address("0x4200000000000000000000000000000000000006")
FACTORIES = [
    ("Uniswap V2 Factory", w3.to_checksum_address("0x8909Dc15e40173Ff4699343b6eB8132c65e18eC6")),
    ("BaseSwap", w3.to_checksum_address("0xFDa619b6d20975be80A10332cD39b9a4b0FAa8BB")),
    ("SushiSwap V2", w3.to_checksum_address("0x71524B4f93c58fcbF659783284E38825f0622859")),
    ("PancakeSwap V2", w3.to_checksum_address("0x02a84c1b3BBD7401a5f7fa98a384EBC70bB5749E")),
    ("SwapBased", w3.to_checksum_address("0x04C9f118d21e8B767D2e50C946f0cC9F6C367300"))
]

token_addr = w3.to_checksum_address("0xac1bd2486aaf3b5c0fc3fd868558b082a531b2b4") # ToshiToken
critical_thresh = 0.10 / 0.006 # 16.67 ETH

discovered_pools = []
for name, f_addr in FACTORIES:
    try:
        fc = w3.eth.contract(address=f_addr, abi=FACTORY_ABI)
        p = fc.functions.getPair(token_addr, WETH_BASE).call()
        if p and p != "0x0000000000000000000000000000000000000000":
            pc = w3.eth.contract(address=w3.to_checksum_address(p), abi=PAIR_ABI)
            r0, r1, _ = pc.functions.getReserves().call()
            t0 = pc.functions.token0().call()
            eth_res = (r0 if t0.lower() == WETH_BASE.lower() else r1) / 1e18
            discovered_pools.append({
                "dex": name,
                "pair": p,
                "eth_reserves": eth_res,
                "is_critical": eth_res <= critical_thresh
            })
    except Exception:
        continue

print(f"Total DEX Pools Discovered for ToshiToken: {len(discovered_pools)}")
for dp in discovered_pools:
    flag = "🚨 CRITICAL THREAT" if dp["is_critical"] else "🛡️ BUFFERED"
    print(f"  • [{dp['dex']}] Pair: {dp['pair']} | Reserves: {dp['eth_reserves']:.4f} ETH -> {flag}")
