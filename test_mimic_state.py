from web3 import Web3

w3 = Web3(Web3.HTTPProvider("https://ethereum-rpc.publicnode.com"))

tkn_addr = w3.to_checksum_address("0x8c6df25707cdd6d97c6161c0d5a6382f9c7f56b4")
WETH_ETH = w3.to_checksum_address("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
UNI_FACTORY = w3.to_checksum_address("0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f")

FACTORY_ABI = [{"constant":True,"inputs":[{"name":"tokenA","type":"address"},{"name":"tokenB","type":"address"}],"name":"getPair","outputs":[{"name":"pair","type":"address"}],"type":"function"}]
PAIR_ABI = [
    {"constant":True,"inputs":[],"name":"getReserves","outputs":[{"name":"_reserve0","type":"uint112"},{"name":"_reserve1","type":"uint112"},{"name":"_blockTimestampLast","type":"uint32"}],"type":"function"},
    {"constant":True,"inputs":[],"name":"token0","outputs":[{"name":"","type":"address"}],"type":"function"}
]
TOKEN_ABI = [
    {"constant":True,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"type":"function"},
    {"constant":True,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"type":"function"},
    {"constant":True,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"type":"function"},
    {"constant":True,"inputs":[{"name":"account","type":"address"}],"name":"isExcluded","outputs":[{"name":"","type":"bool"}],"type":"function"}
]

try:
    c = w3.eth.contract(address=tkn_addr, abi=TOKEN_ABI)
    name = c.functions.name().call()
    sym = c.functions.symbol().call()
    supp = c.functions.totalSupply().call()
    bal = w3.eth.get_balance(tkn_addr)

    fc = w3.eth.contract(address=UNI_FACTORY, abi=FACTORY_ABI)
    pair = fc.functions.getPair(tkn_addr, WETH_ETH).call()

    print(f"Token: {name} ({sym}) at {tkn_addr}")
    print(f"ETH Balance of Contract: {w3.from_wei(bal, 'ether')} ETH")
    print(f"Total Supply: {supp / 1e18:.2f} {sym}")
    print(f"Uniswap V2 Pair: {pair}")

    if pair and pair != "0x0000000000000000000000000000000000000000":
        pc = w3.eth.contract(address=w3.to_checksum_address(pair), abi=PAIR_ABI)
        r0, r1, _ = pc.functions.getReserves().call()
        t0 = pc.functions.token0().call()
        eth_res = (r0 if t0.lower() == WETH_ETH.lower() else r1) / 1e18
        token_res = (r1 if t0.lower() == WETH_ETH.lower() else r0) / 1e18
        is_pair_excluded = c.functions.isExcluded(w3.to_checksum_address(pair)).call()
        print(f"  • Pair ETH Reserves: {eth_res:.4f} ETH")
        print(f"  • Pair Token Reserves: {token_res:.2f} {sym}")
        print(f"  • Is Pair Excluded from Reflection: {is_pair_excluded}")
    else:
        print("  • No Uniswap V2 Pair found.")
except Exception as e:
    print(f"Error querying on-chain state: {e}")
