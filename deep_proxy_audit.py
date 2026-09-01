import glob
from web3 import Web3

EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

RPC_ENDPOINTS = {
    "base": "https://mainnet.base.org",
    "arbitrum": "https://arb1.arbitrum.io/rpc",
    "ethereum": "https://ethereum-rpc.publicnode.com"
}

triage_files = glob.glob("./contracts/triage_queue/*.md")
print(f"Auditing {len(triage_files)} triage cards for real-world risk factors...\n")

for f in sorted(triage_files):
    with open(f, "r") as fp:
        lines = fp.readlines()
    name = "Unknown"
    addr = "Unknown"
    chain = "Unknown"
    for line in lines:
        if "**Contract Name:**" in line:
            name = line.split("`")[1]
        elif "**Address:**" in line:
            addr = line.split("`")[1]
        elif "**Blockchain:**" in line:
            chain = line.split("`")[1].lower()

    rpc = RPC_ENDPOINTS.get(chain)
    if not rpc:
        continue
    w3 = Web3(Web3.HTTPProvider(rpc))
    c_addr = w3.to_checksum_address(addr)

    bal = w3.from_wei(w3.eth.get_balance(c_addr), "ether")
    code = w3.eth.get_code(c_addr).hex()

    # Check if Facet or Pair or Proxy
    is_facet = "facet" in name.lower() or "diamond" in name.lower()
    is_pair = "pair" in name.lower() or "uniswap" in name.lower()

    print(f"• [{chain.upper()}] {name} ({addr})")
    print(f"   ↳ Native ETH Balance: {bal:.4f} ETH | Bytecode Size: {len(code)//2} bytes")
    print(f"   ↳ Architecture Type: {'Diamond Facet (ERC-2535)' if is_facet else 'DEX Pair' if is_pair else 'Standalone Proxy / Custom'}")
