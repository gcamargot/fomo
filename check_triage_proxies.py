from web3 import Web3

EIP1967_IMPL_SLOT = hex(int(Web3.keccak(text='eip1967.proxy.implementation').hex(), 16) - 1)
EIP1967_ADMIN_SLOT = hex(int(Web3.keccak(text='eip1967.proxy.admin').hex(), 16) - 1)

proxies = [
    {"chain": "ethereum", "rpc": "https://ethereum-rpc.publicnode.com", "name": "BankProxy", "addr": "0x4b181d51e472a43ca9d00116e73a1d265cbdecb0"},
    {"chain": "arbitrum", "rpc": "https://arb1.arbitrum.io/rpc", "name": "RainPoolDiamond", "addr": "0x89061dae5498a014915d0ff46f37417354ae9ae3"},
    {"chain": "arbitrum", "rpc": "https://arb1.arbitrum.io/rpc", "name": "MPSSmartWallet", "addr": "0xa05b711213b99232d1a6e42d6e5f685df5b0a0a1"},
    {"chain": "arbitrum", "rpc": "https://arb1.arbitrum.io/rpc", "name": "Competition", "addr": "0x820bd1b517347927b23f06cce41dfe9b1676d582"},
    {"chain": "arbitrum", "rpc": "https://arb1.arbitrum.io/rpc", "name": "Conduit", "addr": "0x7e65dddef1d094f3a5a8e2235a589de01ca990f9"},
    {"chain": "arbitrum", "rpc": "https://arb1.arbitrum.io/rpc", "name": "DiamondLoupeFacet", "addr": "0x7a432d6ece2771d3ae7c3ba78e35664392c99834"},
]

print("="*80)
print("ON-CHAIN VERIFICATION OF PROXY CONTRACTS IN TRIAGE QUEUE")
print("="*80)

for p in proxies:
    w3 = Web3(Web3.HTTPProvider(p["rpc"]))
    addr = w3.to_checksum_address(p["addr"])

    impl_val = w3.eth.get_storage_at(addr, EIP1967_IMPL_SLOT).hex()
    admin_val = w3.eth.get_storage_at(addr, EIP1967_ADMIN_SLOT).hex()
    balance = w3.from_wei(w3.eth.get_balance(addr), "ether")

    impl_addr = "0x" + impl_val[-40:]
    admin_addr = "0x" + admin_val[-40:]

    is_uninitialized = (int(impl_val, 16) == 0)

    print(f"\nContract: {p['name']} ({p['addr']}) on {p['chain'].upper()}")
    print(f"  • EIP-1967 Implementation: {impl_addr}")
    print(f"  • EIP-1967 Admin: {admin_addr}")
    print(f"  • Native Balance: {balance:.4f} ETH")
    if is_uninitialized:
        print("  🚨 STATUS: UNINITIALIZED! Open for Takeover (True Positive)")
    else:
        print("  ✓ STATUS: INITIALIZED & SEALED (Implementation bound). False Positive for Takeover.")
