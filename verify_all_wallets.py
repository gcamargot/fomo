import json
import glob
from web3 import Web3

RPC_URLS = [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://cloudflare-eth.com"
]

w3 = None
for rpc in RPC_URLS:
    try:
        client = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 15}))
        if client.is_connected():
            w3 = client
            print(f"Connected to RPC: {rpc}")
            break
    except Exception:
        continue

if not w3:
    print("Could not connect to any Ethereum RPC")
    exit(1)

abi_path = "./contracts/ethereum/0x027adfbd47a4aa73523741a6c030176df8977ba8/abi.json"
with open(abi_path, "r") as f:
    abi = json.load(f)

wallet_dirs = glob.glob("./contracts/ethereum/*/src/WalletSimple.sol")
addresses = [d.split("/")[3] for d in wallet_dirs]

print(f"\n[*] Auditing {len(addresses)} WalletSimple instances on Ethereum Mainnet...")

wallet_data = {}
all_signers_map = {} # signer_addr -> list of wallet addresses

for idx, addr in enumerate(addresses, 1):
    c_addr = w3.to_checksum_address(addr)
    contract = w3.eth.contract(address=c_addr, abi=abi)

    signers = []
    for i in range(3):
        try:
            s = contract.functions.signers(i).call()
            signers.append(s.lower())
        except Exception:
            pass

    try:
        seq_id = contract.functions.getNextSequenceId().call()
    except Exception:
        seq_id = "N/A"

    try:
        bal = w3.from_wei(w3.eth.get_balance(c_addr), "ether")
    except Exception:
        bal = 0.0

    wallet_data[addr] = {
        "signers": signers,
        "sequenceId": seq_id,
        "balance_eth": float(bal)
    }

    for s in signers:
        if s not in all_signers_map:
            all_signers_map[s] = []
        all_signers_map[s].append(addr)

    print(f"[{idx}/{len(addresses)}] {addr} | Signers ({len(signers)}): {signers} | Bal: {bal:.4f} ETH | Seq: {seq_id}")

print("\n" + "="*80)
print("SIGNER CLUSTERING & KEYPAIR ISOLATION REPORT")
print("="*80)

shared_signers = {s: w_list for s, w_list in all_signers_map.items() if len(w_list) > 1}

if shared_signers:
    print(f"🚨 CLUSTER DETECTED: {len(shared_signers)} signer address(es) are shared across multiple wallets!")
    for s, w_list in shared_signers.items():
        print(f"\n🔑 Shared Signer: {s}")
        for w in w_list:
            print(f"   ↳ Wallet: {w} (Next Seq: {wallet_data[w]['sequenceId']}, Bal: {wallet_data[w]['balance_eth']} ETH)")
else:
    print("✓ COMPLETE ISOLATION CONFIRMED:")
    print(f"  All {len(all_signers_map)} observed signers belong to exactly 1 wallet instance.")
    print("  There is zero keypair overlap across the scanned WalletSimple instances.")
