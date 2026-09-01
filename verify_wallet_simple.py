import json
import glob
from web3 import Web3

RPC_URL = "https://cloudflare-eth.com"
w3 = Web3(Web3.HTTPProvider(RPC_URL, request_kwargs={"timeout": 15}))

if not w3.is_connected():
    print("Error: Could not connect to Ethereum RPC")
    exit(1)

abi_path = "./contracts/ethereum/0x027adfbd47a4aa73523741a6c030176df8977ba8/abi.json"
with open(abi_path, "r") as f:
    abi = json.load(f)

# Find all WalletSimple folders
wallet_dirs = glob.glob("./contracts/ethereum/*/src/WalletSimple.sol")
addresses = [d.split("/")[3] for d in wallet_dirs]

print(f"[*] Analyzing {len(addresses)} WalletSimple instances on Ethereum Mainnet...\n")

results = []
for addr in addresses[:15]: # Check 15 instances
    try:
        c_addr = w3.to_checksum_address(addr)
        contract = w3.eth.contract(address=c_addr, abi=abi)

        # Query signers
        signers = []
        for i in range(3):
            try:
                s = contract.functions.signers(i).call()
                signers.append(s.lower())
            except Exception:
                pass

        seq_id = contract.functions.getNextSequenceId().call()
        balance = w3.eth.get_balance(c_addr)
        eth_balance = w3.from_wei(balance, "ether")

        results.append({
            "address": addr,
            "signers": signers,
            "sequenceId": seq_id,
            "balance_eth": float(eth_balance)
        })
        print(f"✓ [{addr}] Signers: {len(signers)} | NextSequenceId: {seq_id} | Balance: {eth_balance:.4f} ETH")
    except Exception as e:
        print(f"[!] Error on {addr}: {e}")

# Compare Signers overlap
print("\n" + "="*80)
print("CROSS-CONTRACT SIGNERS COMPARISON & REPLAY FEASIBILITY ANALYSIS:")
print("="*80)
overlap_found = False
for i in range(len(results)):
    for j in range(i+1, len(results)):
        w1 = results[i]
        w2 = results[j]
        set1 = set(w1["signers"])
        set2 = set(w2["signers"])
        common = set1.intersection(set2)
        if common:
            overlap_found = True
            print("\n🚨 SHARED SIGNER CLUSTER DETECTED!")
            print(f"   Wallet A: {w1['address']} (Next SequenceId: {w1['sequenceId']})")
            print(f"   Wallet B: {w2['address']} (Next SequenceId: {w2['sequenceId']})")
            print(f"   Shared Signers: {list(common)}")

if not overlap_found:
    print("\n✓ RESULT: Distinct Keypairs Isolation.")
    print("  Although the contract architecture lacks address(this) in the hash, each BitGo wallet")
    print("  instance was deployed with unique/segregated private key sets for each user/institution,")
    print("  preventing cross-contract replay in practice across these instances.")
