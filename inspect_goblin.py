import json
from web3 import Web3

RPC = "https://ethereum-rpc.publicnode.com"
w3 = Web3(Web3.HTTPProvider(RPC))

addr = w3.to_checksum_address("0x80d2fd69467dfab82e09d26860d5fd81cb65075e")
with open("./contracts/ethereum/0x80d2fd69467dfab82e09d26860d5fd81cb65075e/abi.json") as f:
    abi = json.load(f)

contract = w3.eth.contract(address=addr, abi=abi)

print("=== UniswapGoblin (0x80d2fd69467dfab82e09d26860d5fd81cb65075e) On-Chain Audit ===")
try:
    operator = contract.functions.operator().call()
    print(f"• Operator: {operator}")
except Exception as e:
    print(f"• Operator query failed: {e}")

try:
    staking_addr = contract.functions.staking().call()
    print(f"• Staking Pool: {staking_addr}")
except Exception as e:
    print(f"• Staking query failed: {e}")

try:
    uni_token = contract.functions.uni().call()
    print(f"• Reward Token (UNI): {uni_token}")

    # Check goblin's current UNI token balance
    erc20_abi = [{"constant":True,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"type":"function"}]
    uni_c = w3.eth.contract(address=w3.to_checksum_address(uni_token), abi=erc20_abi)
    uni_bal = uni_c.functions.balanceOf(addr).call()
    print(f"• Goblin Current UNI Balance: {uni_bal / 1e18:.6f} UNI")
except Exception as e:
    print(f"• UNI token query failed: {e}")

try:
    total_share = contract.functions.totalShare().call()
    print(f"• Total Share in Goblin: {total_share}")
except Exception as e:
    print(f"• totalShare failed: {e}")

try:
    lp_token = contract.functions.lpToken().call()
    print(f"• LP Token: {lp_token}")
    lp_c = w3.eth.contract(address=w3.to_checksum_address(lp_token), abi=erc20_abi)
    lp_bal = lp_c.functions.balanceOf(addr).call()
    print(f"• Goblin Held LP Tokens: {lp_bal / 1e18:.6f} LP")
except Exception as e:
    print(f"• LP token query failed: {e}")

