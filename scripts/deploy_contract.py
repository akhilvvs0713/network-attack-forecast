import os
import sys
import solcx
from web3 import Web3

def deploy():
    # Install/Set solc version
    os.environ['SOLCX_BINARY_PATH'] = '/home/karthikeya/network-attack-forecast/.solcx'
    solcx.install_solc('0.8.0')
    solcx.set_solc_version('0.8.0')

    rpc_url = os.environ.get('BLOCKCHAIN_RPC_URL', 'http://127.0.0.1:8545')
    private_key = os.environ.get('BLOCKCHAIN_PRIVATE_KEY', '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80') # Default anvil key 0

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        print("Failed to connect to", rpc_url)
        sys.exit(1)

    account = w3.eth.account.from_key(private_key)
    w3.eth.default_account = account.address

    # Compile contract
    contract_source_path = os.path.join(os.path.dirname(__file__), '..', 'backend', 'contracts', 'AuditLedger.sol')
    with open(contract_source_path, 'r') as f:
        contract_source = f.read()

    compiled = solcx.compile_source(contract_source, output_values=['abi', 'bin'])
    contract_id, contract_interface = compiled.popitem()

    # Deploy
    AuditLedger = w3.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
    tx = AuditLedger.constructor().build_transaction({
        'from': account.address,
        'nonce': w3.eth.get_transaction_count(account.address),
        'gas': 3000000,
        'gasPrice': w3.eth.gas_price
    })

    signed_tx = w3.eth.account.sign_transaction(tx, private_key=private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    print(tx_receipt.contractAddress)

if __name__ == '__main__':
    deploy()
