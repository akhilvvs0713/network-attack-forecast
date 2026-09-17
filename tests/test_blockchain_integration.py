import pytest
import os
import sys
import solcx
import json
import asyncio
from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import backend.blockchain_adapter as blockchain_adapter

@pytest.fixture(scope="module")
def w3_tester():
    return Web3(EthereumTesterProvider())

@pytest.fixture(scope="module")
def compiled_contract():
    os.environ['SOLCX_BINARY_PATH'] = '/home/karthikeya/network-attack-forecast/.solcx'
    solcx.install_solc('0.8.0')
    solcx.set_solc_version('0.8.0')
    
    contract_source_path = os.path.join(os.path.dirname(__file__), '..', 'backend', 'contracts', 'AuditLedger.sol')
    with open(contract_source_path, 'r') as f:
        contract_source = f.read()
        
    compiled = solcx.compile_source(
        contract_source,
        output_values=['abi', 'bin']
    )
    contract_id, contract_interface = compiled.popitem()
    return contract_interface

@pytest.fixture(scope="module")
def deployed_contract(w3_tester, compiled_contract):
    w3_tester.eth.default_account = w3_tester.eth.accounts[0]
    Contract = w3_tester.eth.contract(abi=compiled_contract['abi'], bytecode=compiled_contract['bin'])
    
    tx_hash = Contract.constructor().transact()
    tx_receipt = w3_tester.eth.wait_for_transaction_receipt(tx_hash)
    
    return w3_tester.eth.contract(
        address=tx_receipt.contractAddress,
        abi=compiled_contract['abi']
    )

@pytest.mark.asyncio
async def test_contract_integration(w3_tester, deployed_contract, mocker):
    # Set environment variables for the adapter to pick up
    os.environ['BLOCKCHAIN_RPC_URL'] = 'dummy' # bypassed by mock
    os.environ['BLOCKCHAIN_PRIVATE_KEY'] = '0x0000000000000000000000000000000000000000000000000000000000000001' # dummy
    os.environ['CONTRACT_ADDRESS'] = deployed_contract.address
    
    # We will mock _get_contract or rather inject our w3_tester into the adapter's sync call
    # But adapter._sync_log_event creates Web3(Web3.HTTPProvider).
    # Let's mock the inside of _sync_log_event and _sync_verify_event to use our w3_tester
    
    def mock_sync_log(event, payload_hash):
        try:
            account = w3_tester.eth.default_account
            contract = deployed_contract
            
            event_id_str = event["event_id"]
            risk_score_int = int(event["risk_score"] * 10000)
            mitre_stage_str = event["mitre_stage"]
            import time
            ts = int(time.time())
            
            tx_hash = contract.functions.logEvent(
                event_id_str, payload_hash, risk_score_int, mitre_stage_str, ts
            ).transact({'from': account})
            return tx_hash.hex()
        except Exception as e:
            return None
            
    mocker.patch("backend.blockchain_adapter._sync_log_event", side_effect=mock_sync_log)
    
    def mock_sync_verify(event_id, offchain_hash):
        contract = deployed_contract
        record = contract.functions.records(event_id).call()
        exists = record[4]
        if not exists:
            return {"status": "NOT_ON_CHAIN"}
        onchain_hash = record[1]
        if offchain_hash == onchain_hash:
            return {"status": "VALID", "on_chain_hash": onchain_hash, "off_chain_hash": offchain_hash}
        return {"status": "TAMPERED", "on_chain_hash": onchain_hash, "off_chain_hash": offchain_hash}
        
    mocker.patch("backend.blockchain_adapter._sync_verify_event", side_effect=mock_sync_verify)
    
    raw_window = {
        "event_id": "integration-1",
        "timestamp": "12:00:00",
        "current_risk": 0.99,
        "current_stage": "Exfiltration"
    }
    
    # 1. Log event
    event = await blockchain_adapter.log_security_event_async(raw_window)
    assert event is not None
    assert event["_tx_hash"] is not None
    
    # 2. Verify event
    verify_result = await blockchain_adapter.verify_event_async("integration-1")
    assert verify_result["status"] == "VALID"
    
    # 3. Verify it emitted SecurityEventLogged
    # (Optional in test, but good to know it works)
    
    # 4. Try to alter off-chain state and verify it says TAMPERED
    blockchain_adapter._offchain_audit_events["integration-1"]["risk_score"] = 0.5
    verify_tampered = await blockchain_adapter.verify_event_async("integration-1")
    assert verify_tampered["status"] == "TAMPERED"

