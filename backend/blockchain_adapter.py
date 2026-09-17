import json
import logging
import hashlib
import os
import asyncio
from typing import Dict, Any
from web3 import Web3
from eth_account import Account
import uuid
import time

logger = logging.getLogger("NetworkMonitor.Blockchain")

ABI = [
    {
        "inputs": [
            {"internalType": "string", "name": "eventId", "type": "string"},
            {"internalType": "string", "name": "payloadHash", "type": "string"},
            {"internalType": "uint256", "name": "riskScoreX10000", "type": "uint256"},
            {"internalType": "string", "name": "mitreStage", "type": "string"},
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"}
        ],
        "name": "logEvent",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "string", "name": "", "type": "string"}],
        "name": "records",
        "outputs": [
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
            {"internalType": "string", "name": "payloadHash", "type": "string"},
            {"internalType": "uint256", "name": "riskScoreX10000", "type": "uint256"},
            {"internalType": "string", "name": "mitreStage", "type": "string"},
            {"internalType": "bool", "name": "exists", "type": "bool"}
        ],
        "stateMutability": "view",
        "type": "function"
    }
]

# Off-chain storage simulation
_offchain_audit_events: Dict[str, Any] = {}

def canonicalize(payload: Dict[str, Any]) -> str:
    """Produce deterministic JSON for hashing."""
    return json.dumps(payload, sort_keys=True, separators=(',', ':'))

def get_hash(payload: Dict[str, Any]) -> str:
    """Generate SHA-256 hash of the canonical JSON."""
    canonical_json = canonicalize(payload)
    return hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()

def construct_security_event(window: Dict[str, Any], model_version: str = "lstm-v1.0") -> Dict[str, Any]:
    """Extract and format the allowed fields for the security event."""
    event_id = window.get("event_id") or str(uuid.uuid4())
    event = {
        "event_id": event_id,
        "timestamp": window.get("timestamp", ""),
        "model_version": model_version,
        "risk_score": window.get("current_risk", 0.0),
        "mitre_stage": window.get("current_stage", "Unknown"),
        "forecast_horizon": str(window.get("trajectory", [])),
        "telemetry_window_id": window.get("telemetry_window_id", "")
    }
    return event

def _sync_log_event(event: Dict[str, Any], payload_hash: str) -> Optional[str]:
    """Synchronous web3 call, intended to be run in a thread."""
    rpc_url = os.getenv("BLOCKCHAIN_RPC_URL")
    private_key = os.getenv("BLOCKCHAIN_PRIVATE_KEY")
    contract_address = os.getenv("CONTRACT_ADDRESS")
    
    if not rpc_url or not private_key or not contract_address:
        logger.warning("Blockchain credentials missing. Skipping on-chain log.")
        return None
        
    try:
        w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={'timeout': 2}))
        if not w3.is_connected():
            logger.warning("Blockchain node unreachable. Skipping on-chain log.")
            return None
            
        account = Account.from_key(private_key)
        contract = w3.eth.contract(address=contract_address, abi=ABI)
        
        event_id_str = event["event_id"]
        risk_score_int = int(event["risk_score"] * 10000)
        mitre_stage_str = event["mitre_stage"]
        ts = int(time.time())
        
        tx = contract.functions.logEvent(
            event_id_str, payload_hash, risk_score_int, mitre_stage_str, ts
        ).build_transaction({
            'from': account.address,
            'nonce': w3.eth.get_transaction_count(account.address),
            'gas': 3000000,
            'gasPrice': w3.eth.gas_price
        })
        
        signed_tx = w3.eth.account.sign_transaction(tx, private_key=private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        
        return tx_hash.hex()
    except Exception as e:
        logger.error(f"Blockchain logging failed: {e}")
        return None

async def log_security_event_async(window: Dict[str, Any]):
    """
    Constructs the security event, hashes it, and submits to the blockchain.
    Runs in a separate thread to prevent blocking the asyncio event loop.
    """
    try:
        event = construct_security_event(window)
        payload_hash = get_hash(event)
        
        # Save off-chain
        _offchain_audit_events[event["event_id"]] = event
        
        # Run the blocking Web3 call in a thread
        tx_hash = await asyncio.to_thread(_sync_log_event, event, payload_hash)
        
        if tx_hash:
            logger.info(f"Successfully logged event {event['event_id']} to blockchain: {tx_hash}")
            event["_tx_hash"] = tx_hash
        
        return event
    except Exception as e:
        logger.error(f"Blockchain adapter error: {e}")
        return None

def _sync_verify_event(event_id: str, offchain_hash: str) -> Dict[str, Any]:
    rpc_url = os.getenv("BLOCKCHAIN_RPC_URL")
    contract_address = os.getenv("CONTRACT_ADDRESS")
    
    if not rpc_url or not contract_address:
        return {"status": "UNAVAILABLE", "message": "Blockchain unavailable"}
        
    try:
        w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={'timeout': 2}))
        if not w3.is_connected():
            return {"status": "UNAVAILABLE", "message": "Blockchain unreachable"}
            
        contract = w3.eth.contract(address=contract_address, abi=ABI)
        record = contract.functions.records(event_id).call()
        exists = record[4]
        
        if not exists:
            return {
                "event_id": event_id,
                "status": "NOT_ON_CHAIN",
                "message": "Event exists off-chain but not on-chain"
            }
            
        onchain_hash = record[1]
        
        if offchain_hash == onchain_hash:
            return {
                "event_id": event_id,
                "status": "VALID",
                "off_chain_hash": offchain_hash,
                "on_chain_hash": onchain_hash,
                "transaction_hash": None,  # Optional
                "block_number": -1         # Optional
            }
        else:
            return {
                "event_id": event_id,
                "status": "TAMPERED",
                "off_chain_hash": offchain_hash,
                "on_chain_hash": onchain_hash
            }
            
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}

async def verify_event_async(event_id: str) -> Dict[str, Any]:
    if event_id not in _offchain_audit_events:
        return {"status": "NOT_FOUND", "message": "Event does not exist off-chain"}
        
    offchain_event = dict(_offchain_audit_events[event_id])
    tx_hash = offchain_event.pop("_tx_hash", None)
    
    offchain_hash = get_hash(offchain_event)
    
    result = await asyncio.to_thread(_sync_verify_event, event_id, offchain_hash)
    if result.get("status") == "VALID" and tx_hash:
        result["transaction_hash"] = tx_hash
    return result
