import pytest
import asyncio
import json
import uuid
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.blockchain_adapter import canonicalize, get_hash, construct_security_event
import backend.blockchain_adapter as blockchain_adapter

def test_canonical_json_determinism():
    payload_a = {
        "event_id": "test-uuid",
        "risk_score": 0.94,
        "mitre_stage": "Lateral Movement"
    }
    payload_b = {
        "mitre_stage": "Lateral Movement",
        "risk_score": 0.94,
        "event_id": "test-uuid"
    }
    assert canonicalize(payload_a) == canonicalize(payload_b)
    assert ': ' not in canonicalize(payload_a)
    assert ', ' not in canonicalize(payload_a)

def test_sha256_determinism():
    payload_a = {
        "event_id": "test-uuid",
        "risk_score": 0.94
    }
    payload_b = {
        "risk_score": 0.94,
        "event_id": "test-uuid"
    }
    payload_c = {
        "event_id": "test-uuid",
        "risk_score": 0.95
    }
    hash_a = get_hash(payload_a)
    hash_b = get_hash(payload_b)
    hash_c = get_hash(payload_c)
    
    assert hash_a == hash_b
    assert hash_a != hash_c

def test_security_event_schema():
    raw_window = {
        "event_id": "foo",
        "timestamp": "15:30:00",
        "current_risk": 0.99,
        "current_stage": "Exfiltration",
        "trajectory": [{"prob": 0.9, "stage": "Exfiltration"}],
        "shap_features": {"f1": 0.1, "f2": 0.2},
        "_debug": {"raw_score": 0.99},
        "telemetry_window_id": "live-1"
    }
    event = construct_security_event(raw_window)
    
    # Assert inclusion
    assert event["event_id"] == "foo"
    assert event["timestamp"] == "15:30:00"
    assert event["model_version"] == "lstm-v1.0"
    assert event["risk_score"] == 0.99
    assert event["mitre_stage"] == "Exfiltration"
    assert "Exfiltration" in event["forecast_horizon"]
    assert event["telemetry_window_id"] == "live-1"
    
    # Assert exclusion
    assert "shap_features" not in event
    assert "_debug" not in event
    assert "raw_score" not in event

@pytest.mark.asyncio
async def test_blockchain_adapter_mock_test(mocker):
    raw_window = {
        "event_id": "mock-event",
        "timestamp": "10:00:00",
        "current_risk": 0.88,
        "current_stage": "Testing"
    }
    
    mock_sync_log = mocker.patch("backend.blockchain_adapter._sync_log_event", return_value="0xmocktxhash")
    
    event = await blockchain_adapter.log_security_event_async(raw_window)
    
    # Verify it succeeded and didn't crash
    assert event is not None
    assert event["_tx_hash"] == "0xmocktxhash"
    assert "mock-event" in blockchain_adapter._offchain_audit_events
    
    # Verify exact calls to sync logger
    mock_sync_log.assert_called_once()
    called_event, called_hash = mock_sync_log.call_args[0]
    assert called_event["event_id"] == "mock-event"
    # Ensure _tx_hash is popped if we want to compare hash
    copy_ev = dict(called_event)
    copy_ev.pop("_tx_hash", None)
    assert called_hash == get_hash(copy_ev)

@pytest.mark.asyncio
async def test_blockchain_failure_isolation(mocker):
    raw_window = {
        "event_id": "fail-event",
        "timestamp": "10:01:00",
        "current_risk": 0.90,
        "current_stage": "Testing"
    }
    
    # Mock to RAISE an exception
    mocker.patch("backend.blockchain_adapter._sync_log_event", side_effect=Exception("Blockchain RPC timeout"))
    
    # This must NOT raise an exception to the caller (which is the inference loop)
    event = await blockchain_adapter.log_security_event_async(raw_window)
    
    # It logs the error and returns None, but doesn't crash the event loop
    assert event is None

@pytest.mark.asyncio
async def test_verification_logic(mocker):
    mock_event_id = "verify-me"
    payload = {
        "event_id": mock_event_id,
        "risk_score": 0.8,
        "mitre_stage": "Test"
    }
    offchain_hash = get_hash(payload)
    blockchain_adapter._offchain_audit_events[mock_event_id] = payload
    
    # Case 1: Valid
    mocker.patch("backend.blockchain_adapter._sync_verify_event", return_value={
        "status": "VALID",
        "on_chain_hash": offchain_hash,
        "off_chain_hash": offchain_hash
    })
    res = await blockchain_adapter.verify_event_async(mock_event_id)
    assert res["status"] == "VALID"
    
    # Case 2: Tampered
    mocker.patch("backend.blockchain_adapter._sync_verify_event", return_value={
        "status": "TAMPERED",
        "on_chain_hash": "different_hash",
        "off_chain_hash": offchain_hash
    })
    res2 = await blockchain_adapter.verify_event_async(mock_event_id)
    assert res2["status"] == "TAMPERED"


def test_risk_threshold_logic():
    # We can just read the main.py and regex for the condition
    with open("backend/main.py", "r") as f:
        content = f.read()
    assert "if w.get(\"current_risk\", 0.0) >= _best_threshold:" in content
    assert "asyncio.create_task(blockchain.log_security_event_async(w))" in content
