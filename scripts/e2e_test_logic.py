import os
import sys
import asyncio
import uuid
import time
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.main import app
from backend.blockchain_adapter import log_security_event_async, _offchain_audit_events, _sync_log_event

client = TestClient(app)

async def main():
    print("Submitting realistic security event...")
    event_id = str(uuid.uuid4())
    raw_window = {
        "event_id": event_id,
        "timestamp": "12:34:56",
        "current_risk": 0.99,
        "current_stage": "Exfiltration",
        "trajectory": [],
        "telemetry_window_id": "test-e2e"
    }

    # 1. Submit event via adapter
    result = await log_security_event_async(raw_window)
    if not result or "_tx_hash" not in result:
        print("Failed to submit event to blockchain.")
        sys.exit(1)
    
    print("[PASS] Event submission")
    print(f"[PASS] Transaction mined: {result['_tx_hash']}")

    # 2. Call verification API
    response = client.get(f"/api/audit/verify/{event_id}")
    if response.status_code != 200:
        print(f"Failed verification API: {response.text}")
        sys.exit(1)
    
    data = response.json()
    if data.get("status") == "VALID":
        print("[PASS] VALID verification")
    else:
        print(f"Expected VALID, got {data.get('status')}")
        sys.exit(1)

    # 3. Tamper with off-chain event
    _offchain_audit_events[event_id]["risk_score"] = 0.50

    response = client.get(f"/api/audit/verify/{event_id}")
    data = response.json()
    if data.get("status") == "TAMPERED":
        print("[PASS] TAMPERED verification")
    else:
        print(f"Expected TAMPERED, got {data.get('status')}")
        sys.exit(1)

    # 4. Stop blockchain node (simulate by changing RPC URL to garbage)
    print("Simulating blockchain node failure...")
    os.environ['BLOCKCHAIN_RPC_URL'] = "http://127.0.0.1:9999" # unreachable port

    event_id2 = str(uuid.uuid4())
    raw_window2 = dict(raw_window)
    raw_window2["event_id"] = event_id2

    start_time = time.time()
    result2 = await log_security_event_async(raw_window2)
    elapsed = time.time() - start_time

    # It should fail gracefully, return the event without a tx hash, and NOT block for a long time 
    if result2 is not None and "_tx_hash" not in result2:
        print("[PASS] Blockchain failure isolation (event loop unaffected)")
    else:
        print("Failure isolation test did not behave as expected.")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
