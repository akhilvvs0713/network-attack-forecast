#!/usr/bin/env python3
"""
Integration test for RedisFlowBuffer.
Simulates insertion and pruning without live traffic.
"""
import sys
import time
import uuid
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.buffer.redis_buffer import RedisFlowBuffer

logging.basicConfig(level=logging.INFO, format="%(message)s")

def run_integration_test():
    test_key = f"test:cic:flows:integration:{uuid.uuid4()}"
    buffer = RedisFlowBuffer(key=test_key, retention_seconds=300)
    
    print(f"[*] Testing Redis Connectivity on {buffer.host}:{buffer.port}")
    if not buffer.ping():
        print("[!] Failed to connect to Redis. Ensure it is running.")
        sys.exit(1)
    
    print("[*] Connection successful.")
    
    try:
        # Clear just in case
        buffer.clear()
        
        base_ts = 1000.0
        
        print("[*] Inserting 5 synthetic flows...")
        # 12:00 -> 12:04
        for i in range(5):
            ts = base_ts + (i * 60)
            buffer.add_flow({"flow_id": i, "synthetic": True}, timestamp=ts)
            
        count = buffer.count()
        print(f"[*] Flows in buffer: {count}")
        if count != 5:
            print(f"[!] Expected 5 flows, found {count}")
            sys.exit(1)
            
        print("[*] Inserting flow at T+6m to trigger pruning of T+0...")
        buffer.add_flow({"flow_id": 5, "synthetic": True}, timestamp=base_ts + 360)
        
        count = buffer.count()
        print(f"[*] Flows in buffer after prune: {count}")
        if count != 5: # Added 1, pruned 1
            print(f"[!] Expected 5 flows after pruning, found {count}")
            sys.exit(1)
            
        flows = buffer.get_flows()
        flow_ids = [f["flow_id"] for f in flows]
        print(f"[*] Retained flow IDs: {flow_ids}")
        
        if 0 in flow_ids:
            print("[!] Pruning failed: Flow ID 0 was retained")
            sys.exit(1)
            
        if 5 not in flow_ids:
            print("[!] Insertion failed: Flow ID 5 is missing")
            sys.exit(1)
            
        print("[*] Success! Sliding window works correctly.")
        
    finally:
        print(f"[*] Cleaning up test key: {test_key}")
        buffer.clear()
        
if __name__ == "__main__":
    run_integration_test()
