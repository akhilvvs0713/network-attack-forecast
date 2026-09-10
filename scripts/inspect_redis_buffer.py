#!/usr/bin/env python3
"""
Diagnostic tool to inspect the active CICFlowMeter Redis rolling buffer.
"""
import sys
import time
import json
import argparse
from pathlib import Path
from datetime import datetime

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import config
import redis

def format_timestamp(ts: float) -> str:
    """Convert a unix timestamp float to a readable string."""
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    except Exception:
        return str(ts)

def format_flow(flow_str: str) -> str:
    """Extract a compact summary from the JSON flow."""
    try:
        data = json.loads(flow_str)
        return (
            f"[{data.get('timestamp', 'N/A')}] "
            f"{data.get('src_ip', 'N/A')}:{data.get('src_port', 'N/A')} -> "
            f"{data.get('dst_ip', 'N/A')}:{data.get('dst_port', 'N/A')} "
            f"({data.get('protocol', 'N/A')})"
        )
    except json.JSONDecodeError:
        return "Invalid JSON"

def inspect_buffer(client: redis.Redis, key: str, show_details: bool = True):
    """Fetch and print statistics from the Redis buffer."""
    count = client.zcard(key)
    
    if show_details:
        print(f"\n--- Buffer Status: {key} ---")
        
    if count == 0:
        print("Buffer is currently empty.")
        return
        
    # Get oldest and newest flows
    oldest_records = client.zrange(key, 0, 4, withscores=True)
    newest_records = client.zrange(key, -5, -1, withscores=True)
    # The newest records come back in oldest-to-newest order if using zrange,
    # let's reverse them to show the absolute newest first
    newest_records.reverse()
    
    oldest_ts = oldest_records[0][1]
    newest_ts = newest_records[0][1]
    span = newest_ts - oldest_ts

    if show_details:
        print(f"Current count: {count} flows")
        print(f"Oldest flow:   {format_timestamp(oldest_ts)}")
        print(f"Newest flow:   {format_timestamp(newest_ts)}")
        print(f"Time span:     {span:.2f} seconds")
        
        print("\n--- 5 Oldest Flows ---")
        for record, score in oldest_records:
            print(f"{format_timestamp(score)} | {format_flow(record)}")
            
        print("\n--- 5 Newest Flows ---")
        for record, score in newest_records:
            print(f"{format_timestamp(score)} | {format_flow(record)}")
    else:
        # Compact watch mode
        ts_now = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts_now}] Count: {count} | Oldest: {format_timestamp(oldest_ts)} | Newest: {format_timestamp(newest_ts)} | Span: {span:.2f}s")

def main():
    parser = argparse.ArgumentParser(description="Inspect the real-time Redis flow buffer.")
    parser.add_argument("--watch", action="store_true", help="Refresh stats every 5 seconds")
    args = parser.parse_args()

    # Connect read-only
    client = redis.Redis(
        host=config.REDIS_HOST,
        port=config.REDIS_PORT,
        db=config.REDIS_DB,
        decode_responses=True
    )

    try:
        client.ping()
    except redis.RedisError as e:
        print(f"[!] Could not connect to Redis at {config.REDIS_HOST}:{config.REDIS_PORT}. Error: {e}")
        sys.exit(1)

    print(f"[*] Connected to Redis at {config.REDIS_HOST}:{config.REDIS_PORT}")
    print(f"[*] Inspecting key: {config.REDIS_FLOW_KEY}")

    if args.watch:
        print("[*] Watch mode activated. Press Ctrl+C to stop.")
        try:
            while True:
                inspect_buffer(client, config.REDIS_FLOW_KEY, show_details=False)
                time.sleep(5)
        except KeyboardInterrupt:
            print("\nExiting watch mode.")
    else:
        inspect_buffer(client, config.REDIS_FLOW_KEY, show_details=True)

if __name__ == "__main__":
    main()
