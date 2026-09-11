#!/usr/bin/env python3
import sys
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from config import config
import redis
import json


def inspect_stream():
    print(f"--- Redis Stream Inspection ---")
    print(f"Host: {config.REDIS_HOST}:{config.REDIS_PORT}, DB: {config.REDIS_DB}")
    print(f"Stream Key: {config.REDIS_STREAM_KEY}")

    try:
        r = redis.Redis(
            host=config.REDIS_HOST,
            port=config.REDIS_PORT,
            db=config.REDIS_DB,
            decode_responses=True,
        )
        r.ping()
    except redis.RedisError as e:
        print(f"[!] Redis connection failed: {e}")
        return

    try:
        count = r.xlen(config.REDIS_STREAM_KEY)
        print(f"\nTotal entries in stream: {count}")

        if count > 0:
            info = r.xinfo_stream(config.REDIS_STREAM_KEY)
            print(f"First ID: {info.get('first-entry', [None])[0]}")
            print(f"Last ID: {info.get('last-entry', [None])[0]}")

            print(f"\n--- Latest 3 Events ---")
            # xrevrange for latest events
            latest = r.xrevrange(config.REDIS_STREAM_KEY, max="+", min="-", count=3)
            for stream_id, fields in latest:
                print(f"\nStream ID: {stream_id}")
                print(f"  event_id: {fields.get('event_id', 'N/A')}")
                print(f"  timestamp: {fields.get('timestamp', 'N/A')}")
                print(f"  src_ip: {fields.get('src_ip', fields.get('Src IP', 'N/A'))}")
                print(f"  dst_ip: {fields.get('dst_ip', fields.get('Dst IP', 'N/A'))}")
                print(
                    f"  src_port: {fields.get('src_port', fields.get('Src Port', 'N/A'))}"
                )
                print(
                    f"  dst_port: {fields.get('dst_port', fields.get('Dst Port', 'N/A'))}"
                )
                print(
                    f"  protocol: {fields.get('protocol', fields.get('Protocol', 'N/A'))}"
                )
    except redis.RedisError as e:
        print(f"[!] Failed to inspect stream: {e}")


if __name__ == "__main__":
    inspect_stream()
