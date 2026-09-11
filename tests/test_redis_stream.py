import json
import uuid
import time
from unittest.mock import patch

import pytest
import redis

from src.stream.redis_stream import RedisFlowStream

@pytest.fixture
def test_stream_key():
    return f"test:cic:flows:stream:{uuid.uuid4()}"

@pytest.fixture
def redis_stream(test_stream_key):
    """Provides a fresh Redis stream using an isolated test key."""
    # Assumes Redis is running locally on 6379 as per requirements
    stream = RedisFlowStream(key=test_stream_key, maxlen=100)
    stream.clear()
    yield stream
    stream.clear()

def test_stream_connectivity(redis_stream):
    """1. Verify Redis connectivity."""
    assert redis_stream.ping() is True

def test_xadd_creates_entry(redis_stream):
    """2. XADD creates a stream entry."""
    flow = {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "timestamp": "2026-09-11 10:00:00"}
    stream_id = redis_stream.publish_flow(flow)
    assert stream_id is not None

    count = redis_stream.client.xlen(redis_stream.key)
    assert count == 1

def test_entry_contains_event_id_and_timestamp(redis_stream):
    """3. event_id exists. 6. Timestamp is preserved exactly."""
    flow = {"src_ip": "10.0.0.1", "timestamp": "2026-09-11 10:00:00"}
    redis_stream.publish_flow(flow)

    entries = redis_stream.client.xrange(redis_stream.key)
    assert len(entries) == 1

    fields = entries[0][1]
    assert "event_id" in fields
    assert fields["timestamp"] == "2026-09-11 10:00:00"

def test_supplied_event_id_is_preserved_exactly(redis_stream):
    """4. Supplied event_id is preserved exactly."""
    flow = {"src_ip": "10.0.0.1", "timestamp": "2026-09-11 10:00:00"}
    explicit_id = "abc-123-xyz"
    redis_stream.publish_flow(flow, event_id=explicit_id)

    entries = redis_stream.client.xrange(redis_stream.key)
    assert entries[0][1]["event_id"] == explicit_id

def test_event_ids_are_unique(redis_stream):
    """5. Two different flows receive different IDs."""
    redis_stream.publish_flow({"src_ip": "10.0.0.1", "timestamp": "2026-09-11 10:00:00"})
    redis_stream.publish_flow({"src_ip": "10.0.0.2", "timestamp": "2026-09-11 10:00:00"})

    entries = redis_stream.client.xrange(redis_stream.key)
    assert len(entries) == 2

    id1 = entries[0][1]["event_id"]
    id2 = entries[1][1]["event_id"]
    assert id1 != id2

def test_required_fields_present(redis_stream):
    """7. Required flow fields are preserved."""
    flow = {
        "src_ip": "192.168.1.5",
        "dst_port": 80,
        "timestamp": "2026-09-11 10:00:00",
        "nested": {"key": "val"},
        "null_val": None
    }
    redis_stream.publish_flow(flow)

    entries = redis_stream.client.xrange(redis_stream.key)
    fields = entries[0][1]

    assert fields["src_ip"] == "192.168.1.5"
    assert fields["dst_port"] == "80"
    assert fields["nested"] == '{"key": "val"}'
    assert fields["null_val"] == ""

def test_one_flow_one_entry(redis_stream):
    """8. One flow -> one stream entry."""
    for i in range(5):
        redis_stream.publish_flow({"idx": i, "timestamp": "2026-09-11 10:00:00"})

    assert redis_stream.client.xlen(redis_stream.key) == 5

def test_missing_timestamp_skipped(redis_stream):
    """Ensure exact source timestamp is preserved without guessing."""
    # This flow has no timestamp
    flow = {"src_ip": "10.0.0.1"}
    stream_id = redis_stream.publish_flow(flow)

    # Should be skipped and return None
    assert stream_id is None
    assert redis_stream.client.xlen(redis_stream.key) == 0

@patch("redis.Redis.xadd")
def test_redis_failure_handled_cleanly(mock_xadd, test_stream_key):
    """Stream failure handled cleanly in component."""
    mock_xadd.side_effect = redis.RedisError("Connection lost")

    stream = RedisFlowStream(key=test_stream_key)
    res = stream.publish_flow({"data": "test", "timestamp": "2026-09-11 10:00:00"})
    assert res is None

def test_configuration_read():
    """13. Configuration values are read correctly."""
    from config import config
    stream = RedisFlowStream()
    assert stream.maxlen == config.REDIS_STREAM_MAXLEN
