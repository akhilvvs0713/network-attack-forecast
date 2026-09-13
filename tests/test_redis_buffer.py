import json
import uuid
import time
from unittest.mock import patch, MagicMock

import pytest
import redis

from src.buffer.redis_buffer import RedisFlowBuffer


@pytest.fixture
def test_key():
    return f"test:cic:flows:{uuid.uuid4()}"


@pytest.fixture
def redis_buffer(test_key):
    """Provides a fresh Redis buffer using an isolated test key."""
    # We assume Redis is running locally on 6379 as per requirements
    buffer = RedisFlowBuffer(key=test_key, retention_seconds=300)

    # Ensure it's clean before test
    buffer.clear()

    yield buffer

    # Cleanup after test
    buffer.clear()


def test_redis_connectivity(redis_buffer):
    """1. Verify Redis connectivity."""
    assert redis_buffer.ping() is True


def test_add_and_retrieve_one_flow(redis_buffer):
    """2. Adding one flow. 3. Retrieving one flow."""
    flow = {
        "src_ip": "192.168.1.1",
        "dst_ip": "10.0.0.1",
        "timestamp": "15/02/2018 08:35:18",
    }

    redis_buffer.add_flow(flow)

    assert redis_buffer.count() == 1
    flows = redis_buffer.get_flows()
    assert len(flows) == 1

    # Ensure fields are preserved (and _id was injected)
    assert flows[0]["src_ip"] == "192.168.1.1"
    assert "_id" in flows[0]


def test_multiple_flows_with_identical_timestamps(redis_buffer):
    """4. Multiple flows. 5. Multiple flows with identical timestamps are all retained."""
    ts = 1518683718.0
    flow1 = {"src_ip": "1.1.1.1", "payload": "A"}
    flow2 = {"src_ip": "2.2.2.2", "payload": "B"}
    flow3 = {"src_ip": "3.3.3.3", "payload": "C"}

    redis_buffer.add_flow(flow1, timestamp=ts)
    redis_buffer.add_flow(flow2, timestamp=ts)
    redis_buffer.add_flow(flow3, timestamp=ts)

    # All three must be retained
    assert redis_buffer.count() == 3

    retrieved = redis_buffer.get_flows()
    assert len(retrieved) == 3
    payloads = set(f["payload"] for f in retrieved)
    assert payloads == {"A", "B", "C"}


def test_timestamp_ordering(redis_buffer):
    """6. Timestamp ordering."""
    # Insert out of order
    redis_buffer.add_flow({"id": "second"}, timestamp=200.0)
    redis_buffer.add_flow({"id": "first"}, timestamp=100.0)
    redis_buffer.add_flow({"id": "third"}, timestamp=300.0)

    flows = redis_buffer.get_flows()
    assert len(flows) == 3
    assert flows[0]["id"] == "first"
    assert flows[1]["id"] == "second"
    assert flows[2]["id"] == "third"


def test_time_range_retrieval(redis_buffer):
    """7. Time-range retrieval."""
    redis_buffer.add_flow({"val": 1}, timestamp=100.0)
    redis_buffer.add_flow({"val": 2}, timestamp=200.0)
    redis_buffer.add_flow({"val": 3}, timestamp=300.0)
    redis_buffer.add_flow({"val": 4}, timestamp=400.0)

    # Retrieve between 200 and 350 (inclusive by default in redis)
    flows = redis_buffer.get_flows(start_timestamp=200.0, end_timestamp=350.0)
    assert len(flows) == 2
    vals = [f["val"] for f in flows]
    assert vals == [2, 3]


def test_sliding_window_pruning(redis_buffer):
    """
    8. Automatic pruning.
    9. Explicit pruning.
    10. Five-minute retention behavior.
    11. Six-minute-old data is removed when current time is six minutes later.
    12. Current five-minute data remains.
    """
    # Let's explicitly set the retention to 300 seconds (5 mins)
    redis_buffer.retention_seconds = 300

    # T0 = 1000.0
    base_ts = 1000.0

    # Insert flows from T0 to T0 + 5 minutes
    # 12:00:00 (1000)
    redis_buffer.add_flow({"time": "12:00"}, timestamp=base_ts)
    # 12:01:00 (1060)
    redis_buffer.add_flow({"time": "12:01"}, timestamp=base_ts + 60)
    # 12:02:00 (1120)
    redis_buffer.add_flow({"time": "12:02"}, timestamp=base_ts + 120)
    # 12:03:00 (1180)
    redis_buffer.add_flow({"time": "12:03"}, timestamp=base_ts + 180)
    # 12:04:00 (1240)
    redis_buffer.add_flow({"time": "12:04"}, timestamp=base_ts + 240)
    # 12:05:00 (1300) -> Wait, T0 + 300
    redis_buffer.add_flow({"time": "12:05"}, timestamp=base_ts + 300)

    # The pruning occurs automatically on insertion, using the inserted flow's timestamp as "current"
    # So on inserting 12:05:00 (1300), the cutoff is 1300 - 300 = 1000.
    # We prune strictly less than cutoff (-inf, 1000).
    # This means 12:00 (1000) should SURVIVE!
    assert redis_buffer.count() == 6

    # Now insert at 12:06:00 (1360).
    # Cutoff becomes 1360 - 300 = 1060.
    # Flows strictly older than 1060 are removed. 12:00 (1000) will be removed. 12:01 (1060) survives.
    redis_buffer.add_flow({"time": "12:06"}, timestamp=base_ts + 360)

    assert redis_buffer.count() == 6  # We added one, removed one

    flows = redis_buffer.get_flows()
    times = [f["time"] for f in flows]

    assert "12:00" not in times
    assert "12:01" in times
    assert "12:06" in times


def test_clear_works(redis_buffer):
    """13. clear() works."""
    redis_buffer.add_flow({"test": "data"})
    assert redis_buffer.count() == 1
    redis_buffer.clear()
    assert redis_buffer.count() == 0


@patch("redis.Redis.zadd")
def test_redis_failure_handled_cleanly(mock_zadd, test_key):
    """14. Redis failure is handled cleanly."""
    mock_zadd.side_effect = redis.RedisError("Connection lost")

    buffer = RedisFlowBuffer(key=test_key)

    # Should not raise an exception, just log and return
    buffer.add_flow({"data": "test"})

    # Similarly, retrieval should fail cleanly
    with patch(
        "redis.Redis.zrangebyscore", side_effect=redis.RedisError("Connection lost")
    ):
        assert buffer.get_flows() == []

    with patch("redis.Redis.zcard", side_effect=redis.RedisError("Connection lost")):
        assert buffer.count() == 0


from datetime import datetime


def test_timestamp_parsing_fallback():
    buffer = RedisFlowBuffer(key="test")
    # Missing timestamp
    ts = buffer._parse_timestamp(None)
    assert abs(time.time() - ts) < 2.0

    # Unparseable string
    ts2 = buffer._parse_timestamp("not_a_date")
    assert abs(time.time() - ts2) < 2.0


def test_timestamp_parsing_iso_format():
    """Verify ISO format YYYY-MM-DD is not mangled by dayfirst=True."""
    buffer = RedisFlowBuffer(key="test")

    # 2026-09-10 -> September 10, 2026
    ts = buffer._parse_timestamp("2026-09-10 17:51:52")
    dt = datetime.fromtimestamp(ts)

    assert dt.year == 2026
    assert dt.month == 9
    assert dt.day == 10

    # Fail if it parsed as October 9
    assert dt.month != 10
    assert dt.day != 9


def test_timestamp_parsing_month_boundary():
    """Verify month boundary."""
    buffer = RedisFlowBuffer(key="test")
    ts1 = buffer._parse_timestamp("2026-09-30 23:59:59")
    ts2 = buffer._parse_timestamp("2026-10-01 00:00:01")
    assert ts2 > ts1
    assert ts2 - ts1 == 2.0


def test_timestamp_parsing_year_boundary():
    """Verify year boundary."""
    buffer = RedisFlowBuffer(key="test")
    ts1 = buffer._parse_timestamp("2026-12-31 23:59:59")
    ts2 = buffer._parse_timestamp("2027-01-01 00:00:01")
    assert ts2 > ts1
    assert ts2 - ts1 == 2.0


def test_timestamp_parsing_legacy_cic_format():
    """Verify old CICFlowMeter DD/MM/YYYY parsing."""
    buffer = RedisFlowBuffer(key="test")
    ts = buffer._parse_timestamp("15/02/2018 08:35:18")
    dt = datetime.fromtimestamp(ts)

    assert dt.year == 2018
    assert dt.month == 2
    assert dt.day == 15
