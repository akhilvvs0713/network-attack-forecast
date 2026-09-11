from unittest.mock import MagicMock
import pytest
from src.collector.cic_wrapper import TripleWriter

def test_triple_writer_unified_identity():
    """9. Same event_id appears in both: Redis ZSET _id and Redis Stream event_id."""
    primary_mock = MagicMock()
    buf_mock = MagicMock()
    strm_mock = MagicMock()

    writer = TripleWriter(primary_mock, buf_mock, strm_mock)

    flow_data = {"src_ip": "10.0.0.1", "timestamp": "2026-09-11 10:00:00"}
    writer.write(flow_data)

    # 1. CSV is called with exact raw flow data (no event_id)
    primary_mock.write.assert_called_once_with(flow_data)

    # 2. Extract event_id from ZSET call
    buf_args, buf_kwargs = buf_mock.add_flow.call_args
    assert buf_args[0] == flow_data
    event_id_zset = buf_kwargs.get("event_id")
    assert event_id_zset is not None

    # 3. Extract event_id from Stream call
    strm_args, strm_kwargs = strm_mock.publish_flow.call_args
    assert strm_args[0] == flow_data
    event_id_stream = strm_kwargs.get("event_id")

    # Both IDs must match exactly
    assert event_id_zset == event_id_stream

def test_triple_writer_stream_failure_does_not_prevent_zset():
    """10. Stream failure does not prevent ZSET."""
    primary_mock = MagicMock()
    buf_mock = MagicMock()
    strm_mock = MagicMock()

    strm_mock.publish_flow.side_effect = Exception("Stream failure")

    writer = TripleWriter(primary_mock, buf_mock, strm_mock)

    flow_data = {"src_ip": "10.0.0.1"}
    # Should not raise exception
    writer.write(flow_data)

    primary_mock.write.assert_called_once()
    buf_mock.add_flow.assert_called_once()
    strm_mock.publish_flow.assert_called_once()

def test_triple_writer_zset_failure_does_not_prevent_stream():
    """11. ZSET failure does not prevent Stream."""
    primary_mock = MagicMock()
    buf_mock = MagicMock()
    strm_mock = MagicMock()

    buf_mock.add_flow.side_effect = Exception("ZSET failure")

    writer = TripleWriter(primary_mock, buf_mock, strm_mock)

    flow_data = {"src_ip": "10.0.0.1"}
    # Should not raise exception
    writer.write(flow_data)

    primary_mock.write.assert_called_once()
    buf_mock.add_flow.assert_called_once()
    strm_mock.publish_flow.assert_called_once()

def test_csv_behavior_remains_unchanged():
    """12. CSV behavior remains unchanged."""
    primary_mock = MagicMock()
    buf_mock = MagicMock()
    strm_mock = MagicMock()

    writer = TripleWriter(primary_mock, buf_mock, strm_mock)

    flow_data = {"src_ip": "10.0.0.1"}
    writer.write(flow_data)

    # The dictionary passed to primary.write must not contain event_id or _id
    written_data = primary_mock.write.call_args[0][0]
    assert "event_id" not in written_data
    assert "_id" not in written_data
    assert written_data == flow_data
