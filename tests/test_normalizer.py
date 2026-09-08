import pytest
from src.normalizer.event_normalizer import EventNormalizer

def test_normalize_conn():
    record = {
        '_path': 'conn',
        'ts': '1672531200.123456',
        'id.orig_h': '192.168.1.5',
        'id.orig_p': '12345',
        'id.resp_h': '8.8.8.8',
        'id.resp_p': '443',
        'proto': 'tcp',
        'duration': '1.42',
        'orig_bytes': '1234',
        'resp_bytes': '5678',
        'orig_pkts': '12',
        'resp_pkts': '18',
        'conn_state': 'SF'
    }
    
    event = EventNormalizer.normalize(record)
    assert event['event_type'] == 'connection'
    assert event['src_ip'] == '192.168.1.5'
    assert event['src_port'] == 12345
    assert event['dst_ip'] == '8.8.8.8'
    assert event['dst_port'] == 443
    assert event['protocol'] == 'tcp'
    assert event['duration'] == 1.42
    assert event['orig_bytes'] == 1234
    assert event['resp_bytes'] == 5678
    assert event['orig_pkts'] == 12
    assert event['resp_pkts'] == 18
    assert event['conn_state'] == 'SF'
    # ts conversion: 1672531200 is 2023-01-01 00:00:00 UTC
    assert event['timestamp'].startswith('2023-01-01')

def test_normalize_nulls():
    record = {
        '_path': 'conn',
        'ts': '1672531200.0',
        'duration': None,
        'orig_bytes': None
    }
    event = EventNormalizer.normalize(record)
    assert event['duration'] is None
    assert event['orig_bytes'] is None

def test_normalize_dns():
    record = {
        '_path': 'dns',
        'ts': '1672531200.0',
        'query': 'example.com',
        'qtype_name': 'A',
        'rcode_name': 'NOERROR'
    }
    event = EventNormalizer.normalize(record)
    assert event['event_type'] == 'dns'
    assert event['query'] == 'example.com'
    assert event['qtype_name'] == 'A'
    assert event['rcode_name'] == 'NOERROR'

def test_normalize_generic():
    record = {
        '_path': 'weird',
        'ts': '1672531200.0',
        'name': 'bad_TCP_checksum',
        'notice': 'true'
    }
    event = EventNormalizer.normalize(record)
    assert event['event_type'] == 'weird'
    assert event['name'] == 'bad_TCP_checksum'
