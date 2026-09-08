import pytest
from src.parsers.zeek_parser import ZeekParser

def test_parse_headers():
    parser = ZeekParser()
    headers = [
        "#separator \\x09",
        "#set_separator	,",
        "#empty_field	(empty)",
        "#unset_field	-",
        "#path	conn",
        "#open	2023-01-01-00-00-00",
        "#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents",
        "#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]"
    ]
    
    for h in headers:
        assert parser.parse_line(h) is None
        
    assert parser.path == 'conn'
    assert parser.separator == '\x09'
    assert 'ts' in parser.fields
    assert parser.fields[1] == 'uid'

def test_parse_valid_record():
    parser = ZeekParser()
    parser.path = 'conn'
    parser.fields = ['ts', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto']
    parser.separator = '\t'
    parser.unset_field = '-'
    
    line = "1672531200.123456\t192.168.1.5\t12345\t8.8.8.8\t443\ttcp"
    record = parser.parse_line(line)
    
    assert record is not None
    assert record['ts'] == "1672531200.123456"
    assert record['id.orig_h'] == "192.168.1.5"
    assert record['id.orig_p'] == "12345"
    assert record['id.resp_h'] == "8.8.8.8"
    assert record['id.resp_p'] == "443"
    assert record['proto'] == "tcp"
    assert record['_path'] == "conn"

def test_parse_missing_fields():
    parser = ZeekParser()
    parser.path = 'conn'
    parser.fields = ['ts', 'duration', 'orig_bytes']
    parser.separator = '\t'
    parser.unset_field = '-'
    
    line = "1672531200.123456\t-\t-"
    record = parser.parse_line(line)
    
    assert record['duration'] is None
    assert record['orig_bytes'] is None

def test_parse_malformed_record():
    parser = ZeekParser()
    parser.path = 'conn'
    parser.fields = ['ts', 'id']
    parser.separator = '\t'
    
    line = "1672531200.123456" # missing field
    record = parser.parse_line(line)
    assert record is None
