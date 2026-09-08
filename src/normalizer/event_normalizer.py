import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class EventNormalizer:
    """Converts parsed Zeek records into standard JSON representations."""
    
    @staticmethod
    def normalize(record: dict) -> dict:
        """
        Normalizes a parsed Zeek record based on its _path (event type).
        Returns a normalized dictionary, or None if it cannot be normalized.
        """
        if not record:
            return None
            
        path = record.get('_path')
        if not path:
            return None
            
        try:
            if path == 'conn':
                return EventNormalizer._normalize_conn(record)
            elif path == 'dns':
                return EventNormalizer._normalize_dns(record)
            elif path == 'http':
                return EventNormalizer._normalize_http(record)
            else:
                return EventNormalizer._normalize_generic(record, path)
        except Exception as e:
            logger.debug(f"Error normalizing {path} event: {e}")
            return None

    @staticmethod
    def _parse_timestamp(ts: str) -> str:
        """Converts Zeek epoch timestamp to ISO 8601 string."""
        if not ts:
            return datetime.utcnow().isoformat() + "Z"
        try:
            dt = datetime.fromtimestamp(float(ts))
            return dt.isoformat() + "Z"
        except ValueError:
            return ts

    @staticmethod
    def _safe_int(val):
        if val is None:
            return None
        try:
            return int(val)
        except ValueError:
            return None

    @staticmethod
    def _safe_float(val):
        if val is None:
            return None
        try:
            return float(val)
        except ValueError:
            return None

    @staticmethod
    def _normalize_conn(record: dict) -> dict:
        return {
            "timestamp": EventNormalizer._parse_timestamp(record.get('ts')),
            "event_type": "connection",
            "src_ip": record.get('id.orig_h'),
            "src_port": EventNormalizer._safe_int(record.get('id.orig_p')),
            "dst_ip": record.get('id.resp_h'),
            "dst_port": EventNormalizer._safe_int(record.get('id.resp_p')),
            "protocol": record.get('proto'),
            "duration": EventNormalizer._safe_float(record.get('duration')),
            "orig_bytes": EventNormalizer._safe_int(record.get('orig_bytes')),
            "resp_bytes": EventNormalizer._safe_int(record.get('resp_bytes')),
            "orig_pkts": EventNormalizer._safe_int(record.get('orig_pkts')),
            "resp_pkts": EventNormalizer._safe_int(record.get('resp_pkts')),
            "conn_state": record.get('conn_state')
        }

    @staticmethod
    def _normalize_dns(record: dict) -> dict:
        return {
            "timestamp": EventNormalizer._parse_timestamp(record.get('ts')),
            "event_type": "dns",
            "src_ip": record.get('id.orig_h'),
            "src_port": EventNormalizer._safe_int(record.get('id.orig_p')),
            "dst_ip": record.get('id.resp_h'),
            "dst_port": EventNormalizer._safe_int(record.get('id.resp_p')),
            "protocol": record.get('proto'),
            "query": record.get('query'),
            "qclass_name": record.get('qclass_name'),
            "qtype_name": record.get('qtype_name'),
            "rcode_name": record.get('rcode_name'),
            "answers": record.get('answers')
        }

    @staticmethod
    def _normalize_http(record: dict) -> dict:
        return {
            "timestamp": EventNormalizer._parse_timestamp(record.get('ts')),
            "event_type": "http",
            "src_ip": record.get('id.orig_h'),
            "src_port": EventNormalizer._safe_int(record.get('id.orig_p')),
            "dst_ip": record.get('id.resp_h'),
            "dst_port": EventNormalizer._safe_int(record.get('id.resp_p')),
            "method": record.get('method'),
            "host": record.get('host'),
            "uri": record.get('uri'),
            "status_code": EventNormalizer._safe_int(record.get('status_code')),
            "user_agent": record.get('user_agent')
        }

    @staticmethod
    def _normalize_generic(record: dict, path: str) -> dict:
        event = {
            "timestamp": EventNormalizer._parse_timestamp(record.get('ts')),
            "event_type": path,
            "src_ip": record.get('id.orig_h'),
            "src_port": EventNormalizer._safe_int(record.get('id.orig_p')),
            "dst_ip": record.get('id.resp_h'),
            "dst_port": EventNormalizer._safe_int(record.get('id.resp_p')),
        }
        # Add remaining fields safely
        for k, v in record.items():
            if k not in ['ts', '_path', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p']:
                event[k] = v
        return event
