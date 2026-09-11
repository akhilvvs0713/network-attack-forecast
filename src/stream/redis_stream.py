import json
import logging
import uuid
from typing import Dict, Any, Optional

import redis

from config import config

logger = logging.getLogger("NetworkMonitor.RedisStream")


class RedisFlowStream:
    """
    Publishes network flows to a Redis Stream.
    This component runs alongside the existing Redis ZSET buffer.
    """

    def __init__(
        self,
        host: str = config.REDIS_HOST,
        port: int = config.REDIS_PORT,
        db: int = config.REDIS_DB,
        key: str = config.REDIS_STREAM_KEY,
        maxlen: int = config.REDIS_STREAM_MAXLEN,
    ):
        self.host = host
        self.port = port
        self.db = db
        self.key = key
        self.maxlen = maxlen

        self.client = redis.Redis(
            host=self.host,
            port=self.port,
            db=self.db,
            decode_responses=True,
        )

    def ping(self) -> bool:
        """Verify Redis connectivity."""
        try:
            return self.client.ping()
        except redis.RedisError as e:
            logger.error(f"Redis ping failed: {e}")
            return False

    def _serialize_fields(self, flow: Dict[str, Any]) -> Dict[str, str]:
        """
        Convert flow dictionary values to string/scalar formats
        safe for Redis Stream fields.
        """
        serialized = {}
        for k, v in flow.items():
            if v is None:
                serialized[k] = ""
            elif isinstance(v, (dict, list)):
                serialized[k] = json.dumps(v)
            else:
                serialized[k] = str(v)
        return serialized

    def publish_flow(self, flow: Dict[str, Any], event_id: Optional[str] = None) -> Optional[str]:
        """
        Publish a normalized flow to the Redis Stream using XADD.
        Ensures exact source timestamp preservation and unifies event_id.
        Returns the generated Redis stream ID or None on failure/missing timestamp.
        """
        flow_record = flow.copy()

        # Enforce exact source timestamp
        if "timestamp" not in flow_record:
            logger.warning("Flow is missing exact source 'timestamp', skipping stream publication.")
            return None

        # Inject unique event_id if not present
        if event_id:
            flow_record["event_id"] = event_id
        elif "event_id" not in flow_record:
            if "_id" in flow_record:
                flow_record["event_id"] = flow_record["_id"]
            else:
                flow_record["event_id"] = str(uuid.uuid4())

        stream_fields = self._serialize_fields(flow_record)

        try:
            # XADD key * maxlen ~ MAXLEN ...fields
            # approximate maxlen (~) is more efficient
            stream_id = self.client.xadd(
                self.key, stream_fields, maxlen=self.maxlen, approximate=True
            )
            return stream_id
        except redis.RedisError as e:
            logger.error(f"Failed to publish flow to Redis Stream: {e}")
            return None

    def clear(self) -> None:
        """Clear the stream completely (useful for tests)."""
        try:
            self.client.delete(self.key)
        except redis.RedisError as e:
            logger.error(f"Failed to clear Redis stream: {e}")
