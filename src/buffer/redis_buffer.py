import json
import logging
import time
import uuid
from typing import Dict, List, Optional, Any
from datetime import datetime

import redis
from dateutil import parser as date_parser

from config import config

logger = logging.getLogger("NetworkMonitor.RedisBuffer")


class RedisFlowBuffer:
    """
    Rolling buffer for network flows using Redis Sorted Sets.

    Acts as short-lived working memory for the most recent traffic
    (default 5 minutes), allowing older flows to drop off as new
    traffic arrives.
    """

    def __init__(
        self,
        host: str = config.REDIS_HOST,
        port: int = config.REDIS_PORT,
        db: int = config.REDIS_DB,
        key: str = config.REDIS_FLOW_KEY,
        retention_seconds: int = config.REDIS_RETENTION_SECONDS,
    ):
        self.host = host
        self.port = port
        self.db = db
        self.key = key
        self.retention_seconds = retention_seconds

        # Connect to Redis
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

    def _parse_timestamp(self, ts_val: Any) -> float:
        """
        Robustly parse a flow timestamp into a Unix epoch float.
        Fallback to current time if parsing fails or is missing.
        """
        if not ts_val:
            return time.time()

        try:
            # If it's already a float or int
            return float(ts_val)
        except (ValueError, TypeError):
            pass

        import re

        ts_str = str(ts_val).strip()
        try:
            # ISO-like format: YYYY-MM-DD...
            if re.match(r"^\d{4}-\d{2}-\d{2}", ts_str):
                dt = date_parser.parse(ts_str, dayfirst=False)
            # Legacy CICFlowMeter format: DD/MM/YYYY...
            elif re.match(r"^\d{1,2}/\d{1,2}/\d{4}", ts_str):
                dt = date_parser.parse(ts_str, dayfirst=True)
            else:
                dt = date_parser.parse(ts_str)
            return dt.timestamp()
        except Exception as e:
            logger.debug(
                f"Failed to parse timestamp '{ts_val}', falling back to current time: {e}"
            )
            return time.time()

    def add_flow(self, flow: Dict[str, Any], timestamp: Optional[float] = None, event_id: Optional[str] = None) -> None:
        """
        Add a flow to the rolling buffer and automatically prune old entries.
        """
        if timestamp is None:
            timestamp = self._parse_timestamp(flow.get("timestamp"))

        # Inject a unique ID so identical flows aren't overwritten in the Sorted Set
        flow_record = flow.copy()
        if event_id:
            flow_record["_id"] = event_id
        elif "_id" not in flow_record:
            flow_record["_id"] = str(uuid.uuid4())

        try:
            serialized = json.dumps(flow_record)
            # zadd expects mapping {member: score}
            self.client.zadd(self.key, {serialized: timestamp})

            # Prune old traffic automatically based on the newly inserted timestamp
            self.prune(current_timestamp=timestamp)
        except redis.RedisError as e:
            logger.error(f"Failed to add flow to Redis: {e}")

    def get_flows(
        self,
        start_timestamp: Optional[float] = None,
        end_timestamp: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve flows within the specified time range.
        If no range is provided, returns all flows currently in the buffer (the rolling window).
        """
        min_score = start_timestamp if start_timestamp is not None else "-inf"
        max_score = end_timestamp if end_timestamp is not None else "+inf"

        try:
            records = self.client.zrangebyscore(self.key, min_score, max_score)
            return [json.loads(record) for record in records]
        except redis.RedisError as e:
            logger.error(f"Failed to retrieve flows from Redis: {e}")
            return []

    def prune(self, current_timestamp: Optional[float] = None) -> int:
        """
        Remove flows older than retention_seconds relative to current_timestamp.
        Returns the number of removed entries.
        """
        if current_timestamp is None:
            current_timestamp = time.time()

        cutoff = current_timestamp - self.retention_seconds

        try:
            # ZREMRANGEBYSCORE is inclusive by default for min/max.
            # To exclude the exact cutoff boundary we could use '({cutoff}'
            # but usually inclusive is fine for pruning. We will use strictly less than
            # to be safe and match the strict boundary semantic: (-inf, cutoff)
            cutoff_str = f"({cutoff}"
            removed = self.client.zremrangebyscore(self.key, "-inf", cutoff_str)
            return removed
        except redis.RedisError as e:
            logger.error(f"Failed to prune flows in Redis: {e}")
            return 0

    def count(self) -> int:
        """Return the current number of buffered flows."""
        try:
            return self.client.zcard(self.key)
        except redis.RedisError as e:
            logger.error(f"Failed to count flows in Redis: {e}")
            return 0

    def clear(self) -> None:
        """Clear the buffer completely (useful for tests)."""
        try:
            self.client.delete(self.key)
        except redis.RedisError as e:
            logger.error(f"Failed to clear Redis buffer: {e}")
