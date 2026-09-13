import sys
import time
import signal
import threading
import logging
from config.config import (
    ensure_directories,
    setup_logging,
    ZEEK_LOG_DIR,
    EVENT_OUTPUT_DIR,
    EVENT_ROTATION_MINUTES,
    EVENT_RETENTION_MINUTES,
    NETWORK_INTERFACE,
)
from src.collector.zeek_collector import ZeekCollector
from src.retention.retention_manager import RetentionManager

logger = logging.getLogger(__name__)


class App:
    def __init__(self):
        self.collector = ZeekCollector(
            ZEEK_LOG_DIR, EVENT_OUTPUT_DIR, EVENT_ROTATION_MINUTES
        )
        self.retention = RetentionManager(EVENT_OUTPUT_DIR, EVENT_RETENTION_MINUTES)
        self.collector_thread = None
        self.retention_thread = None

    def start(self):
        logger.info(f"Starting Network Monitor on interface: {NETWORK_INTERFACE}")
        logger.info(f"Zeek logs: {ZEEK_LOG_DIR}")
        logger.info(f"Events output: {EVENT_OUTPUT_DIR}")

        self.collector_thread = threading.Thread(target=self.collector.start)
        self.retention_thread = threading.Thread(target=self.retention.start)

        self.collector_thread.start()
        self.retention_thread.start()

        print("\n" + "=" * 40)
        print("Network Monitor")
        print("Status: RUNNING")
        print(f"Interface: {NETWORK_INTERFACE}")
        print("Collector: RUNNING")
        print("=" * 40 + "\n")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self, signum=None, frame=None):
        logger.info("Initiating graceful shutdown...")
        print("\nShutting down...")
        self.collector.stop()
        self.retention.stop()

        if self.collector_thread:
            self.collector_thread.join()
        if self.retention_thread:
            self.retention_thread.join()

        logger.info("Shutdown complete.")
        sys.exit(0)


if __name__ == "__main__":
    setup_logging()
    ensure_directories()

    app = App()

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, app.stop)
    signal.signal(signal.SIGTERM, app.stop)

    app.start()
