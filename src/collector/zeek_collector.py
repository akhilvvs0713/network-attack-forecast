import os
import time
import json
import logging
from pathlib import Path
from datetime import datetime
from src.parsers.zeek_parser import ZeekParser
from src.normalizer.event_normalizer import EventNormalizer

logger = logging.getLogger(__name__)


class FileTailer:
    """Tails a single Zeek log file, handling rotation and truncation."""

    def __init__(self, filepath: Path):
        self.filepath = filepath
        self.parser = ZeekParser()
        self.file_handle = None
        self.inode = None
        self.size = 0
        self._open_file(seek_to_eof=True)

    def _open_file(self, seek_to_eof=True):
        if not self.filepath.exists():
            return False

        try:
            stat = os.stat(self.filepath)
            self.file_handle = open(self.filepath, "r")
            self.inode = stat.st_ino

            # Read headers
            while True:
                pos = self.file_handle.tell()
                line = self.file_handle.readline()
                if not line:
                    break
                if line.startswith("#"):
                    self.parser.parse_line(line)
                else:
                    break

            if seek_to_eof:
                # Seek to EOF for initial startup to only process new lines
                self.file_handle.seek(0, 2)
            else:
                # Seek back to just after the headers so we process new data lines
                self.file_handle.seek(pos)

            self.size = self.file_handle.tell()

            return True
        except Exception as e:
            logger.debug(f"Failed to open {self.filepath}: {e}")
            return False

    def read_new_events(self):
        """Reads new lines, parses them, normalizes them, and returns them."""
        events = []
        if not self.file_handle:
            if not self._open_file(seek_to_eof=False):
                return events

        # Check for rotation or truncation
        try:
            stat = os.stat(self.filepath)
            if stat.st_ino != self.inode or stat.st_size < self.size:
                logger.info(f"Log rotation or truncation detected for {self.filepath}")
                self.file_handle.close()
                self.parser = ZeekParser()  # reset parser for new headers
                if not self._open_file(seek_to_eof=False):
                    return events
        except FileNotFoundError:
            logger.debug(f"File {self.filepath} disappeared.")
            self.file_handle.close()
            self.file_handle = None
            return events

        # Read new lines
        while True:
            try:
                line = self.file_handle.readline()
                if not line:
                    break

                self.size += len(line)
                record = self.parser.parse_line(line)
                if record:
                    normalized = EventNormalizer.normalize(record)
                    if normalized:
                        events.append(normalized)
            except ValueError:
                # File was closed (e.g. by rotation test on Windows)
                self.file_handle = None
                break

        return events


class ZeekCollector:
    """Watches a directory for Zeek logs and streams them to an output directory."""

    def __init__(self, zeek_dir: Path, output_dir: Path, rotation_minutes: int):
        self.zeek_dir = zeek_dir
        self.output_dir = output_dir
        self.rotation_minutes = rotation_minutes
        self.tailers = {}
        self.active_logs = ["conn.log", "dns.log", "http.log", "ssl.log", "notice.log"]
        self.events_processed = 0
        self.running = False
        self.current_output_file = None
        self.current_output_period = None

    def _get_output_filepath(self) -> Path:
        """Determines the current output file based on rotation interval."""
        now = datetime.utcnow()
        # Round minute down to nearest rotation interval
        minute = (now.minute // self.rotation_minutes) * self.rotation_minutes
        date_str = now.strftime("%Y-%m-%d")
        time_str = f"{now.hour:02d}-{minute:02d}"

        dir_path = self.output_dir / date_str
        dir_path.mkdir(parents=True, exist_ok=True)

        return dir_path / f"{time_str}.jsonl"

    def _write_events(self, events):
        if not events:
            return

        target_path = self._get_output_filepath()
        try:
            with open(target_path, "a") as f:
                for event in events:
                    f.write(json.dumps(event) + "\n")
            self.events_processed += len(events)
        except Exception as e:
            logger.error(f"Failed to write events to {target_path}: {e}")

    def run_once(self):
        """Perform one pass of checking all active logs."""
        new_events = []
        for log_name in self.active_logs:
            filepath = self.zeek_dir / log_name
            if log_name not in self.tailers:
                self.tailers[log_name] = FileTailer(filepath)

            tailer = self.tailers[log_name]
            events = tailer.read_new_events()
            new_events.extend(events)

        self._write_events(new_events)
        return len(new_events)

    def start(self):
        """Runs the collector continuously."""
        self.running = True
        logger.info(f"Collector started. Watching {self.zeek_dir}")
        while self.running:
            try:
                processed = self.run_once()
                if processed > 0:
                    logger.debug(
                        f"Processed {processed} events. Total: {self.events_processed}"
                    )
                time.sleep(1.0)
            except Exception as e:
                logger.error(f"Collector error: {e}")
                time.sleep(5.0)  # Back off on error

    def stop(self):
        """Stops the collector gracefully."""
        self.running = False
        for tailer in self.tailers.values():
            if tailer.file_handle:
                tailer.file_handle.close()
        logger.info(
            f"Collector stopped. Total events processed: {self.events_processed}"
        )
