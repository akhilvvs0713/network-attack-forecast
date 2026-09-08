import time
import logging
from pathlib import Path
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class RetentionManager:
    """Manages the lifecycle of normalized event files in the live buffer."""
    
    def __init__(self, output_dir: Path, retention_minutes: int):
        self.output_dir = output_dir
        self.retention_minutes = retention_minutes
        self.running = False
        
    def _clean_old_files(self):
        """Scans and removes files older than the retention limit."""
        if self.retention_minutes <= 0:
            return
            
        cutoff_ts = time.time() - (self.retention_minutes * 60)
        
        deleted_count = 0
        try:
            for filepath in self.output_dir.rglob('*.jsonl'):
                if filepath.is_file():
                    stat = filepath.stat()
                    # Use modification time for retention logic
                    if stat.st_mtime < cutoff_ts:
                        filepath.unlink()
                        logger.info(f"Retention manager deleted old file: {filepath.name}")
                        deleted_count += 1
                        
            # Clean up empty date directories
            for dirpath in self.output_dir.glob('*/'):
                if dirpath.is_dir() and not any(dirpath.iterdir()):
                    dirpath.rmdir()
                    logger.debug(f"Removed empty directory: {dirpath.name}")
                    
        except Exception as e:
            logger.error(f"Error during retention cleanup: {e}")

    def start(self):
        """Runs the retention manager continuously in a loop."""
        self.running = True
        logger.info(f"Retention manager started. Retention: {self.retention_minutes} minutes")
        while self.running:
            self._clean_old_files()
            # Sleep for a minute before checking again
            for _ in range(60):
                if not self.running:
                    break
                time.sleep(1)

    def stop(self):
        self.running = False
        logger.info("Retention manager stopped.")
