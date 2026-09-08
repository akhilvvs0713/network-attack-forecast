import time
from pathlib import Path
from src.retention.retention_manager import RetentionManager

def test_retention_cleanup(tmp_path: Path):
    out_dir = tmp_path / "events"
    date_dir = out_dir / "2023-01-01"
    date_dir.mkdir(parents=True)
    
    # Create two files: one old, one new
    old_file = date_dir / "10-00.jsonl"
    new_file = date_dir / "11-00.jsonl"
    
    old_file.write_text('{"event": "old"}\n')
    new_file.write_text('{"event": "new"}\n')
    
    manager = RetentionManager(out_dir, retention_minutes=10)
    
    # Fake the modification times.
    # New file: now. Old file: 20 minutes ago.
    now = time.time()
    old_time = now - (20 * 60)
    
    import os
    os.utime(old_file, (old_time, old_time))
    os.utime(new_file, (now, now))
    
    manager._clean_old_files()
    
    assert not old_file.exists()
    assert new_file.exists()
    
def test_retention_cleans_empty_dirs(tmp_path: Path):
    out_dir = tmp_path / "events"
    empty_dir = out_dir / "2023-01-01"
    empty_dir.mkdir(parents=True)
    
    manager = RetentionManager(out_dir, retention_minutes=10)
    manager._clean_old_files()
    
    assert not empty_dir.exists()
