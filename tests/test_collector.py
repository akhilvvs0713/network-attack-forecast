import json
import time
from pathlib import Path
from src.collector.zeek_collector import FileTailer, ZeekCollector


def test_file_tailer(tmp_path: Path):
    log_file = tmp_path / "conn.log"

    # Write initial headers
    with open(log_file, "w") as f:
        f.write("#separator \\x09\n")
        f.write("#path\tconn\n")
        f.write("#fields\tts\tid.orig_h\tid.orig_p\n")

    tailer = FileTailer(log_file)

    # No data yet
    events = tailer.read_new_events()
    assert len(events) == 0

    # Append a line
    with open(log_file, "a") as f:
        f.write("12345.0\t192.168.1.1\t80\n")

    events = tailer.read_new_events()
    assert len(events) == 1
    assert events[0]["src_ip"] == "192.168.1.1"

    # Read again, should be empty
    events = tailer.read_new_events()
    assert len(events) == 0


def test_collector_rotation(tmp_path: Path):
    zeek_dir = tmp_path / "zeek"
    out_dir = tmp_path / "events"
    zeek_dir.mkdir()
    out_dir.mkdir()

    conn_log = zeek_dir / "conn.log"
    with open(conn_log, "w") as f:
        f.write("#separator \\x09\n#path\tconn\n#fields\tts\n")

    collector = ZeekCollector(zeek_dir, out_dir, rotation_minutes=15)

    # Initialize tailer and seek to EOF
    collector.run_once()

    with open(conn_log, "a") as f:
        f.write("12345.0\n")

    processed = collector.run_once()
    assert processed == 1  # 1 data line

    # Rotate log
    collector.tailers["conn.log"].file_handle.close()
    conn_log.rename(zeek_dir / "conn.log.old")

    with open(conn_log, "w") as f:
        f.write("#separator \\x09\n#path\tconn\n#fields\tts\n")
        f.write("12346.0\n")

    processed = collector.run_once()
    assert processed == 1  # picks up the new line in the new file
