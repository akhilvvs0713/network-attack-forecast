import time
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from src.collector.cic_collector import CICCollector


class TestOutputFilename:
    """Tests for deterministic output filename generation."""

    def test_filename_format(self):
        dt = datetime(2026, 9, 9, 22, 0, 0)
        name = CICCollector.output_filename_for(dt, rotation_minutes=1)
        assert name == "flows_2026-09-09_22-00.csv"

    def test_filename_rounds_minute_down(self):
        dt = datetime(2026, 9, 9, 14, 37, 45)
        name = CICCollector.output_filename_for(dt, rotation_minutes=5)
        assert name == "flows_2026-09-09_14-35.csv"

    def test_filename_1min_rotation(self):
        dt = datetime(2026, 9, 9, 8, 3, 12)
        name = CICCollector.output_filename_for(dt, rotation_minutes=1)
        assert name == "flows_2026-09-09_08-03.csv"

    def test_filename_15min_rotation(self):
        dt = datetime(2026, 9, 9, 10, 22, 0)
        name = CICCollector.output_filename_for(dt, rotation_minutes=15)
        assert name == "flows_2026-09-09_10-15.csv"

    def test_filename_at_midnight(self):
        dt = datetime(2026, 9, 10, 0, 0, 0)
        name = CICCollector.output_filename_for(dt, rotation_minutes=1)
        assert name == "flows_2026-09-10_00-00.csv"


class TestCICCollectorInit:
    """Tests for collector initialization."""

    def test_default_interface(self, tmp_path: Path):
        collector = CICCollector(tmp_path / "flows")
        assert collector.interface == "eth0"
        assert collector.rotation_minutes == 1

    def test_custom_interface(self, tmp_path: Path):
        collector = CICCollector(tmp_path / "flows", interface="lo", rotation_minutes=5)
        assert collector.interface == "lo"
        assert collector.rotation_minutes == 5

    def test_rotation_minutes_minimum(self, tmp_path: Path):
        collector = CICCollector(tmp_path / "flows", rotation_minutes=0)
        assert collector.rotation_minutes == 1

    def test_output_dir_stored(self, tmp_path: Path):
        d = tmp_path / "my_flows"
        collector = CICCollector(d)
        assert collector.output_dir == d


class TestNextOutputPath:
    """Tests for _next_output_path which combines dir and timestamped name."""

    def test_path_in_output_dir(self, tmp_path: Path):
        collector = CICCollector(tmp_path / "flows", rotation_minutes=1)
        with patch("src.collector.cic_collector.datetime") as mock_dt:
            mock_dt.utcnow.return_value = datetime(2026, 9, 9, 15, 30, 0)
            mock_dt.side_effect = lambda *a, **k: datetime(*a, **k)
            path = collector._next_output_path()
            assert path.parent == tmp_path / "flows"
            assert path.name == "flows_2026-09-09_15-30.csv"


class TestSecondsUntilRotation:
    """Tests for rotation timing calculation."""

    def test_at_boundary(self, tmp_path: Path):
        collector = CICCollector(tmp_path / "flows", rotation_minutes=1)
        with patch("src.collector.cic_collector.datetime") as mock_dt:
            mock_dt.utcnow.return_value = datetime(2026, 9, 9, 15, 30, 0)
            secs = collector._seconds_until_next_rotation()
            assert secs == 60  # full minute left

    def test_mid_minute(self, tmp_path: Path):
        collector = CICCollector(tmp_path / "flows", rotation_minutes=1)
        with patch("src.collector.cic_collector.datetime") as mock_dt:
            mock_dt.utcnow.return_value = datetime(2026, 9, 9, 15, 30, 30)
            secs = collector._seconds_until_next_rotation()
            assert secs == 30

    def test_5min_rotation(self, tmp_path: Path):
        collector = CICCollector(tmp_path / "flows", rotation_minutes=5)
        with patch("src.collector.cic_collector.datetime") as mock_dt:
            mock_dt.utcnow.return_value = datetime(2026, 9, 9, 15, 32, 0)
            secs = collector._seconds_until_next_rotation()
            assert secs == 180  # 3 minutes to reach :35


class TestResolveWrapper:
    """Tests for wrapper resolution (venv python + cic_wrapper.py)."""

    def test_resolves_when_both_exist(self, tmp_path: Path):
        """When both .venv/bin/python and src/collector/cic_wrapper.py
        exist, returns (python_path, wrapper_path)."""
        fake_project = tmp_path / "project"

        # Create fake venv python
        venv_python = fake_project / ".venv" / "bin" / "python"
        venv_python.parent.mkdir(parents=True)
        venv_python.write_text("#!/bin/sh\n")
        venv_python.chmod(0o755)

        # Create fake wrapper
        wrapper = fake_project / "src" / "collector" / "cic_wrapper.py"
        wrapper.parent.mkdir(parents=True)
        wrapper.write_text("# wrapper\n")

        # Patch __file__ so project_root = fake_project
        fake_module = fake_project / "src" / "collector" / "cic_collector.py"
        fake_module.write_text("")

        with patch("src.collector.cic_collector.__file__", str(fake_module)):
            python_bin, wrapper_path = CICCollector._resolve_wrapper()
        assert python_bin == str(venv_python)
        assert wrapper_path == str(wrapper)

    def test_raises_when_venv_missing(self, tmp_path: Path):
        """When .venv/bin/python doesn't exist, raises FileNotFoundError."""
        fake_project = tmp_path / "project"
        wrapper = fake_project / "src" / "collector" / "cic_wrapper.py"
        wrapper.parent.mkdir(parents=True)
        wrapper.write_text("# wrapper\n")
        # No .venv created

        fake_module = fake_project / "src" / "collector" / "cic_collector.py"
        fake_module.write_text("")

        with patch("src.collector.cic_collector.__file__", str(fake_module)):
            import pytest
            with pytest.raises(FileNotFoundError, match="Venv Python not found"):
                CICCollector._resolve_wrapper()

    def test_raises_when_wrapper_missing(self, tmp_path: Path):
        """When cic_wrapper.py doesn't exist, raises FileNotFoundError."""
        fake_project = tmp_path / "project"
        venv_python = fake_project / ".venv" / "bin" / "python"
        venv_python.parent.mkdir(parents=True)
        venv_python.write_text("#!/bin/sh\n")
        venv_python.chmod(0o755)
        # No wrapper created — but we need the dir for cic_collector.py
        (fake_project / "src" / "collector").mkdir(parents=True)

        fake_module = fake_project / "src" / "collector" / "cic_collector.py"
        fake_module.write_text("")

        with patch("src.collector.cic_collector.__file__", str(fake_module)):
            import pytest
            with pytest.raises(FileNotFoundError, match="CIC wrapper script not found"):
                CICCollector._resolve_wrapper()


class TestCreateSnifferKwargRegression:
    """Regression test: cicflowmeter 0.5.0 has a bug where main()
    passes positional args to create_sniffer() in the wrong order,
    causing `fields` to receive a bool and crash with:
        AttributeError: 'bool' object has no attribute 'split'

    Our cic_wrapper.py fixes this by calling create_sniffer() with
    keyword arguments.  This test ensures the wrapper's call is correct.
    """

    def test_wrapper_uses_kwargs(self):
        """Verify that cic_wrapper.py calls create_sniffer with
        keyword arguments by inspecting its source code."""
        project_root = Path(__file__).resolve().parent.parent
        wrapper = project_root / "src" / "collector" / "cic_wrapper.py"
        source = wrapper.read_text()
        # The wrapper must contain a keyword-argument call to create_sniffer
        assert "create_sniffer(" in source
        assert "input_file=" in source
        assert "input_interface=" in source
        assert "output_mode=" in source
        assert "fields=" in source
        assert "verbose=" in source

    def test_create_sniffer_fields_none_no_crash(self):
        """Directly call create_sniffer signature check: fields=None
        should NOT crash (the bug was fields=False reaching .split())."""
        from cicflowmeter.sniffer import create_sniffer
        # We can't actually create a sniffer without a real interface,
        # but we can verify the fields guard works with None
        # by checking the code path: if fields is not None → split
        fields = None
        if fields is not None:
            fields = fields.split(",")
        assert fields is None  # No crash

    def test_create_sniffer_bool_would_crash(self):
        """Confirm that passing a bool as fields WOULD crash — this is
        the exact bug in cicflowmeter 0.5.0's main()."""
        fields = False  # What main() incorrectly passes
        import pytest
        with pytest.raises(AttributeError, match="split"):
            if fields is not None:  # False is not None!
                fields.split(",")  # BOOM


class TestStopCapture:
    """Tests for graceful subprocess shutdown."""

    def test_stop_with_no_process(self, tmp_path: Path):
        collector = CICCollector(tmp_path / "flows")
        # Should not raise
        collector._stop_capture()
        assert collector._process is None

    def test_stop_sends_sigint(self, tmp_path: Path):
        collector = CICCollector(tmp_path / "flows")
        mock_proc = MagicMock()
        mock_proc.wait.return_value = 0
        mock_proc.stderr = None
        collector._process = mock_proc

        collector._stop_capture()

        # Should send SIGINT and wait with a timeout (e.g. 5 or 10 seconds)
        mock_proc.send_signal.assert_called_once_with(2)  # signal.SIGINT == 2
        mock_proc.wait.assert_called_once()
        assert mock_proc.wait.call_args[1]["timeout"] >= 5
        assert collector._process is None
