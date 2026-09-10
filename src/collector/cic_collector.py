import os
import time
import signal
import logging
import subprocess
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


class CICCollector:
    """Captures live network traffic using CICFlowMeter and writes
    timestamped CSV files to a configurable output directory.

    CICFlowMeter is invoked as a subprocess so that its raw CSV output
    is preserved exactly as produced — no feature transformation is
    applied.  Rotation is handled by periodically stopping and
    restarting the subprocess with a new output filename.
    """

    def __init__(
        self,
        output_dir: Path,
        interface: str = "eth0",
        rotation_minutes: int = 1,
    ):
        self.output_dir = Path(output_dir)
        self.interface = interface
        self.rotation_minutes = max(1, rotation_minutes)
        self.running = False
        self._process: subprocess.Popen | None = None
        self._current_file: Path | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self):
        """Run the collector loop.  Blocks until ``stop()`` is called
        (typically from another thread or a signal handler)."""
        self.running = True

        # Validate that the wrapper and venv Python are available
        try:
            python_bin, wrapper = self._resolve_wrapper()
        except FileNotFoundError as exc:
            logger.error("CIC collector cannot start: %s", exc)
            return

        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(
            "CIC collector started — interface=%s  output=%s  rotation=%dm",
            self.interface,
            self.output_dir,
            self.rotation_minutes,
        )

        try:
            while self.running:
                target = self._next_output_path()
                self._start_capture(target)

                # Sleep in 1-second ticks until the rotation boundary
                sleep_seconds = self._seconds_until_next_rotation()
                for _ in range(sleep_seconds):
                    if not self.running:
                        break
                    time.sleep(1)

                self._stop_capture()
        except Exception as exc:
            logger.error("CIC collector error: %s", exc)
        finally:
            self._stop_capture()
            logger.info("CIC collector stopped.")

    def stop(self):
        """Signal the collector to shut down gracefully."""
        self.running = False
        self._stop_capture()

    # ------------------------------------------------------------------
    # Capture lifecycle
    # ------------------------------------------------------------------

    def _start_capture(self, output_path: Path):
        """Launch a cicflowmeter subprocess writing to *output_path*.

        Uses our ``cic_wrapper.py`` instead of the installed
        ``cicflowmeter`` entry-point to work around a positional-argument
        bug in cicflowmeter 0.5.0 (see ``cic_wrapper.py`` docstring).
        """
        if self._process is not None:
            self._stop_capture()

        python_bin, wrapper_script = self._resolve_wrapper()
        cmd = [
            python_bin,
            wrapper_script,
            "-i", self.interface,
            "-c", str(output_path),
        ]
        logger.info("Starting capture → %s", output_path.name)
        logger.debug("Command: %s", " ".join(cmd))

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            self._current_file = output_path
        except FileNotFoundError:
            logger.error("cicflowmeter binary not found at: %s", self._cicflowmeter_bin)
            self._process = None
        except PermissionError:
            logger.error(
                "Permission denied launching cicflowmeter.  "
                "Live capture requires root — try running with sudo."
            )
            self._process = None

    def _stop_capture(self):
        """Gracefully terminate the running cicflowmeter subprocess."""
        proc = self._process
        if proc is None:
            return

        # Send SIGINT for graceful flush, then wait briefly
        try:
            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            logger.warning("cicflowmeter did not exit after SIGINT, sending SIGTERM")
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logger.warning("cicflowmeter did not exit after SIGTERM, killing")
                proc.kill()
                proc.wait()
        except Exception as exc:
            logger.debug("Error stopping cicflowmeter: %s", exc)

        # Log stderr from the completed process
        if proc.stderr:
            try:
                stderr_output = proc.stderr.read().decode("utf-8", errors="replace").strip()
                if stderr_output:
                    logger.debug("cicflowmeter stderr: %s", stderr_output)
            except Exception:
                pass

        self._process = None

        # Log result for the finished file
        if self._current_file and self._current_file.exists():
            size = self._current_file.stat().st_size
            logger.info(
                "Capture complete: %s (%d bytes)",
                self._current_file.name,
                size,
            )
        self._current_file = None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _next_output_path(self) -> Path:
        """Return the output CSV path for the current rotation window."""
        now = datetime.utcnow()
        minute = (now.minute // self.rotation_minutes) * self.rotation_minutes
        filename = now.strftime(f"%Y-%m-%d_{now.hour:02d}-{minute:02d}").replace(
            f"{now.hour:02d}-{minute:02d}",
            f"{now.hour:02d}-{minute:02d}",
        )
        # Simpler: build the name directly
        filename = f"flows_{now.strftime('%Y-%m-%d')}_{now.hour:02d}-{minute:02d}.csv"
        return self.output_dir / filename

    def _seconds_until_next_rotation(self) -> int:
        """Seconds remaining until the next rotation boundary."""
        now = datetime.utcnow()
        current_slot_minute = (now.minute // self.rotation_minutes) * self.rotation_minutes
        next_slot_minute = current_slot_minute + self.rotation_minutes

        if next_slot_minute >= 60:
            # Rolls over to next hour; for simplicity cap at 60
            remaining_in_hour = 60 - now.minute
            remaining_seconds = (remaining_in_hour * 60) - now.second
        else:
            remaining_seconds = ((next_slot_minute - now.minute) * 60) - now.second

        return max(1, remaining_seconds)

    @staticmethod
    def _resolve_wrapper() -> tuple[str, str]:
        """Return ``(python_binary, wrapper_script)`` for launching
        CICFlowMeter via our bugfix wrapper.

        Both paths are derived from this module's location so they work
        even under ``sudo`` where PATH does not include the venv.

        Raises :class:`FileNotFoundError` if either component is missing.
        """
        # Derive project root: this file is src/collector/cic_collector.py
        project_root = Path(__file__).resolve().parent.parent.parent

        venv_python = project_root / ".venv" / "bin" / "python"
        if not venv_python.is_file():
            # Fallback: try python3
            venv_python = project_root / ".venv" / "bin" / "python3"

        wrapper = project_root / "src" / "collector" / "cic_wrapper.py"

        if not venv_python.is_file():
            raise FileNotFoundError(
                f"Venv Python not found at {venv_python}. "
                f"Create a venv with: python3 -m venv {project_root / '.venv'}"
            )
        if not wrapper.is_file():
            raise FileNotFoundError(
                f"CIC wrapper script not found at {wrapper}"
            )

        return str(venv_python), str(wrapper)

    @staticmethod
    def output_filename_for(dt: datetime, rotation_minutes: int = 1) -> str:
        """Public helper: compute the output filename for a given datetime.
        Useful for tests and for consumers that need to predict file names."""
        minute = (dt.minute // rotation_minutes) * rotation_minutes
        return f"flows_{dt.strftime('%Y-%m-%d')}_{dt.hour:02d}-{minute:02d}.csv"
