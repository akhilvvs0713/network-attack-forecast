#!/usr/bin/env python3
"""Wrapper entry-point for CICFlowMeter that works around a positional-
argument ordering bug in cicflowmeter 0.5.0's ``main()`` function.

Bug summary
-----------
``create_sniffer()`` expects::

    create_sniffer(input_file, input_interface, output_mode, output,
                   input_directory=None, fields=None, verbose=False)

but ``main()`` calls it with positional args in the *old* order (before
``input_directory`` was inserted), so ``args.fields`` lands on
``input_directory`` and ``args.verbose`` (a bool) lands on ``fields``.
``fields.split(",")`` then raises ``AttributeError: 'bool' object has no
attribute 'split'``.

This wrapper reuses the package's argument parser and ``create_sniffer``
but calls it with **keyword arguments** so the mapping is correct.
"""

import sys
import argparse
from cicflowmeter.sniffer import create_sniffer, process_directory, process_directory_merged


def main():
    parser = argparse.ArgumentParser(description="CICFlowMeter (bugfix wrapper)")

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "-i", "--interface", action="store", dest="input_interface",
        help="capture online data from INPUT_INTERFACE",
    )
    input_group.add_argument(
        "-f", "--file", action="store", dest="input_file",
        help="capture offline data from INPUT_FILE",
    )
    input_group.add_argument(
        "-d", "--directory", action="store", dest="input_directory",
        help="process all pcap files from INPUT_DIRECTORY",
    )

    output_group = parser.add_mutually_exclusive_group(required=True)
    output_group.add_argument(
        "-c", "--csv", action="store_const", const="csv", dest="output_mode",
        help="output flows as csv",
    )
    output_group.add_argument(
        "-u", "--url", action="store_const", const="url", dest="output_mode",
        help="output flows as request to url",
    )

    parser.add_argument(
        "output",
        help="output file name (csv mode), url (url mode), or output dir (directory mode)",
    )
    parser.add_argument(
        "--fields", action="store", dest="fields",
        help="comma separated fields to include in output (default: all)",
    )
    parser.add_argument(
        "--merge", action="store_true",
        help="merge all pcap files into a single CSV (-d mode only)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="more verbose")

    args = parser.parse_args()

    if args.merge and not args.input_directory:
        parser.error("--merge can only be used with -d/--directory mode")

    if args.input_directory:
        if args.merge:
            process_directory_merged(
                args.input_directory, args.output, args.fields, args.verbose,
            )
        else:
            process_directory(
                args.input_directory, args.output, args.fields, args.verbose,
            )
        return

    # The fix: use keyword arguments so they map to the correct
    # parameters regardless of signature ordering.
    sniffer, session = create_sniffer(
        input_file=args.input_file,
        input_interface=args.input_interface,
        output_mode=args.output_mode,
        output=args.output,
        input_directory=None,
        fields=args.fields,
        verbose=args.verbose,
    )
    # Add the project root to sys.path so we can import internal modules
    project_root = __import__("pathlib").Path(__file__).resolve().parent.parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    from src.buffer.redis_buffer import RedisFlowBuffer

    # ---------------------------------------------------------
    # Dual Output Adapter: CSV + Redis
    # ---------------------------------------------------------
    redis_buffer = RedisFlowBuffer()
    original_writer = session.output_writer

    class DualWriter:
        def __init__(self, primary, redis_buf):
            self.primary = primary
            self.redis_buf = redis_buf

        def write(self, data: dict) -> None:
            # 1. Write to original destination (e.g. CSV archive)
            if self.primary:
                self.primary.write(data)
            # 2. Write to Redis rolling buffer
            try:
                self.redis_buf.add_flow(data)
            except Exception as e:
                # Fail gracefully if Redis is down, preserve CSV
                import logging
                logging.getLogger("DualWriter").error(f"Redis write failed: {e}")

    session.output_writer = DualWriter(original_writer, redis_buffer)
    # ---------------------------------------------------------

    # Make the sniffer thread a daemon so it cannot block process exit
    # if it hangs on a blocking socket recv after stop() is called.
    sniffer.daemon = True
    sniffer.start()

    import signal
    import time

    shutdown_requested = False

    def handle_signal(signum, frame):
        nonlocal shutdown_requested
        shutdown_requested = True
        sniffer.stop()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        # Polling loop ensures signals are processed immediately
        while sniffer.running and not shutdown_requested:
            time.sleep(0.5)
    except KeyboardInterrupt:
        sniffer.stop()
    finally:
        if hasattr(session, "_gc_stop"):
            session._gc_stop.set()
            session._gc_thread.join(timeout=2.0)

        # Give the sniffer thread a bounded time to exit gracefully,
        # but don't block indefinitely.
        sniffer.join(timeout=3.0)

        # Most critical step: flush the CSV to disk
        session.flush_flows()


if __name__ == "__main__":
    sys.exit(main())
