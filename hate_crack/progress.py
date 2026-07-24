"""Generic terminal progress utilities for hate_crack.

Provides a context manager that shows a live spinner with elapsed-seconds
counter while a blocking operation runs.  Safe to use in non-TTY environments:
if stdout is not a TTY the message is printed once and no background thread is
started.
"""

from __future__ import annotations

import sys
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager

_SPINNER_FRAMES = ["|", "/", "-", "\\"]
_TICK_INTERVAL = 0.12  # seconds between repaints (~120 ms)


@contextmanager
def spinner(message: str) -> "Generator[None, None, None]":
    """Context manager that shows *message* plus a live elapsed-seconds counter.

    While the body executes a daemon thread repaints a single terminal line
    roughly every 120 ms showing:

        | Generating password candidates via Ollama (model)...  3s

    On exit (normal or exceptional) the spinner line is erased so subsequent
    output starts on a clean line.

    TTY guard: if ``sys.stdout.isatty()`` is False the message is printed once
    via ``print()`` and no thread is started, keeping piped output and the test
    suite clean.
    """
    if not sys.stdout.isatty():
        print(message)
        yield
        return

    stop_event = threading.Event()
    start_time = time.monotonic()

    def _run() -> None:
        frame_idx = 0
        while not stop_event.is_set():
            elapsed = int(time.monotonic() - start_time)
            frame = _SPINNER_FRAMES[frame_idx % len(_SPINNER_FRAMES)]
            line = f"\r{frame} {message}  {elapsed}s"
            sys.stdout.write(line)
            sys.stdout.flush()
            frame_idx += 1
            stop_event.wait(_TICK_INTERVAL)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop_event.set()
        # Clear *after* the join, so a thread sitting just past its is_set()
        # check cannot repaint the line after we erase it.  The nested finally
        # keeps that guarantee even when join() is interrupted: hate_crack's
        # _sigint_handler raises DoubleInterrupt on a second SIGINT within 2 s,
        # and join() can block up to _TICK_INTERVAL (0.12 s).
        try:
            thread.join()
        finally:
            sys.stdout.write("\033[2K\r")
            sys.stdout.flush()
