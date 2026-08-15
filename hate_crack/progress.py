"""Generic terminal progress utilities for hate_crack.

Provides a context manager that shows a live spinner with elapsed-seconds
counter while a blocking operation runs.  Safe to use in non-TTY environments:
if stdout is not a TTY the message is printed once and no background thread is
started.

The context manager yields a :class:`SpinnerHandle` so long operations can push
a detail string ("4,120,000 lines") into the same line as they go.  Elapsed
seconds alone are ambiguous once a pass runs into the tens of seconds: a
corpus profile of a multi-million-line wordlist looks exactly like a hang.
"""

from __future__ import annotations

import sys
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager

_SPINNER_FRAMES = ["|", "/", "-", "\\"]
_TICK_INTERVAL = 0.12  # seconds between repaints (~120 ms)


class SpinnerHandle:
    """Mutable detail text for a running spinner.

    The repaint thread reads :attr:`detail` on every tick, so the body of the
    ``with`` block only has to assign — it never writes to the terminal itself
    and cannot race the painter into a garbled line.  A plain attribute
    assignment is atomic, so no lock is needed for the single-writer,
    single-reader pattern this has.
    """

    __slots__ = ("detail",)

    def __init__(self) -> None:
        self.detail = ""

    def set_detail(self, detail: str) -> None:
        """Set the text shown between the message and the elapsed counter."""
        self.detail = detail


@contextmanager
def spinner(message: str) -> "Generator[SpinnerHandle, None, None]":
    """Context manager that shows *message* plus a live elapsed-seconds counter.

    While the body executes a daemon thread repaints a single terminal line
    roughly every 120 ms showing:

        | Generating password candidates via Ollama (model)...  3s

    Yields a :class:`SpinnerHandle`; calling ``set_detail("4,120,000 lines")``
    on it adds that text before the counter:

        | Profiling corpus locally (no LLM yet)...  4,120,000 lines  38s

    On exit (normal or exceptional) the spinner line is erased so subsequent
    output starts on a clean line.

    TTY guard: if ``sys.stdout.isatty()`` is False the message is printed once
    via ``print()`` and no thread is started, keeping piped output and the test
    suite clean.  A handle is still yielded in that case — callers pass the
    same callback either way — but nothing repaints, so the detail is dropped.
    """
    handle = SpinnerHandle()

    if not sys.stdout.isatty():
        print(message)
        yield handle
        return

    stop_event = threading.Event()
    start_time = time.monotonic()

    def _run() -> None:
        frame_idx = 0
        while not stop_event.is_set():
            elapsed = int(time.monotonic() - start_time)
            frame = _SPINNER_FRAMES[frame_idx % len(_SPINNER_FRAMES)]
            detail = handle.detail
            detail_part = f"  {detail}" if detail else ""
            # Repaint over the previous frame rather than appending to it: the
            # detail can shrink ("1,000,000" -> "999,999" never happens here,
            # but a caller may clear it), and a stale tail would otherwise sit
            # on the line until the final erase.
            line = f"\r\033[2K{frame} {message}{detail_part}  {elapsed}s"
            sys.stdout.write(line)
            sys.stdout.flush()
            frame_idx += 1
            stop_event.wait(_TICK_INTERVAL)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    try:
        yield handle
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
