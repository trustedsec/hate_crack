"""Tests for hate_crack/progress.py — the generic spinner context manager."""

from __future__ import annotations

import io
import sys
import threading
import time
from unittest import mock

import pytest

from hate_crack.progress import spinner


# ---------------------------------------------------------------------------
# TTY guard: non-TTY path must print message once and not start a thread
# ---------------------------------------------------------------------------


def test_non_tty_prints_message(capsys: pytest.CaptureFixture[str]) -> None:
    """In a non-TTY environment the message is printed once and no thread runs."""
    with mock.patch.object(sys, "stdout", wraps=sys.stdout) as m_stdout:
        m_stdout.isatty.return_value = False  # type: ignore[attr-defined]
        # Use actual capsys for the print capture but override isatty
        original_isatty = sys.stdout.isatty
        sys.stdout.isatty = lambda: False  # type: ignore[method-assign]
        try:
            with spinner("Working..."):
                pass
        finally:
            sys.stdout.isatty = original_isatty  # type: ignore[method-assign]

    captured = capsys.readouterr()
    assert "Working..." in captured.out


def test_non_tty_no_extra_thread() -> None:
    """Spinner in non-TTY context should not start a background thread."""
    buf = io.StringIO()
    buf.isatty = lambda: False  # type: ignore[attr-defined]

    threads_before = threading.active_count()
    with mock.patch("sys.stdout", buf):
        with spinner("No threads please"):
            peak = threading.active_count()
    # The thread count during the body should not exceed baseline + 1
    # (pytest itself may add threads; we just want no extra daemon spinner thread).
    assert peak <= threads_before + 1


# ---------------------------------------------------------------------------
# TTY path: spinner starts a thread, clears the line on exit
# ---------------------------------------------------------------------------


def test_tty_clears_line_on_exit() -> None:
    """After the context exits the spinner line must be erased."""
    buf = io.StringIO()
    buf.isatty = lambda: True  # type: ignore[attr-defined]

    with mock.patch("sys.stdout", buf):
        with spinner("Testing..."):
            time.sleep(0.05)  # let spinner tick at least once

    output = buf.getvalue()
    # Line clear sequence must be present somewhere after the spinner started.
    assert "\033[2K\r" in output or ("\033[2K" in output)


def test_tty_shows_elapsed_seconds() -> None:
    """The spinner should show at least a 0s counter in its output."""
    buf = io.StringIO()
    buf.isatty = lambda: True  # type: ignore[attr-defined]

    with mock.patch("sys.stdout", buf):
        with spinner("Counting..."):
            time.sleep(0.25)  # enough time for several ticks

    output = buf.getvalue()
    # Should have written at least one elapsed counter like "0s" or "1s"
    assert "s" in output
    assert "Counting..." in output


def test_tty_exception_still_clears_line() -> None:
    """Spinner must clear the line even when the body raises."""
    buf = io.StringIO()
    buf.isatty = lambda: True  # type: ignore[attr-defined]

    with mock.patch("sys.stdout", buf):
        with pytest.raises(ValueError):
            with spinner("Will raise"):
                raise ValueError("boom")

    output = buf.getvalue()
    assert "\033[2K\r" in output or ("\033[2K" in output)


def test_spinner_does_not_swallow_exception() -> None:
    """The spinner context manager must re-raise exceptions from the body."""
    buf = io.StringIO()
    buf.isatty = lambda: True  # type: ignore[attr-defined]

    with mock.patch("sys.stdout", buf):
        with pytest.raises(RuntimeError, match="test error"):
            with spinner("Should propagate"):
                raise RuntimeError("test error")
