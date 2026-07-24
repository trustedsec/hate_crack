"""Tests for hate_crack/progress.py — the generic spinner context manager."""

from __future__ import annotations

import io
import sys
import time
from unittest import mock

import pytest

from hate_crack.progress import spinner


# ---------------------------------------------------------------------------
# TTY guard: non-TTY path must print message once and not start a thread
# ---------------------------------------------------------------------------


def test_non_tty_prints_message(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """In a non-TTY environment the message is printed once and no thread runs."""
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)

    with spinner("Working..."):
        pass

    captured = capsys.readouterr()
    assert "Working..." in captured.out


def test_non_tty_no_extra_thread() -> None:
    """Spinner in non-TTY context must never construct a Thread."""
    buf = io.StringIO()
    buf.isatty = lambda: False  # type: ignore[attr-defined]

    with mock.patch("sys.stdout", buf), mock.patch(
        "hate_crack.progress.threading.Thread"
    ) as mock_thread:
        with spinner("No threads please"):
            pass
    mock_thread.assert_not_called()


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
