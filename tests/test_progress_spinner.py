"""Tests for hate_crack/progress.py — the generic spinner context manager."""

from __future__ import annotations

import io
import re
import sys
import time
from unittest import mock

import pytest

from hate_crack.progress import _TICK_INTERVAL, spinner


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

    with (
        mock.patch("sys.stdout", buf),
        mock.patch("hate_crack.progress.threading.Thread") as mock_thread,
    ):
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
            pass  # no sleep needed — the finally block writes the escape regardless

    output = buf.getvalue()
    # Line clear sequence must be present somewhere after the spinner started.
    assert "\033[2K\r" in output or ("\033[2K" in output)


def test_tty_shows_elapsed_seconds() -> None:
    """The spinner must render the elapsed-seconds counter in the expected format.

    time.monotonic is patched so the test is deterministic regardless of
    scheduling: the first call returns 0.0 (start), the second returns 3.0
    (first tick), giving a stable "3s" label without sleeping.
    """
    buf = io.StringIO()
    buf.isatty = lambda: True  # type: ignore[attr-defined]

    # Patch monotonic: start=0.0, then 3.0 at the first tick, then keep
    # returning 3.0 so stop_event.wait() ends quickly.
    mono_values = iter([0.0, 3.0, 3.0, 3.0, 3.0, 3.0, 3.0, 3.0, 3.0, 3.0])

    with (
        mock.patch("sys.stdout", buf),
        mock.patch("hate_crack.progress.time.monotonic", side_effect=mono_values),
    ):
        with spinner("Counting..."):
            pass  # body exits immediately; the thread gets one tick then stops

    output = buf.getvalue()
    assert "Counting..." in output
    # At least one frame must match the "Ns" elapsed format (e.g. "3s").
    assert re.search(r"\d+s", output), f"Expected elapsed counter in output: {output!r}"


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


# ---------------------------------------------------------------------------
# Teardown robustness: line must be cleared even if join() is interrupted
# ---------------------------------------------------------------------------


def test_tty_clears_line_even_if_join_raises() -> None:
    """Line-clear must happen even when thread.join() raises (e.g. DoubleInterrupt).

    The fix moves the write("\033[2K\r") *before* thread.join() so an
    exception during join cannot prevent the terminal from being cleaned up.
    """
    buf = io.StringIO()
    buf.isatty = lambda: True  # type: ignore[attr-defined]

    class FakeThread:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def start(self) -> None:
            pass

        def join(self, *args, **kwargs) -> None:
            raise KeyboardInterrupt("simulated double Ctrl-C during join")

    with (
        mock.patch("hate_crack.progress.threading.Thread", FakeThread),
        mock.patch("sys.stdout", buf),
    ):
        with pytest.raises(KeyboardInterrupt):
            with spinner("Robust teardown"):
                pass

    output = buf.getvalue()
    assert "\033[2K\r" in output, (
        "Line-clear escape sequence must be written before join() is called"
    )


# ---------------------------------------------------------------------------
# Live detail: long local passes report progress alongside the elapsed counter
# ---------------------------------------------------------------------------


def test_spinner_yields_handle_and_renders_detail() -> None:
    """``with spinner(msg) as handle`` must render handle.set_detail() text.

    A minute-long local pass (corpus profiling) is indistinguishable from a
    hang when only seconds tick up, so the caller needs a way to say how far
    it has got without owning the repaint loop.
    """
    buf = io.StringIO()
    buf.isatty = lambda: True  # type: ignore[attr-defined]

    with mock.patch("sys.stdout", buf):
        with spinner("Profiling...") as handle:
            handle.set_detail("4,120,000 lines")
            # Give the repaint thread at least one tick with the detail set.
            time.sleep(_TICK_INTERVAL * 3)

    output = buf.getvalue()
    assert "Profiling..." in output
    assert "4,120,000 lines" in output


def test_spinner_detail_is_optional_in_rendering() -> None:
    """With no detail set, the rendered line must not gain stray separators."""
    buf = io.StringIO()
    buf.isatty = lambda: True  # type: ignore[attr-defined]

    mono_values = iter([0.0] + [3.0] * 12)
    with (
        mock.patch("sys.stdout", buf),
        mock.patch("hate_crack.progress.time.monotonic", side_effect=mono_values),
    ):
        with spinner("Plain"):
            pass

    assert "Plain  3s" in buf.getvalue()


def test_non_tty_handle_set_detail_is_silent(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The non-TTY path still yields a handle, and set_detail prints nothing.

    Callers pass the same callback either way, so a missing handle would be an
    AttributeError in piped output and in the test suite.
    """
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)

    with spinner("Working...") as handle:
        handle.set_detail("1,000 lines")

    captured = capsys.readouterr()
    assert "Working..." in captured.out
    assert "1,000 lines" not in captured.out
