"""hashcat is killed mid-run; the terminal must come back usable.

hashcat puts the tty into non-canonical, no-echo mode for its keypress menu and
restores it only on a clean exit. Ctrl-C kills it with SIGKILL, so the operator
returned to a menu where Backspace and echo no longer worked.
``cli.preserve_tty`` snapshots termios and restores it, driven here against a
real pty rather than a mock, which would only assert call names.
"""

from __future__ import annotations

import os
import pty
import termios
from unittest.mock import patch

import pytest

from hate_crack import cli


@pytest.fixture
def tty_fd():
    master, slave = pty.openpty()
    try:
        yield slave
    finally:
        os.close(master)
        os.close(slave)


def _scramble(fd: int) -> None:
    """Do what hashcat does: raw-ish, no echo, no canonical line editing."""
    attrs = termios.tcgetattr(fd)
    attrs[3] &= ~(termios.ECHO | termios.ICANON)
    termios.tcsetattr(fd, termios.TCSANOW, attrs)


def test_restores_mode_after_child_changed_it(tty_fd):
    before = termios.tcgetattr(tty_fd)
    with cli.preserve_tty(tty_fd):
        _scramble(tty_fd)
        assert termios.tcgetattr(tty_fd) != before
    assert termios.tcgetattr(tty_fd) == before


def test_restores_mode_when_body_raises(tty_fd):
    before = termios.tcgetattr(tty_fd)
    with pytest.raises(KeyboardInterrupt), cli.preserve_tty(tty_fd):
        _scramble(tty_fd)
        raise KeyboardInterrupt
    assert termios.tcgetattr(tty_fd) == before


def test_not_a_tty_is_a_no_op():
    r, w = os.pipe()
    try:
        with cli.preserve_tty(r):
            pass
    finally:
        os.close(r)
        os.close(w)


def test_closed_fd_is_a_no_op():
    r, w = os.pipe()
    os.close(r)
    os.close(w)
    with cli.preserve_tty(r):
        pass


def test_defaults_to_stdin_and_tolerates_non_fileno_stdin():
    class NoFileno:
        def fileno(self):
            raise OSError("no fileno")

    with patch("sys.stdin", NoFileno()), cli.preserve_tty():
        pass


def test_restore_failure_does_not_mask_the_body_exception(tty_fd):
    with (
        patch("termios.tcsetattr", side_effect=termios.error("gone")),
        pytest.raises(ValueError),
        cli.preserve_tty(tty_fd),
    ):
        raise ValueError("real error")


def test_hashcat_runner_wraps_the_spawn_in_preserve_tty():
    """The wiring: a runner that skips the wrapper reintroduces the bug."""
    import inspect

    from hate_crack import main

    src = inspect.getsource(main._run_hcat_cmd_uncovered)
    assert "preserve_tty()" in src
    assert src.index("preserve_tty()") < src.index(
        "subprocess.Popen(cmd, **popen_kwargs)"
    )
