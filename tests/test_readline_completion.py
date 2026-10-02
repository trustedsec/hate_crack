"""Tab-completion tests that actually press Tab.

The completion surface had no tests at all, and the failure mode it is prone to
is silent: ``readline.parse_and_bind`` accepts a string meant for the *other*
backend without complaining, and an unbound Tab simply inserts a literal tab.
Asserting that ``parse_and_bind`` "was called" would pass in exactly that case,
so these tests drive a real pty and assert on the value readline hands back.
"""

from __future__ import annotations

import ast
import os
import re
import select
import subprocess
import sys
import textwrap
import time

import pytest

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="pty-driven completion test requires POSIX"
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Printed by the child once input() returns, so the assertions read the value
# readline produced rather than the echoed terminal bytes (which are full of
# redraw escapes and easy to misread).
_CHILD = """
import sys
sys.path.insert(0, {repo!r})
import glob, os, readline
from hate_crack.cli import configure_completion

base_dir = {base!r}

def completer(text, state):
    if not text:
        matches = glob.glob(os.path.join(base_dir, "*"))
    else:
        text = os.path.expanduser(text)
        if text.startswith(("/", "./", "../", "~")):
            matches = glob.glob(text + "*")
        else:
            matches = glob.glob(os.path.join(base_dir, text + "*"))
    matches = [m + "/" if os.path.isdir(m) else m for m in matches]
    try:
        return matches[state]
    except IndexError:
        return None

configure_completion(completer)
value = input("prompt> ")
sys.stdout.write("\\nVALUE=" + repr(value) + "\\n")
sys.stdout.flush()
"""


def _complete(base_dir: str, keys: bytes, timeout: float = 10.0) -> str:
    """Type *keys* at a completing prompt and return the submitted value."""
    import pty

    script = _CHILD.format(repo=REPO_ROOT, base=base_dir)
    master, slave = pty.openpty()
    proc = subprocess.Popen(
        [sys.executable, "-c", textwrap.dedent(script)],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        close_fds=True,
        # Its own session, so the child cannot grab the test runner's terminal.
        start_new_session=True,
    )
    os.close(slave)
    buf = b""

    def pump(duration: float) -> None:
        nonlocal buf
        end = time.time() + duration
        while time.time() < end:
            ready, _, _ = select.select([master], [], [], 0.1)
            if not ready:
                continue
            try:
                chunk = os.read(master, 65536)
            except OSError:
                return
            if not chunk:
                return
            buf += chunk

    try:
        deadline = time.time() + timeout
        while time.time() < deadline and b"prompt>" not in buf:
            pump(0.2)
        assert b"prompt>" in buf, f"child never prompted; got {buf!r}"
        os.write(master, keys)
        pump(0.8)
        os.write(master, b"\r")
        deadline = time.time() + timeout
        while time.time() < deadline and b"VALUE=" not in buf:
            pump(0.2)
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        os.close(master)

    match = re.search(r"VALUE=(.+)", buf.decode(errors="replace"))
    assert match, f"child never reported a value; got {buf!r}"
    return ast.literal_eval(match.group(1).strip())


@pytest.fixture
def wordlists(tmp_path):
    (tmp_path / "rockyou.txt").write_text("a\n")
    (tmp_path / "shared_alpha.txt").write_text("b\n")
    (tmp_path / "shared_beta.txt").write_text("c\n")
    return str(tmp_path)


def test_tab_completes_a_unique_match_to_the_full_path(wordlists):
    assert _complete(wordlists, b"rock\t") == os.path.join(wordlists, "rockyou.txt")


def test_tab_completes_an_ambiguous_match_to_the_common_prefix(wordlists):
    # Two files share "shared_", so Tab fills that much and waits.
    assert _complete(wordlists, b"sha\t") == os.path.join(wordlists, "shared_")


def test_tab_with_no_match_inserts_no_literal_tab(wordlists):
    # The regression this file exists for: an unbound Tab yields "zzz\t".
    assert _complete(wordlists, b"zzz\t") == "zzz"


def test_tab_is_not_left_as_a_literal_character_anywhere(wordlists):
    for keys in (b"rock\t", b"sha\t", b"zzz\t"):
        assert "\t" not in _complete(wordlists, keys)


class TestSelectorReturnContract:
    """``select_file_with_autocomplete`` returns str, "" or list.

    ~20 call sites do ``select_file_with_autocomplete(...).strip()``. Those
    without a ``base_dir`` to fall back on used to get None on a bare Enter and
    raise AttributeError, so the empty case must stay a string.
    """

    @staticmethod
    def _main():
        if REPO_ROOT not in sys.path:
            sys.path.insert(0, REPO_ROOT)
        import hate_crack.main as m  # noqa: PLC0415

        return m

    def test_empty_input_returns_empty_string_not_none(self):
        from unittest.mock import patch  # noqa: PLC0415

        m = self._main()
        with patch("builtins.input", return_value=""):
            result = m.select_file_with_autocomplete("Pick a file")
        assert result == ""
        assert result.strip() == ""  # the call shape that used to crash

    def test_comma_input_with_allow_multiple_returns_a_list(self):
        from unittest.mock import patch  # noqa: PLC0415

        m = self._main()
        with patch("builtins.input", return_value="/a.txt,/b.txt"):
            result = m.select_file_with_autocomplete("Pick", allow_multiple=True)
        assert result == ["/a.txt", "/b.txt"]

    def test_single_path_returns_a_string_even_with_allow_multiple(self):
        from unittest.mock import patch  # noqa: PLC0415

        m = self._main()
        with patch("builtins.input", return_value="/a.txt"):
            result = m.select_file_with_autocomplete("Pick", allow_multiple=True)
        assert result == "/a.txt"


class TestAsPathList:
    @staticmethod
    def _attacks():
        if REPO_ROOT not in sys.path:
            sys.path.insert(0, REPO_ROOT)
        import hate_crack.attacks as attacks  # noqa: PLC0415

        return attacks

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (["/a.txt", "/b.txt"], ["/a.txt", "/b.txt"]),
            ("/a.txt,/b.txt", ["/a.txt", "/b.txt"]),
            ("/a.txt", ["/a.txt"]),
            ("", []),
            (None, []),
            (["/a.txt", "", "  "], ["/a.txt"]),
            ("/a.txt, /b.txt ", ["/a.txt", "/b.txt"]),
        ],
    )
    def test_normalises_every_selector_return_shape(self, value, expected):
        assert self._attacks()._as_path_list(value) == expected
