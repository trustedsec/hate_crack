"""libedit must only ever be handed the last line of a prompt.

libedit measures a prompt containing a newline as if it were one line: given
``"\\n" + 68 chars + "\\n" + 72 chars`` in a 120-column terminal it soft-wraps
the last line at column 51, so it believes the editable text starts near
column 139. Every redraw is then drawn at the wrong offset: the prompt is
garbled as soon as you type, and a Tab completion lands far to the right of
the text it replaced. Quick Crack's wordlist prompt is exactly that shape.

Every prompt site therefore goes through ``cli.read_line``, which writes the
leading lines itself and gives ``input()`` only the last one. The pty test
asserts on the bytes libedit emits, because a mock of ``input`` cannot see a
redraw; the unit tests pin that each prompt site uses the helper.
"""

from __future__ import annotations

import fcntl
import os
import select
import struct
import subprocess
import sys
import termios
import time

import pytest

from hate_crack import cli, menu
from hate_crack.ui.plain import PlainUI
from hate_crack.ui.rich_ui import RichUI

FIRST = "A" * 68
LAST = "B" * 70 + ": "
PROMPT = f"\n{FIRST}\n{LAST}"

_CHILD = """
import glob, os, sys
from hate_crack import cli
from hate_crack.ui.plain import PlainUI
from hate_crack.ui.rich_ui import RichUI

base = sys.argv[1]

def complete(text, state):
    matches = sorted(glob.glob(os.path.join(base, text + "*")))
    return matches[state] if state < len(matches) else None

cli.configure_completion(complete)
ui = {"plain": PlainUI, "rich": RichUI}[sys.argv[2]]()
print("RESULT=" + ui.ask(sys.argv[3]), flush=True)
"""


def _drive(base: str, backend: str, keys: bytes) -> str:
    leader, follower = os.openpty()
    # 120 columns: wide enough for either prompt line, narrower than both.
    fcntl.ioctl(follower, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 120, 0, 0))
    proc = subprocess.Popen(
        [sys.executable, "-c", _CHILD, base, backend, PROMPT],
        stdin=follower,
        stdout=follower,
        stderr=follower,
        env={**os.environ, "HATE_CRACK_SKIP_INIT": "1"},
        close_fds=True,
    )
    os.close(follower)
    out = b""
    try:
        deadline = time.time() + 10
        while b": " not in out and time.time() < deadline:
            if select.select([leader], [], [], 0.1)[0]:
                out += os.read(leader, 4096)
        for key in keys:
            os.write(leader, bytes([key]))
            time.sleep(0.15)
        while time.time() < deadline:
            if select.select([leader], [], [], 0.1)[0]:
                try:
                    chunk = os.read(leader, 4096)
                except OSError:  # Linux: the child exited and closed the pty
                    break
                if not chunk:  # macOS reports the same thing as EOF
                    break
                out += chunk
            elif proc.poll() is not None:
                break
    finally:
        proc.wait(timeout=10)
        os.close(leader)
    return out.decode(errors="replace")


@pytest.mark.skipif(not hasattr(os, "openpty"), reason="needs a pty")
@pytest.mark.parametrize("backend", ["plain", "rich"])
def test_last_prompt_line_is_not_wrapped_by_the_line_editor(backend, tmp_path):
    (tmp_path / "rockyou.txt").touch()
    out = _drive(str(tmp_path), backend, b"ro\t\r")
    # A multi-line prompt makes libedit soft-wrap this line (" \\r") mid-way.
    assert LAST in out, out
    assert f"RESULT={tmp_path / 'rockyou.txt'}" in out, out


def test_read_line_writes_the_head_and_prompts_with_the_last_line(monkeypatch, capsys):
    seen = []
    monkeypatch.setattr("builtins.input", lambda p="": seen.append(p) or "x")
    assert cli.read_line(PROMPT) == "x"
    assert seen == [LAST]
    assert capsys.readouterr().out == f"\n{FIRST}\n"


def test_read_line_passes_a_single_line_prompt_through(monkeypatch, capsys):
    seen = []
    monkeypatch.setattr("builtins.input", lambda p="": seen.append(p) or "x")
    assert cli.read_line("Path: ") == "x"
    assert seen == ["Path: "]
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    ("call", "answer"),
    [
        (lambda: PlainUI().ask(PROMPT), "1"),
        (lambda: RichUI().ask(PROMPT), "1"),
        (lambda: PlainUI().confirm(PROMPT), "y"),
        (lambda: RichUI().confirm(PROMPT), "y"),
        (lambda: cli.prompt_int(PROMPT), "1"),
        (lambda: menu._numbered_menu([("1", "x")], PROMPT), "1"),
    ],
    ids=["plain-ask", "rich-ask", "plain-confirm", "rich-confirm", "int", "menu"],
)
def test_no_prompt_site_hands_input_a_newline(call, answer, monkeypatch):
    seen = []
    monkeypatch.setattr("builtins.input", lambda p="": seen.append(p) or answer)
    call()
    assert seen and all("\n" not in p for p in seen), seen
