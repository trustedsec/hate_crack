"""Readline must know the prompt, or every completion redraw erases it.

RichUI used to print the prompt through the console and call ``input()`` with
no prompt. Completion still returned the right paths, but each redraw started
at column 0: ``ro<Tab>`` overwrote the prompt with the completed path, and a
match listing dropped it entirely. Driven in a real pty, because this
machine's line editor is libedit and a mock proves nothing about redraws.
"""

from __future__ import annotations

import os
import select
import subprocess
import sys
import time

import pytest

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
print("RESULT=" + ui.ask("Corpus path: "), flush=True)
"""


def _drive(base: str, backend: str, keys: bytes) -> str:
    leader, follower = os.openpty()
    proc = subprocess.Popen(
        [sys.executable, "-c", _CHILD, base, backend],
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
        while b"Corpus path: " not in out and time.time() < deadline:
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
def test_prompt_survives_a_match_listing(backend, tmp_path):
    (tmp_path / "rockyou.txt").touch()
    (tmp_path / "other.txt").touch()
    out = _drive(str(tmp_path), backend, b"\t\t\r")
    listing = out.index("rockyou.txt")
    assert "Corpus path: " in out[listing:], out
