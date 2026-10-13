"""Up/Down walk a prompt's listed choices under the plain and rich backends.

Those backends read with ``input()``, so arrows are readline history. For the
one prompt that passes ``choices=``, the history is swapped for the listed keys
and restored afterwards, so the operator's own history is never lost.
"""

from __future__ import annotations

import os
import readline
import select
import subprocess
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

from hate_crack import cli
from hate_crack.ui.plain import PlainUI
from hate_crack.ui.rich_ui import RichUI

CHOICES = [("0", "none"), ("1", "best64.rule"), ("99", "Back")]


def _history():
    n = readline.get_current_history_length()
    return [readline.get_history_item(i) for i in range(1, n + 1)]


@pytest.fixture
def clean_history():
    saved = _history()
    readline.clear_history()
    yield
    readline.clear_history()
    for item in saved:
        readline.add_history(item)


def test_history_holds_the_keys_and_is_restored(clean_history):
    readline.add_history("mine")
    with cli.choice_history(CHOICES):
        assert _history() == ["0", "1", "99"]
    assert _history() == ["mine"]


def test_history_is_restored_when_the_prompt_raises(clean_history):
    readline.add_history("mine")
    with pytest.raises(EOFError), cli.choice_history(CHOICES):
        raise EOFError
    assert _history() == ["mine"]


def test_no_choices_leaves_history_alone(clean_history):
    readline.add_history("mine")
    with cli.choice_history(None):
        assert _history() == ["mine"]


@pytest.mark.parametrize("backend", [PlainUI, RichUI])
def test_ask_swaps_history_for_the_prompt(backend, clean_history, monkeypatch):
    readline.add_history("mine")
    seen = []
    monkeypatch.setattr("builtins.input", lambda *a: seen.append(_history()) or "1")
    assert backend().ask("? ", choices=CHOICES) == "1"
    assert seen == [["0", "1", "99"]]
    assert _history() == ["mine"]


_CHILD = """
import readline
from hate_crack.ui.plain import PlainUI
readline.add_history("mine")
ans = PlainUI().ask("pick: ", choices=[("0", "a"), ("1", "b"), ("99", "c")])
print("RESULT=" + ans, flush=True)
"""


@pytest.mark.skipif(not hasattr(os, "openpty"), reason="needs a pty")
@pytest.mark.parametrize(
    "keys, expected",
    [
        (b"\x1b[A\r", "99"),  # Up: the last key, as under Textual
        (b"\x1b[A\x1b[A\r", "1"),
        (b"\x1b[A\x1b[A\x1b[B\r", "99"),
        (b"\x1b[A,1\r", "99,1"),  # a separator extends the filled key
        (b"5\r", "5"),
    ],
)
def test_arrows_in_a_real_terminal(keys, expected):
    """The real line editor, not a mock: this machine's may be libedit."""
    leader, follower = os.openpty()
    proc = subprocess.Popen(
        [sys.executable, "-c", _CHILD],
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
        while b"pick: " not in out and time.time() < deadline:
            if select.select([leader], [], [], 0.1)[0]:
                out += os.read(leader, 4096)
        # One escape sequence or character at a time, as a keyboard sends them.
        for chunk in _split_keys(keys):
            os.write(leader, chunk)
            time.sleep(0.1)
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
    lines = [ln for ln in out.decode(errors="replace").splitlines() if "RESULT=" in ln]
    assert lines, out
    assert lines[-1].split("RESULT=", 1)[1].strip() == expected


def _split_keys(keys: bytes):
    i = 0
    while i < len(keys):
        if keys[i : i + 1] == b"\x1b":
            yield keys[i : i + 3]
            i += 3
        else:
            yield keys[i : i + 1]
            i += 1


class _RecordingUI(PlainUI):
    def __init__(self, answers):
        self.answers = iter(answers)
        self.asked = []

    def ask(self, prompt="", *, default="", choices=None):
        self.asked.append((prompt, choices))
        return next(self.answers)


def _hashview(hc_module, monkeypatch, option, answers):
    main = hc_module._main
    monkeypatch.setattr(main, "hcatHashFile", None)
    monkeypatch.setattr(main, "hashview_api_key", "k", raising=False)
    monkeypatch.setattr(main, "hashview_url", "http://x", raising=False)
    picks = [option, "Back to Main Menu"]

    def pick(items, **kwargs):
        wanted = picks.pop(0)
        return next(key for key, text in items if text == wanted)

    monkeypatch.setattr(main, "interactive_menu", pick, raising=False)
    harness = MagicMock()
    harness.list_wordlists.return_value = [
        {"id": 3, "name": "rockyou.txt", "size": 10},
        {"id": 7, "name": "hibp.txt", "size": 20},
    ]
    harness.list_rules.return_value = [{"id": 4, "name": "best64.rule", "size": 77}]
    harness.download_wordlist.return_value = {"size": 1, "output_file": "/tmp/x"}
    harness.download_rules.return_value = {"size": 1, "output_file": "/tmp/y"}
    ui = _RecordingUI(answers)
    monkeypatch.setattr(main, "get_ui", lambda: ui)
    with patch.object(main, "HashviewAPI", return_value=harness):
        main.hashview_api()
    return ui.asked


def test_hashview_wordlist_id_prompt_offers_the_listed_ids(hc_module, monkeypatch):
    asked = _hashview(hc_module, monkeypatch, "Download Wordlist", ["3", ""])
    assert asked[0][1] == [("3", "rockyou.txt"), ("7", "hibp.txt")]


def test_hashview_rule_id_prompt_offers_the_listed_ids(hc_module, monkeypatch):
    asked = _hashview(hc_module, monkeypatch, "Download Rule", ["4", ""])
    assert asked[0][1] == [("4", "best64.rule"), ("a", "all")]


def test_weakpass_prompt_offers_the_listed_numbers(monkeypatch):
    from hate_crack import api

    wordlists = [
        {"name": "rockyou", "rank": 5, "tier": "A", "rate": 1.0},
        {"name": "hibp", "rank": 6, "tier": "S", "rate": 2.0},
    ]
    monkeypatch.setattr(
        api, "fetch_all_weakpass_wordlists_multithreaded", lambda: wordlists
    )
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    ui = _RecordingUI(["q"])
    monkeypatch.setattr(api, "get_ui", lambda: ui)

    api.weakpass_wordlist_menu()

    assert ui.asked[0][1] == [("1", "rockyou"), ("2", "hibp")]
