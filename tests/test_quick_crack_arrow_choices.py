"""Quick Crack's pickers offer their lists to the arrow keys.

Both pickers (wordlist, then rules) are free-text prompts, not menus: they take
paths, ``1,2``, ``1+1`` and ranges. So they cannot go through ``select``; they
pass the listed entries to ``ask(choices=...)``, which the Textual backend uses
for Up/Down while still returning whatever was typed.
"""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace

from textual.widgets import Input

from hate_crack.ui.app import HateCrackApp
from hate_crack.ui.plain import PlainUI
from hate_crack.ui.rich_ui import RichUI
from hate_crack.ui.textual_ui import TextualUI


def _drive(worker, keys):
    out = {}

    async def body():
        app = HateCrackApp()
        ui = TextualUI()
        ui.bind(app)
        async with app.run_test() as pilot:
            t = threading.Thread(target=lambda: out.update(v=worker(ui)))
            t.start()
            await pilot.pause(0.2)
            await pilot.click(Input)
            for k in keys:
                await pilot.press(k)
                await pilot.pause(0.02)
            await pilot.press("enter")
            while t.is_alive():
                await pilot.pause(0.05)
            t.join()

    asyncio.run(body())
    return out["v"]


CHOICES = [("0", "none"), ("1", "best64.rule"), ("2", "d3ad0ne.rule")]


def test_ask_with_choices_walks_them_with_arrows():
    got = _drive(lambda ui: ui.ask("rules? ", choices=CHOICES), ["down", "down"])
    assert got == "1"


def test_ask_with_choices_still_returns_free_text():
    got = _drive(lambda ui: ui.ask("rules? ", choices=CHOICES), list("/tmp/x"))
    assert got == "/tmp/x"


def test_a_separator_after_an_arrow_extends_the_filled_key():
    """Arrow to 1, then type ",2": the rule list is "1,2", not ",2"."""
    keys = ["down", "down", "comma", "2"]
    assert _drive(lambda ui: ui.ask("rules? ", choices=CHOICES), keys) == "1,2"
    keys = ["down", "down", "plus", "1"]
    assert _drive(lambda ui: ui.ask("rules? ", choices=CHOICES), keys) == "1+1"


def test_plain_and_rich_accept_and_ignore_choices(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *a: "7")
    assert PlainUI().ask("? ", choices=CHOICES) == "7"
    assert RichUI().ask("? ", choices=CHOICES) == "7"


class _RecordingUI(PlainUI):
    def __init__(self, answers):
        self.answers = iter(answers)
        self.asked = []

    def ask(self, prompt="", *, default="", choices=None):
        self.asked.append(choices)
        return next(self.answers)


def test_select_rules_offers_its_entries(tmp_path, monkeypatch):
    from hate_crack import attacks

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "best64.rule").write_text(":\n")
    ctx = SimpleNamespace(
        rulesDirectory=str(rules), list_rule_files=lambda d: ["best64.rule"]
    )
    ui = _RecordingUI(["99"])
    monkeypatch.setattr(attacks, "get_ui", lambda: ui)

    assert attacks._select_rules(ctx) is None
    assert ui.asked == [
        [
            ("0", "To run without any rules"),
            ("1", "best64.rule"),
            ("98", "YOLO...run all of the rules"),
            ("99", "Back to Main Menu"),
        ]
    ]


def test_quick_crack_wordlist_prompt_offers_its_entries(tmp_path, monkeypatch):
    from hate_crack import attacks
    from hate_crack import main as hc

    wl = tmp_path / "wordlists"
    wl.mkdir()
    (wl / "rockyou.txt").write_text("a\n")
    (wl / "hibp").mkdir()
    (wl / "hibp" / "p.txt").write_text("b\n")
    ctx = SimpleNamespace(
        hcatWordlists=str(wl),
        hcatOptimizedWordlists=str(wl),
        list_wordlist_entries=hc.list_wordlist_entries,
    )
    ui = _RecordingUI(["1"])
    monkeypatch.setattr(attacks, "get_ui", lambda: ui)
    monkeypatch.setattr(attacks._notify, "prompt_notify_for_attack", lambda *a: None)
    monkeypatch.setattr(attacks, "_select_rules", lambda ctx: None)

    attacks.quick_crack(ctx)

    names = [e.name for e in hc.list_wordlist_entries(str(wl))]
    expected = [
        (str(i), f"{n}/" if n == "hibp" else n) for i, n in enumerate(names, start=1)
    ]
    assert ui.asked == [expected]
