"""The list-plus-prompt pickers offer their lists to the arrow keys.

Quick Crack's wordlist and rule pickers, the OMEN/Markov training pickers and
the Random Rules wordlist picker are free-text prompts, not menus: they take
paths, ``p``/``q``, ``1,2``, ``1+1`` and ranges. So they cannot go through
``select``; they pass the listed entries to ``ask(choices=...)``, which the
plain and rich backends load into readline history for Up/Down (see
tests/test_readline_choice_history.py).
"""

from __future__ import annotations

from types import SimpleNamespace

from hate_crack.ui.plain import PlainUI
from hate_crack.ui.rich_ui import RichUI


CHOICES = [("0", "none"), ("1", "best64.rule"), ("2", "d3ad0ne.rule")]


def test_plain_and_rich_accept_choices(monkeypatch):
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


def _wordlists(tmp_path):
    wl = tmp_path / "wordlists"
    wl.mkdir()
    (wl / "rockyou.txt").write_text("a\n")
    (wl / "hibp").mkdir()
    (wl / "hibp" / "p.txt").write_text("b\n")
    return wl


def _listed(wl):
    from hate_crack import main as hc

    return [
        (str(i), f"{e.name}/" if e.is_dir else e.name)
        for i, e in enumerate(hc.list_wordlist_entries(str(wl)), start=1)
    ]


PQ = [("p", "Enter a custom path"), ("q", "Cancel")]


def _training_ctx(tmp_path, wl):
    from hate_crack import main as hc

    hash_file = tmp_path / "hashes.txt"
    hash_file.write_text("x\n")
    return SimpleNamespace(
        hcatWordlists=str(wl),
        hcatHashFile=str(hash_file),
        list_wordlist_entries=hc.list_wordlist_entries,
        select_file_with_autocomplete=lambda *a, **k: "",
    )


def test_training_wordlist_picker_offers_its_entries(tmp_path, monkeypatch):
    from hate_crack import attacks

    wl = _wordlists(tmp_path)
    ui = _RecordingUI(["q"])
    monkeypatch.setattr(attacks, "get_ui", lambda: ui)

    assert attacks._pick_training_wordlist(_training_ctx(tmp_path, wl)) is None
    assert ui.asked == [_listed(wl) + PQ]


def test_markov_source_picker_offers_its_entries(tmp_path, monkeypatch):
    from hate_crack import attacks

    wl = _wordlists(tmp_path)
    ctx = _training_ctx(tmp_path, wl)
    with open(f"{ctx.hcatHashFile}.out", "w") as fh:
        fh.write("cracked\n")
    ui = _RecordingUI(["q"])
    monkeypatch.setattr(attacks, "get_ui", lambda: ui)

    assert attacks._markov_pick_training_source(ctx) is None
    cracked = [("0", "Cracked passwords (current session)")]
    assert ui.asked == [cracked + _listed(wl) + PQ]


def test_generate_rules_wordlist_prompt_offers_its_entries(tmp_path, monkeypatch):
    from hate_crack import attacks
    from hate_crack import main as hc

    wl = _wordlists(tmp_path)
    ctx = SimpleNamespace(
        hcatWordlists=str(wl),
        hcatHashType="1000",
        hcatHashFile=str(tmp_path / "h.txt"),
        list_wordlist_entries=hc.list_wordlist_entries,
        hcatGenerateRules=lambda *a, **k: None,
    )
    ui = _RecordingUI(["", "1"])  # default rule count, then the first wordlist
    monkeypatch.setattr(attacks, "get_ui", lambda: ui)
    monkeypatch.setattr(attacks._notify, "prompt_notify_for_attack", lambda *a: None)

    attacks.generate_rules_crack(ctx)

    assert ui.asked == [None, _listed(wl)]
