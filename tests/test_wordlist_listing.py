"""The listing layer under hate_crack's pickers.

Issue #233: `list_wordlist_files()` was a bare `os.listdir` with an extension
blocklist and a one-off `.DS_Store` exclusion, so subdirectories and dot-files
were numbered in the pickers as if they were wordlists, and several callers
joined those names onto a directory and handed the result to hashcat as a file.
"""

from __future__ import annotations

import os

import pytest


@pytest.fixture
def wordlist_dir(tmp_path):
    """A wordlists directory with one of everything that has caused trouble."""
    d = tmp_path / "wordlists"
    d.mkdir()
    (d / "rockyou.txt").write_text("password\n")
    (d / "custom.dict").write_text("hunter2\n")
    (d / "hibp").mkdir()  # a directory: valid for hashcat, not a file
    (d / "hibp" / "part1.txt").write_text("a\n")
    (d / ".gitkeep").write_text("")  # dot-files: never wordlists
    (d / ".DS_Store").write_text("")
    (d / "archive.7z").write_text("")  # excluded extension
    (d / "hashes.out").write_text("")  # excluded extension
    (d / "list.torrent").write_text("")  # excluded extension
    return d


def test_files_listing_excludes_directories(hc_module, wordlist_dir):
    """The regression: a directory in this list gets joined onto the wordlists
    path and passed to hashcat as a file by hcatDictionary and the yolo path."""
    got = hc_module.list_wordlist_files(str(wordlist_dir))
    assert got == ["custom.dict", "rockyou.txt"]
    assert "hibp" not in got


def test_files_listing_excludes_all_dot_files(hc_module, wordlist_dir):
    """Replaces the one-off .DS_Store special case: .gitkeep and friends are
    not wordlists either."""
    got = hc_module.list_wordlist_files(str(wordlist_dir))
    assert not [name for name in got if name.startswith(".")]


def test_entries_listing_includes_directories_and_marks_them(hc_module, wordlist_dir):
    entries = hc_module.list_wordlist_entries(str(wordlist_dir))
    assert [(e.name, e.is_dir) for e in entries] == [
        ("custom.dict", False),
        ("hibp", True),
        ("rockyou.txt", False),
    ]


def test_entries_listing_excludes_dot_files(hc_module, wordlist_dir):
    entries = hc_module.list_wordlist_entries(str(wordlist_dir))
    assert not [e for e in entries if e.name.startswith(".")]


def test_rule_listing_excludes_directories_and_dot_files(hc_module, tmp_path):
    """A rules directory picks up subdirectories when someone drops in a cloned
    rules repo or hashcat's own rules tree. `-r <directory>` is rejected by
    hashcat, and the LLM attack iterates every entry unattended."""
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "best64.rule").write_text(":\n")
    (rules / "toggles.rule").write_text(":\n")
    (rules / "OneRuleToRuleThemStill").mkdir()
    (rules / ".DS_Store").write_text("")
    (rules / ".gitkeep").write_text("")

    got = hc_module.list_rule_files(str(rules))

    assert got == ["best64.rule", "toggles.rule"]


@pytest.mark.parametrize(
    "func", ["list_wordlist_files", "list_rule_files", "list_wordlist_entries"]
)
def test_missing_directory_is_empty_not_an_exception(hc_module, tmp_path, func):
    """A wordlists path that does not exist yet must not crash a picker."""
    assert getattr(hc_module, func)(str(tmp_path / "nope")) == []


def test_a_file_where_a_directory_was_expected_is_empty(hc_module, tmp_path):
    """os.listdir raises NotADirectoryError here; the pickers must survive it."""
    f = tmp_path / "not-a-dir"
    f.write_text("x\n")
    assert hc_module.list_wordlist_files(str(f)) == []


@pytest.fixture
def hc_module():
    import importlib

    os.environ["HATE_CRACK_SKIP_INIT"] = "1"
    return importlib.import_module("hate_crack.main")


def test_rule_picker_offers_no_directories_or_dot_files(
    hc_module, tmp_path, monkeypatch, capsys
):
    from types import SimpleNamespace

    from hate_crack import attacks

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "best64.rule").write_text(":\n")
    (rules / "OneRuleToRuleThemStill").mkdir()
    (rules / ".DS_Store").write_text("")

    ctx = SimpleNamespace(
        rulesDirectory=str(rules), list_rule_files=hc_module.list_rule_files
    )
    monkeypatch.setattr("builtins.input", lambda *a: "99")

    attacks._select_rules(ctx)

    out = capsys.readouterr().out
    assert "best64.rule" in out
    assert "OneRuleToRuleThemStill" not in out, "a directory was offered as a rule"
    assert ".DS_Store" not in out


def test_llm_rule_loop_skips_directories(hc_module, tmp_path):
    """main.py:2906 iterates every entry and runs `hashcat -r <entry>`
    unattended, so one subdirectory fails the run with nobody watching. This is
    the highest-severity site in #233 because the user cannot steer around it.
    """
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "best64.rule").write_text(":\n")
    (rules / "subdir").mkdir()
    (rules / ".gitkeep").write_text("")

    got = hc_module.list_rule_files(str(rules))

    assert got == ["best64.rule"]
    for name in got:
        assert os.path.isfile(os.path.join(str(rules), name)), (
            f"{name} would be passed to hashcat as -r and is not a file"
        )


def _quick_crack_ctx(hc_module, wordlist_dir, tmp_path):
    """A ctx just complete enough to drive quick_crack's picker."""
    from types import SimpleNamespace

    calls = []
    hash_file = tmp_path / "hashes.txt"
    hash_file.write_text("aad3b435b51404eeaad3b435b51404ee\n")
    return SimpleNamespace(
        hcatWordlists=str(wordlist_dir),
        hcatOptimizedWordlists=str(wordlist_dir),
        hcatHashType="1000",
        hcatHashFile=str(hash_file),
        rulesDirectory=str(tmp_path / "rules"),
        list_wordlist_files=hc_module.list_wordlist_files,
        list_wordlist_entries=hc_module.list_wordlist_entries,
        list_rule_files=hc_module.list_rule_files,
        hcatQuickDictionary=lambda *a, **k: calls.append((a, k)),
    ), calls


def test_quick_crack_marks_directories_in_the_grid(
    hc_module, wordlist_dir, tmp_path, capsys, monkeypatch
):
    """A directory expands to every file inside it, so the user has to be able
    to tell it apart from a single wordlist at a glance."""
    from hate_crack import attacks

    ctx, _calls = _quick_crack_ctx(hc_module, wordlist_dir, tmp_path)
    monkeypatch.setattr("builtins.input", lambda *a: (_ for _ in ()).throw(EOFError))
    monkeypatch.setattr(attacks._notify, "prompt_notify_for_attack", lambda *a: None)

    with pytest.raises((EOFError, SystemExit)):
        attacks.quick_crack(ctx)

    out = capsys.readouterr().out
    assert "hibp/" in out, f"directory not marked as one:\n{out}"
    assert "rockyou.txt" in out
    assert ".gitkeep" not in out
    assert ".DS_Store" not in out


def test_quick_crack_passes_a_selected_directory_through_as_a_directory(
    hc_module, wordlist_dir, tmp_path, monkeypatch
):
    """hashcat consumes every file in a directory, so selecting one must hand
    the directory itself to hcatQuickDictionary, not a file inside it."""
    from hate_crack import attacks

    ctx, calls = _quick_crack_ctx(hc_module, wordlist_dir, tmp_path)
    entries = hc_module.list_wordlist_entries(str(wordlist_dir))
    choice = str(1 + [e.name for e in entries].index("hibp"))

    answers = iter([choice])
    monkeypatch.setattr("builtins.input", lambda *a: next(answers))
    monkeypatch.setattr(attacks._notify, "prompt_notify_for_attack", lambda *a: None)
    monkeypatch.setattr(attacks, "_select_rules", lambda ctx: [""])

    attacks.quick_crack(ctx)

    assert calls, "hcatQuickDictionary was never called"
    passed = calls[0][0][3]
    assert passed == str(wordlist_dir / "hibp"), (
        f"expected the directory itself, got {passed!r}"
    )


@pytest.mark.parametrize(
    "picker",
    ["_pick_training_wordlist", "_markov_pick_training_source"],
)
def test_training_pickers_refuse_a_directory(
    hc_module, wordlist_dir, tmp_path, monkeypatch, capsys, picker
):
    """OMEN and Markov training take one file. A directory reached
    hcatOmenTrain / hcatMarkovTrain and failed there instead of at selection.

    Note the asymmetry this fixes: the "p. Enter a custom path" branch of both
    pickers already validated, so only the numbered shortcut was exposed.
    """
    from types import SimpleNamespace

    from hate_crack import attacks

    hash_file = tmp_path / "hashes.txt"
    hash_file.write_text("x\n")
    ctx = SimpleNamespace(
        hcatWordlists=str(wordlist_dir),
        hcatHashFile=str(hash_file),
        list_wordlist_files=hc_module.list_wordlist_files,
        list_wordlist_entries=hc_module.list_wordlist_entries,
        select_file_with_autocomplete=lambda *a, **k: "",
    )
    entries = hc_module.list_wordlist_entries(str(wordlist_dir))
    dir_choice = str(1 + [e.name for e in entries].index("hibp"))

    answers = iter([dir_choice, "q"])
    monkeypatch.setattr("builtins.input", lambda *a: next(answers))

    result = getattr(attacks, picker)(ctx)

    assert result is None, f"a directory was accepted as a training file: {result!r}"
    assert "directory" in capsys.readouterr().out.lower(), (
        "the rejection must say why, or the menu looks like it ignored the key"
    )


def test_generate_rules_picker_refuses_a_directory(
    hc_module, wordlist_dir, tmp_path, monkeypatch, capsys
):
    """Rule generation hands its wordlist argument straight to hashcat. The
    numbered shortcut used `os.path.exists(chosen)` as its guard, which a
    directory passes -- so a directory picked here reached hashcat instead of
    being refused at selection, unlike the "enter a path" and default-Enter
    branches this test does not touch.
    """
    from types import SimpleNamespace

    from hate_crack import attacks

    calls = []
    hash_file = tmp_path / "hashes.txt"
    hash_file.write_text("x\n")
    ctx = SimpleNamespace(
        hcatWordlists=str(wordlist_dir),
        hcatHashType="1000",
        hcatHashFile=str(hash_file),
        list_wordlist_entries=hc_module.list_wordlist_entries,
        hcatGenerateRules=lambda *a, **k: calls.append((a, k)),
    )
    entries = hc_module.list_wordlist_entries(str(wordlist_dir))
    dir_choice = str(1 + [e.name for e in entries].index("hibp"))
    file_choice = str(1 + [e.name for e in entries].index("rockyou.txt"))

    # "" answers the rule-count prompt (default). Then a directory is picked
    # and must be refused -- looping back for a second, valid pick.
    answers = iter(["", dir_choice, file_choice])
    monkeypatch.setattr("builtins.input", lambda *a: next(answers))
    monkeypatch.setattr(attacks._notify, "prompt_notify_for_attack", lambda *a: None)

    attacks.generate_rules_crack(ctx)

    out = capsys.readouterr().out.lower()
    assert "directory" in out, (
        "the rejection must say why, or the menu looks like it ignored the key"
    )
    assert calls, "hcatGenerateRules was never called -- the picker did not loop"
    passed_wordlist = calls[0][0][3]
    assert passed_wordlist == str(wordlist_dir / "rockyou.txt"), (
        f"expected the second, valid pick to go through, got {passed_wordlist!r}"
    )
