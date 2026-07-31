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


def test_generate_rules_picker_passes_a_selected_directory_through_as_a_directory(
    hc_module, wordlist_dir, tmp_path, monkeypatch
):
    """Rule generation hands its wordlist argument straight to hashcat as a
    straight-mode (`-a 0`) dictionary position, and hashcat itself accepts a
    directory there (`-a 0 -r r.rule <dir>` works). The numbered shortcut must
    agree with the Enter-default and typed-path branches, which already pass a
    directory through untouched -- mirroring
    test_quick_crack_passes_a_selected_directory_through_as_a_directory."""
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

    # "" answers the rule-count prompt (default). Then a directory is picked
    # and must be accepted immediately -- no second prompt.
    answers = iter(["", dir_choice])
    monkeypatch.setattr("builtins.input", lambda *a: next(answers))
    monkeypatch.setattr(attacks._notify, "prompt_notify_for_attack", lambda *a: None)

    attacks.generate_rules_crack(ctx)

    assert calls, "hcatGenerateRules was never called"
    passed_wordlist = calls[0][0][3]
    assert passed_wordlist == str(wordlist_dir / "hibp"), (
        f"expected the directory itself, got {passed_wordlist!r}"
    )


def test_generate_rules_picker_colours_directory_entries(
    hc_module, wordlist_dir, tmp_path, monkeypatch
):
    """Quick Crack, OMEN, and Markov all highlight directory entries in cyan
    via a `styles=` list passed to print_multicolumn_list. The rule-generation
    picker built the same directory markers but never built or passed the
    matching styles list, so its directories rendered uncoloured."""
    from types import SimpleNamespace

    from hate_crack import attacks

    hash_file = tmp_path / "hashes.txt"
    hash_file.write_text("x\n")
    ctx = SimpleNamespace(
        hcatWordlists=str(wordlist_dir),
        hcatHashType="1000",
        hcatHashFile=str(hash_file),
        list_wordlist_entries=hc_module.list_wordlist_entries,
        hcatGenerateRules=lambda *a, **k: None,
    )
    entries = hc_module.list_wordlist_entries(str(wordlist_dir))
    file_choice = str(1 + [e.name for e in entries].index("rockyou.txt"))

    captured = {}
    original = attacks.print_multicolumn_list

    def spy(*args, **kwargs):
        captured["styles"] = kwargs.get("styles")
        return original(*args, **kwargs)

    monkeypatch.setattr(attacks, "print_multicolumn_list", spy)

    answers = iter(["", file_choice])
    monkeypatch.setattr("builtins.input", lambda *a: next(answers))
    monkeypatch.setattr(attacks._notify, "prompt_notify_for_attack", lambda *a: None)

    attacks.generate_rules_crack(ctx)

    styles = captured.get("styles")
    assert styles, "print_multicolumn_list was not given a styles list"
    is_dir_by_position = [e.is_dir for e in entries]
    expected = ["\033[36m" if is_dir else None for is_dir in is_dir_by_position]
    assert styles == expected, (
        f"expected directory entries highlighted in cyan, got {styles!r}"
    )


def _capture_rule_completer(ctx):
    """Drive `_rule_select_file` with a stubbed input/readline just far enough
    to capture the `rule_completer` closure it registers, then hand it back
    so tests can call it directly with arbitrary (text, state) pairs.
    """
    from hate_crack import attacks

    captured = {}

    def fake_configure(completer):
        captured["completer"] = completer

    original = attacks._configure_readline
    attacks._configure_readline = fake_configure
    try:
        import builtins

        original_input = builtins.input
        builtins.input = lambda *a: ""
        try:
            attacks._rule_select_file(ctx, "rule: ")
        finally:
            builtins.input = original_input
    finally:
        attacks._configure_readline = original

    return captured["completer"]


def _all_rule_matches(completer, text):
    matches = []
    state = 0
    while (m := completer(text, state)) is not None:
        matches.append(m)
        state += 1
    return matches


def test_rule_completer_marks_directories_and_globs_consistently(tmp_path):
    """The odd one out: five of the six tab-completers add a trailing / for a
    directory and this one does not. It also globs *.rule when the input is
    empty but <text>* once you type, so typing one character surfaces non-rule
    files the empty prompt hides.
    """
    from types import SimpleNamespace

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "best64.rule").write_text(":\n")
    (rules / "notes.txt").write_text("x\n")
    (rules / "collection").mkdir()

    ctx = SimpleNamespace(rulesDirectory=str(rules))
    completer = _capture_rule_completer(ctx)
    matches = _all_rule_matches(completer, "")

    assert any(m.endswith("collection/") for m in matches), (
        f"directory not marked with a trailing slash: {matches}"
    )
    assert not any(m.endswith("notes.txt") for m in matches), (
        f"a non-rule file was offered: {matches}"
    )


def test_rule_completer_incremental_typing_still_completes_past_the_dot(tmp_path):
    """Filtering on `.rule` must happen after the glob, not by baking
    `*.rule` into the glob pattern -- otherwise typing past the base name
    (into the extension itself) stops matching anything.
    """
    from types import SimpleNamespace

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "best64.rule").write_text(":\n")
    (rules / "best64.rule.bak").write_text(":\n")
    (rules / "notes.txt").write_text("x\n")

    ctx = SimpleNamespace(rulesDirectory=str(rules))
    completer = _capture_rule_completer(ctx)

    for typed in ("best", "best64", "best64.", "best64.r", "best64.rule"):
        matches = _all_rule_matches(completer, typed)
        assert any(m.endswith("best64.rule") for m in matches), (
            f"typing {typed!r} lost the completion: {matches}"
        )
        assert not any(m.endswith("best64.rule.bak") for m in matches), (
            f"typing {typed!r} surfaced a backup file: {matches}"
        )
        assert not any(m.endswith("notes.txt") for m in matches), (
            f"typing {typed!r} surfaced a non-rule file: {matches}"
        )


def test_rule_completer_marks_directories_in_base_and_relative_branches(tmp_path):
    """A directory must get its trailing slash in both the base-directory
    branch and the `./`-relative free-path branch -- deriving the marker
    from a separately hardcoded `os.path.join(base, ...)` only worked for
    the base branch (and, by accident, absolute paths).
    """
    from types import SimpleNamespace

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "collection").mkdir()

    other = tmp_path / "elsewhere"
    other.mkdir()
    (other / "extra").mkdir()

    ctx = SimpleNamespace(rulesDirectory=str(rules))
    completer = _capture_rule_completer(ctx)

    base_matches = _all_rule_matches(completer, "coll")
    assert any(m.endswith("collection/") for m in base_matches), (
        f"base-directory branch did not mark the directory: {base_matches}"
    )

    cwd = os.getcwd()
    os.chdir(str(tmp_path))
    try:
        rel_matches = _all_rule_matches(completer, "./elsewhere/ext")
    finally:
        os.chdir(cwd)
    assert any(m.endswith("extra/") for m in rel_matches), (
        f"./-relative branch did not mark the directory: {rel_matches}"
    )


def test_rule_completer_ordering_stable_across_repeated_state_calls(tmp_path):
    """The completer recomputes its match list on every call; repeated calls
    for the same `text` must still yield the same list, or completion
    (which walks `state` up from 0) behaves erratically.
    """
    from types import SimpleNamespace

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "best64.rule").write_text(":\n")
    (rules / "dive.rule").write_text(":\n")
    (rules / "collection").mkdir()

    ctx = SimpleNamespace(rulesDirectory=str(rules))
    completer = _capture_rule_completer(ctx)

    first = _all_rule_matches(completer, "")
    second = _all_rule_matches(completer, "")
    assert first == second, (
        f"match ordering was not stable across repeated calls: {first} != {second}"
    )


def test_hashmob_dedup_set_ignores_directories(tmp_path):
    """A directory name could shadow a rule filename and skip a real download."""
    from hate_crack import api

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "best64.rule").write_text(":\n")
    (rules / "wanted.rule").mkdir()  # a directory sharing a wanted filename

    already = api._downloaded_rule_names(str(rules))

    assert "best64.rule" in already
    assert "wanted.rule" not in already, (
        "a directory shadowed a rule filename and would skip its download"
    )


def test_optimize_emptiness_check_ignores_dot_files(hc_module, tmp_path):
    """`if not os.listdir(outdir)` is defeated by a stray .DS_Store, so the
    first wordlist takes the slow merge path against an empty directory."""
    outdir = tmp_path / "optimized"
    outdir.mkdir()
    (outdir / ".DS_Store").write_text("")

    assert hc_module._outdir_is_empty(str(outdir)) is True

    (outdir / "len8.txt").write_text("password\n")
    assert hc_module._outdir_is_empty(str(outdir)) is False


def test_hcatDictionary_includes_subdirectories_in_dictionary_args(
    hc_module, wordlist_dir, tmp_path, monkeypatch
):
    """Issue #233 follow-up: hcatDictionary built its dictionary arguments from
    list_wordlist_files (files only), so a subdirectory like wordlists/hibp/
    was silently dropped from the standard Dictionary attack even though
    hashcat itself enumerates every file inside it in this straight-mode
    dictionary position (verified against the real binary: `-a 0 w1.txt sub`
    enumerates both). Quick Crack already treats a directory as a legitimate
    dictionary argument; hcatDictionary must match that policy.
    """
    hash_file = tmp_path / "hashes.txt"
    hash_file.write_text("aad3b435b51404eeaad3b435b51404ee\n")
    (tmp_path / "hashes.txt.out").write_text("")

    captured_cmds = []

    def fake_run_hcat_cmd(cmd, **kwargs):
        captured_cmds.append(list(cmd))

    monkeypatch.setattr(hc_module, "hcatWordlists", str(wordlist_dir))
    monkeypatch.setattr(hc_module, "hcatDictionaryWordlist", [])
    monkeypatch.setattr(hc_module, "hcatBruteCount", 0)
    monkeypatch.setattr(hc_module, "hcatHashFile", str(hash_file))
    monkeypatch.setattr(hc_module, "_run_hcat_cmd", fake_run_hcat_cmd)

    hc_module.hcatDictionary("1000", str(hash_file))

    assert captured_cmds, "hcatDictionary never invoked _run_hcat_cmd"
    dictionary_cmd = captured_cmds[0]
    assert str(wordlist_dir / "hibp") in dictionary_cmd, (
        "the wordlists subdirectory was dropped from the Dictionary attack's "
        f"arguments: {dictionary_cmd}"
    )
