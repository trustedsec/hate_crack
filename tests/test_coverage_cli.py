"""The coverage CLI subcommand and the scripted skip exit code (#273)."""

import os
import types
from unittest.mock import patch

import pytest

from hate_crack import attack_coverage as ac
from hate_crack import noninteractive as ni


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


@pytest.fixture
def store(tmp_path, monkeypatch):
    s = ac.CoverageStore(tmp_path / "cov.sqlite3")
    monkeypatch.setattr(ac, "get_store", lambda: s)
    ac.clear_target_memo()
    yield s
    s.close()
    ac.clear_target_memo()


@pytest.fixture
def hashes(tmp_path):
    path = tmp_path / "target.txt"
    path.write_text("aad3b435b51404eeaad3b435b51404ee\n")
    return str(path)


def _args(**kw):
    return types.SimpleNamespace(**kw)


# --- coverage status / history / forget ------------------------------------


def test_status_on_an_untouched_target(main_module, store, hashes, capsys):
    code = main_module._run_coverage_command(
        _args(coverage_command="status", hashfile=hashes)
    )
    assert code == 0
    assert "No attacks recorded" in capsys.readouterr().out


def test_status_reports_entries_runs_and_the_attack_split(
    main_module, store, hashes, capsys
):
    target = ac.target_id(hashes)
    store.record(["a", "b", "c"], target=target, kind="rule", attack="Dictionary")
    store.log_run(target, attack="PRINCE", kind="history")

    main_module._run_coverage_command(_args(coverage_command="status", hashfile=hashes))
    out = capsys.readouterr().out
    assert "entries   : 3" in out
    assert "runs      : 2" in out
    assert "Dictionary" in out and "PRINCE" in out


def test_history_lists_every_run_including_unfiltered_ones(
    main_module, store, hashes, capsys
):
    target = ac.target_id(hashes)
    store.record(["a"], target=target, attack="Dictionary")
    store.log_run(target, attack="PRINCE", kind="history")
    main_module._run_coverage_command(
        _args(coverage_command="history", hashfile=hashes)
    )
    out = capsys.readouterr().out
    assert "Dictionary" in out
    assert "PRINCE" in out


def test_forget_requires_confirmation(main_module, store, hashes, capsys):
    target = ac.target_id(hashes)
    store.record(["a", "b"], target=target, attack="Dictionary")

    with patch("builtins.input", lambda *a: "n"):
        main_module._run_coverage_command(
            _args(coverage_command="forget", hashfile=hashes, yes=False)
        )
    assert "Left unchanged" in capsys.readouterr().out
    assert store.covered(["a", "b"]) == {"a", "b"}


def test_forget_yes_skips_the_prompt_and_clears(main_module, store, hashes, capsys):
    target = ac.target_id(hashes)
    store.record(["a", "b"], target=target, attack="Dictionary")

    def explode(*a, **kw):
        raise AssertionError("--yes must not prompt")

    with patch("builtins.input", explode):
        code = main_module._run_coverage_command(
            _args(coverage_command="forget", hashfile=hashes, yes=True)
        )
    assert code == 0
    assert "Dropped 2" in capsys.readouterr().out
    assert store.covered(["a", "b"]) == set()


def test_forget_only_touches_the_named_target(main_module, store, hashes, tmp_path):
    other = tmp_path / "other.txt"
    other.write_text("31d6cfe0d16ae931b73c59d7e0c089c0\n")
    store.record(["a"], target=ac.target_id(hashes), attack="Dictionary")
    store.record(["b"], target=ac.target_id(str(other)), attack="Dictionary")

    main_module._run_coverage_command(
        _args(coverage_command="forget", hashfile=hashes, yes=True)
    )
    assert store.covered(["a", "b"]) == {"b"}


def test_a_missing_hash_file_is_an_error(main_module, store, tmp_path, capsys):
    code = main_module._run_coverage_command(
        _args(coverage_command="status", hashfile=str(tmp_path / "nope.txt"))
    )
    assert code == 1
    assert "not found" in capsys.readouterr().out


def test_no_subcommand_is_an_error(main_module, store, hashes, capsys):
    code = main_module._run_coverage_command(
        _args(coverage_command=None, hashfile=hashes)
    )
    assert code == 2
    assert "status, history, forget" in capsys.readouterr().out


def test_the_cli_parses_and_dispatches_the_coverage_subcommand(
    main_module, store, hashes, monkeypatch, capsys
):
    """End to end through main(): argv -> parser -> _run_coverage_command.

    _build_parser is nested inside main(), so the only honest way to pin the
    subcommand wiring is to drive the real entry point.
    """
    target = ac.target_id(hashes)
    store.record(["a"], target=target, attack="Dictionary")

    monkeypatch.setattr(
        main_module.sys,
        "argv",
        ["hate_crack", "coverage", "status", "--hashfile", hashes],
    )
    with pytest.raises(SystemExit) as excinfo:
        main_module.main()
    assert excinfo.value.code == 0
    assert "entries   : 1" in capsys.readouterr().out


def test_coverage_forget_runs_end_to_end(
    main_module, store, hashes, monkeypatch, capsys
):
    target = ac.target_id(hashes)
    store.record(["a", "b"], target=target, attack="Dictionary")
    monkeypatch.setattr(
        main_module.sys,
        "argv",
        ["hate_crack", "coverage", "forget", "--hashfile", hashes, "--yes"],
    )
    with pytest.raises(SystemExit) as excinfo:
        main_module.main()
    assert excinfo.value.code == 0
    assert store.covered(["a", "b"]) == set()


# --- coverage precompute ----------------------------------------------------


def test_run_coverage_precompute_direct(main_module, store, tmp_path, capsys):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "a.rule").write_text("$1\nc\n", encoding="utf-8")
    masks_dir = tmp_path / "masks"
    masks_dir.mkdir()
    (masks_dir / "a.hcmask").write_text("?d?d\n", encoding="utf-8")

    code = main_module._run_coverage_precompute(
        _args(rules_dir=[str(rules_dir)], masks_dir=[str(masks_dir)])
    )
    assert code == 0
    assert "Built 2 manifest(s), 0 failed." in capsys.readouterr().out


def test_run_coverage_precompute_skips_missing_directories(
    main_module, store, tmp_path, capsys
):
    """A configured-but-absent directory contributes zero paths, not a crash."""
    code = main_module._run_coverage_precompute(
        _args(rules_dir=[str(tmp_path / "nope")], masks_dir=[str(tmp_path / "gone")])
    )
    assert code == 0
    assert "Built 0 manifest(s), 0 failed." in capsys.readouterr().out


def test_coverage_precompute_cli_does_not_require_hashfile(
    main_module, store, tmp_path, monkeypatch, capsys
):
    """`coverage precompute` has no --hashfile and must not crash on args.hashfile.

    Regression test: the naive wiring resolves args.hashfile unconditionally
    before dispatching on the subcommand, which raises AttributeError for a
    subparser that was never given a --hashfile argument.
    """
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "a.rule").write_text("$1\n", encoding="utf-8")

    monkeypatch.setattr(
        main_module.sys,
        "argv",
        [
            "hate_crack",
            "coverage",
            "precompute",
            "--rules-dir",
            str(rules_dir),
            "--masks-dir",
            str(tmp_path / "no-masks-here"),
        ],
    )
    with pytest.raises(SystemExit) as excinfo:
        main_module.main()
    assert excinfo.value.code == 0
    assert "Built 1 manifest(s), 0 failed." in capsys.readouterr().out


def test_run_coverage_precompute_skips_unreadable_directory(
    main_module, store, tmp_path, capsys
):
    """An unreadable (as opposed to absent) directory is a visible skip, not a crash.

    os.path.isdir() is True for a directory with no read permission, so the
    crash lives one line later, in os.listdir(). Restore permissions in a
    finally so tmp_path's own cleanup doesn't choke on an unreadable dir.
    """
    unreadable = tmp_path / "unreadable"
    unreadable.mkdir()
    readable = tmp_path / "readable"
    readable.mkdir()
    (readable / "a.rule").write_text("$1\n", encoding="utf-8")

    os.chmod(unreadable, 0o000)
    try:
        code = main_module._run_coverage_precompute(
            _args(
                rules_dir=[str(unreadable), str(readable)],
                masks_dir=[str(tmp_path / "gone")],
            )
        )
    finally:
        os.chmod(unreadable, 0o755)

    out = capsys.readouterr().out
    assert code == 0
    assert "Built 1 manifest(s), 0 failed." in out
    assert f"[!] Skipping {unreadable}" in out


def test_run_coverage_precompute_uses_the_tools_own_default_directories(
    main_module, store, tmp_path, monkeypatch, capsys
):
    """rules_dir=None/masks_dir=None must resolve via the tool's own defaults.

    Pins rulesDirectory reuse and hate_path/masks specifically -- without
    this, a future change to either default's resolution could pass every
    other precompute test (which all pass explicit directories) while
    silently breaking the CLI's undecorated default invocation.
    """
    default_rules = tmp_path / "default-rules"
    default_rules.mkdir()
    (default_rules / "a.rule").write_text("$1\n", encoding="utf-8")
    (default_rules / "b.rule").write_text("c\n", encoding="utf-8")

    default_masks_parent = tmp_path / "default-hate-path"
    default_masks_parent.mkdir()
    default_masks = default_masks_parent / "masks"
    default_masks.mkdir()
    (default_masks / "a.hcmask").write_text("?d?d\n", encoding="utf-8")

    monkeypatch.setattr(main_module, "rulesDirectory", str(default_rules))
    monkeypatch.setattr(main_module, "hate_path", str(default_masks_parent))

    code = main_module._run_coverage_precompute(_args(rules_dir=None, masks_dir=None))
    assert code == 0
    assert "Built 3 manifest(s), 0 failed." in capsys.readouterr().out


# --- coverage compact --------------------------------------------------------


def test_compact_requires_confirmation(main_module, store, capsys):
    with patch("builtins.input", lambda *a: "n"):
        code = main_module._run_coverage_compact(
            _args(rules_dir=None, masks_dir=None, yes=False)
        )
    assert code == 0
    assert "Left unchanged" in capsys.readouterr().out


def test_compact_yes_skips_the_prompt_and_runs(main_module, store, capsys):
    def explode(*a, **kw):
        raise AssertionError("--yes must not prompt")

    with patch("builtins.input", explode):
        code = main_module._run_coverage_compact(
            _args(rules_dir=None, masks_dir=None, yes=True)
        )
    out = capsys.readouterr().out
    assert code == 0
    assert "Converted: 0" in out
    assert "Unconvertible: 0" in out
    assert "Dropped old table:" in out


def test_compact_cli_does_not_require_hashfile(main_module, store, monkeypatch, capsys):
    """`coverage compact` has no --hashfile and must not crash on args.hashfile,
    same regression as precompute's equivalent test.
    """
    monkeypatch.setattr(
        main_module.sys,
        "argv",
        ["hate_crack", "coverage", "compact", "--yes"],
    )

    def explode(*a, **kw):
        raise AssertionError("--yes must not prompt")

    with patch("builtins.input", explode):
        with pytest.raises(SystemExit) as excinfo:
            main_module.main()
    assert excinfo.value.code == 0
    assert "Dropped old table:" in capsys.readouterr().out


def test_compact_reports_unconvertible_coverage(main_module, store, capsys):
    target = "t" * 64
    old_key = ac.entry_key(target, "rule", "w" * 64, "unbacked", "")
    conn = store._connect()
    conn.executescript(
        "CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "target TEXT NOT NULL, kind TEXT NOT NULL DEFAULT '', "
        "attack TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '', "
        "ran_at TEXT NOT NULL);"
    )
    conn.execute(
        "INSERT INTO runs (target, kind, ran_at) VALUES (?, ?, ?)",
        (target, "rule", "2026-01-01T00:00:00+00:00"),
    )
    conn.execute("INSERT OR IGNORE INTO legacy_targets (target) VALUES (?)", (target,))
    conn.execute("INSERT INTO covered VALUES (?, 1)", (old_key,))
    conn.commit()

    with patch("builtins.input", lambda *a: "y"):
        code = main_module._run_coverage_compact(
            _args(rules_dir=None, masks_dir=None, yes=False)
        )
    out = capsys.readouterr().out
    assert code == 0
    assert "Unconvertible: 1" in out
    assert "Dropped old table: False" in out
    assert "could not be reconstructed" in out


# --- the scripted skip exit code -------------------------------------------


def _ctx(launches, skips, rc=0):
    return types.SimpleNamespace(
        reset_run_counters=lambda: None,
        run_counters=lambda: (launches, skips),
        hcatHashType="1000",
        hcatHashFile="h.txt",
        hcatDictionary=lambda *a, **kw: None,
    )


def test_a_fully_skipped_scripted_run_exits_3_when_asked(capsys):
    code = ni.run_noninteractive(
        _ctx(launches=0, skips=2), _args(command="dict", exit_code_on_skip=True)
    )
    assert code == ni.SKIPPED_BY_COVERAGE == 3
    assert "already covered" in capsys.readouterr().out


def test_a_fully_skipped_run_still_exits_0_without_the_flag():
    """Coverage is on by default, so the flag is what keeps existing set -e
    harnesses from failing the first time an attack repeats."""
    code = ni.run_noninteractive(
        _ctx(launches=0, skips=2), _args(command="dict", exit_code_on_skip=False)
    )
    assert code == 0


def test_a_partially_skipped_run_exits_0(capsys):
    """Something ran, so the run did work -- 3 means nothing was launched."""
    code = ni.run_noninteractive(
        _ctx(launches=1, skips=3), _args(command="dict", exit_code_on_skip=True)
    )
    assert code == 0


def test_a_normal_run_exits_0_with_the_flag_set():
    code = ni.run_noninteractive(
        _ctx(launches=1, skips=0), _args(command="dict", exit_code_on_skip=True)
    )
    assert code == 0


def test_an_input_error_outranks_the_skip_code(capsys):
    """A bad wordlist is still exit 1, not 3."""
    ctx = types.SimpleNamespace(
        reset_run_counters=lambda: None,
        run_counters=lambda: (0, 0),
        resolve_path=lambda p: None,
    )
    code = ni.run_noninteractive(
        ctx, _args(command="quick", wordlist="nope.txt", exit_code_on_skip=True)
    )
    assert code == 1


def test_counters_reset_between_runs(main_module):
    main_module.reset_run_counters()
    assert main_module.run_counters() == (0, 0)
