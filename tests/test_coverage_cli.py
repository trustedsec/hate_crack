"""The coverage CLI subcommand and the scripted skip exit code (#273)."""

import types
from unittest.mock import patch

import pytest

from hate_crack import attack_coverage as ac
from hate_crack import noninteractive as ni
from hate_crack.coverage_store import NO_WORDLIST


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


@pytest.fixture
def hashes(tmp_path):
    path = tmp_path / "target.txt"
    path.write_text("aad3b435b51404eeaad3b435b51404ee\n")
    return str(path)


@pytest.fixture
def store(hashes):
    ac.reset_store()
    ac.clear_target_memo()
    s = ac.get_store(str(hashes))
    yield s
    ac.reset_store()
    ac.clear_target_memo()


def _record(store, target, entries, attack="Dictionary", kind="rule"):
    """Record rule entries against ``target`` in the no-wordlist scope."""
    rows = [(NO_WORDLIST, ac.entry_hash(kind, entry)) for entry in entries]
    store.record(
        target=target,
        kind=kind,
        variant="",
        attack=attack,
        wordlist_ids=(),
        rows=rows,
    )


def _covered(store, target, entries, kind="rule"):
    """The subset of ``entries`` the store reports covered."""
    hashed = {ac.entry_hash(kind, entry): entry for entry in entries}
    found = store.covered(target, NO_WORDLIST, "", kind, list(hashed))
    return {hashed[h] for h in found}


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
    _record(store, target, ["a", "b", "c"])
    store.log_run(target, attack="PRINCE")

    main_module._run_coverage_command(_args(coverage_command="status", hashfile=hashes))
    out = capsys.readouterr().out
    assert "entries   : 3" in out
    assert "runs      : 2" in out
    assert "Dictionary" in out and "PRINCE" in out


def test_history_lists_every_run_including_unfiltered_ones(
    main_module, store, hashes, capsys
):
    target = ac.target_id(hashes)
    _record(store, target, ["a"])
    store.log_run(target, attack="PRINCE")
    main_module._run_coverage_command(
        _args(coverage_command="history", hashfile=hashes)
    )
    out = capsys.readouterr().out
    assert "Dictionary" in out
    assert "PRINCE" in out


def test_forget_requires_confirmation(main_module, store, hashes, capsys):
    target = ac.target_id(hashes)
    _record(store, target, ["a", "b"])

    with patch("builtins.input", lambda *a: "n"):
        main_module._run_coverage_command(
            _args(coverage_command="forget", hashfile=hashes, yes=False)
        )
    assert "Left unchanged" in capsys.readouterr().out
    assert _covered(store, target, ["a", "b"]) == {"a", "b"}


def test_forget_yes_skips_the_prompt_and_clears(main_module, store, hashes, capsys):
    target = ac.target_id(hashes)
    _record(store, target, ["a", "b"])

    def explode(*a, **kw):
        raise AssertionError("--yes must not prompt")

    with patch("builtins.input", explode):
        code = main_module._run_coverage_command(
            _args(coverage_command="forget", hashfile=hashes, yes=True)
        )
    assert code == 0
    assert "Dropped 2" in capsys.readouterr().out
    assert _covered(store, target, ["a", "b"]) == set()


def test_forget_only_touches_the_named_target(main_module, store, hashes, tmp_path):
    """Both targets live in ONE store: rewriting a hash file in place gives it a
    new content sha256 (a new target) but the same <hashfile>.coverage.sqlite3."""
    old_target = ac.target_id(hashes)
    _record(store, old_target, ["a"], attack="Old Attack")

    with open(hashes, "w") as handle:
        handle.write("31d6cfe0d16ae931b73c59d7e0c089c0\n")
    ac.clear_target_memo()
    new_target = ac.target_id(hashes)
    assert new_target != old_target
    assert ac.get_store(hashes) is store
    _record(store, new_target, ["b"], attack="New Attack")

    main_module._run_coverage_command(
        _args(coverage_command="forget", hashfile=hashes, yes=True)
    )

    assert _covered(store, new_target, ["b"]) == set()
    assert store.summary(new_target)["runs"] == 0
    assert store.history(new_target) == []
    assert _covered(store, old_target, ["a"]) == {"a"}
    assert store.summary(old_target)["entries"] == 1
    assert [row[0] for row in store.history(old_target)] == ["Old Attack"]


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
    _record(store, target, ["a"])

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
    _record(store, target, ["a", "b"])
    monkeypatch.setattr(
        main_module.sys,
        "argv",
        ["hate_crack", "coverage", "forget", "--hashfile", hashes, "--yes"],
    )
    with pytest.raises(SystemExit) as excinfo:
        main_module.main()
    assert excinfo.value.code == 0
    assert _covered(store, target, ["a", "b"]) == set()


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
