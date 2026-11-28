"""A hashcat run that bypassed a queue item must not be recorded as covered.

hashcat b1b1f3ea makes a queue whose last item was bypassed exit 1, the code
_run_hcat_cmd treats as "keyspace exhausted". The session log's
status-after-work lines are the only signal that tells the two apart.
"""

from unittest.mock import patch

import pytest

from hate_crack import attack_coverage as ac
from hate_crack import session_log

SESSION = "target_Dictionary"
EXHAUSTED = "TOP.1\tSUB.1\tstatus-after-work\t5\n"
BYPASSED = "TOP.1\tSUB.2\tstatus-after-work\t9\n"


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


@pytest.fixture
def env(tmp_path):
    hashes = tmp_path / "target.txt"
    hashes.write_text("aad3b435b51404eeaad3b435b51404ee\n")
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("alpha\nbravo\n")
    rules = tmp_path / "r.rule"
    rules.write_text("c\n$1\nu\n")
    log = tmp_path / "sessions" / f"{SESSION}.log"
    log.parent.mkdir()
    return {
        "hashes": str(hashes),
        "wordlist": str(wordlist),
        "rules": str(rules),
        "log": log,
    }


@pytest.fixture
def store(env):
    ac.reset_store()
    ac.clear_target_memo()
    yield ac.get_store(env["hashes"])
    ac.reset_store()
    ac.clear_target_memo()


class FakePopen:
    def __init__(self, returncode):
        self.pid = 4242
        self.returncode = returncode

    def wait(self):
        return self.returncode

    def kill(self):
        pass


def _run(main_module, env, cmd, *, writes="", returncode=1):
    """Run _run_hcat_cmd with a fake hashcat that appends *writes* to the log."""

    def fake_popen(cmd, **kwargs):
        if writes:
            with open(env["log"], "a") as fh:
                fh.write(writes)
        return FakePopen(returncode)

    spec = ac.CoverageSpec(
        hash_file=env["hashes"],
        wordlists=(env["wordlist"],),
        rule_files=(env["rules"],),
    )
    with (
        patch.object(main_module.subprocess, "Popen", fake_popen),
        patch.object(main_module, "_coverage_enabled", True),
        patch.object(main_module, "non_interactive", False),
        patch.object(
            session_log,
            "candidate_log_paths",
            lambda session, hcat_bin: [str(env["log"])],
        ),
        patch("builtins.input", lambda *a: "y"),
    ):
        main_module._run_hcat_cmd(cmd, attack_name="Dictionary", coverage=spec)
    return spec


def _cmd(env, session=True):
    cmd = ["hashcat", env["hashes"], env["wordlist"], "-r", env["rules"]]
    return cmd + ["--session", SESSION] if session else cmd


def test_bypassed_run_records_nothing(main_module, store, env, capsys):
    spec = _run(main_module, env, _cmd(env), writes=EXHAUSTED + BYPASSED)
    assert ac.plan_run(spec).covered_count == 0
    assert "bypassed" in capsys.readouterr().out


def test_exhausted_run_still_records(main_module, store, env):
    spec = _run(main_module, env, _cmd(env), writes=EXHAUSTED)
    assert ac.plan_run(spec).skip is True


def test_bypass_from_an_earlier_run_is_ignored(main_module, store, env):
    env["log"].write_text(BYPASSED)
    spec = _run(main_module, env, _cmd(env), writes=EXHAUSTED)
    assert ac.plan_run(spec).skip is True


def test_missing_log_keeps_exit_code_behaviour(main_module, store, env):
    """No readable log is 'unknown', not 'bypassed': coverage must not go
    silently dead on a build that keeps its sessions somewhere unexpected."""
    spec = _run(main_module, env, _cmd(env), writes="")
    assert ac.plan_run(spec).skip is True


def test_command_without_session_keeps_exit_code_behaviour(main_module, store, env):
    spec = _run(main_module, env, _cmd(env, session=False), writes=BYPASSED)
    assert ac.plan_run(spec).skip is True


def test_bypassed_specless_run_is_not_logged(main_module, store, env):
    """Attacks without a spec log one 'it ran' row on completion; a bypassed
    one did not run to completion either."""
    logged = []

    def fake_popen(cmd, **kwargs):
        with open(env["log"], "a") as fh:
            fh.write(BYPASSED)
        return FakePopen(1)

    with (
        patch.object(main_module.subprocess, "Popen", fake_popen),
        patch.object(main_module, "_coverage_enabled", True),
        patch.object(main_module, "_brain_enabled", False),
        patch.object(
            session_log,
            "candidate_log_paths",
            lambda session, hcat_bin: [str(env["log"])],
        ),
        patch.object(type(store), "log_run", lambda self, *a, **k: logged.append(a)),
    ):
        main_module._run_hcat_cmd(
            _cmd(env), attack_name="PRINCE", hash_file=env["hashes"]
        )
    assert logged == []
