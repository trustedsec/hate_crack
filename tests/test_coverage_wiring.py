"""Coverage tracking as wired into main.py's hashcat funnel (#273).

The store and planner are unit-tested in test_attack_coverage*.py. What is
pinned here is the plumbing: that _run_hcat_cmd consults the store before
launching, rewrites or skips the run accordingly, and records only on clean
completion.
"""

import inspect
import os

from unittest.mock import patch

import pytest

from hate_crack import attack_coverage as ac


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


@pytest.fixture
def store(tmp_path, monkeypatch):
    s = ac.CoverageStore(tmp_path / "cov.sqlite3")
    monkeypatch.setattr(ac, "get_store", lambda: s)
    yield s
    s.close()


@pytest.fixture
def env(tmp_path):
    hashes = tmp_path / "target.txt"
    hashes.write_text("aad3b435b51404eeaad3b435b51404ee\n")
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("alpha\nbravo\n")
    rules = tmp_path / "r.rule"
    rules.write_text("c\n$1\nu\n")
    return {
        "hashes": str(hashes),
        "wordlist": str(wordlist),
        "rules": str(rules),
        "tmp": tmp_path,
    }


class FakePopen:
    """Minimal Popen double that reports a chosen exit status."""

    def __init__(self, cmd, returncode=1, raise_interrupt=False, **kwargs):
        self.cmd = list(cmd)
        self.pid = 4242
        self.returncode = returncode
        self._raise_interrupt = raise_interrupt

    def wait(self):
        if self._raise_interrupt:
            raise KeyboardInterrupt
        return self.returncode

    def kill(self):
        pass


def _run(
    main_module,
    cmd,
    spec,
    returncode=1,
    raise_interrupt=False,
    answer="y",
    seen_rules=None,
):
    """Drive _run_hcat_cmd with a fake hashcat and capture the launched cmd.

    ``seen_rules`` collects the *contents* of the -r file as hashcat would have
    seen them. It has to be read at launch time: a filtered rule file is a temp
    file that _run_hcat_cmd unlinks once the run returns.
    """
    launched = []

    def fake_popen(cmd, **kwargs):
        launched.append(list(cmd))
        if seen_rules is not None and "-r" in cmd:
            seen_rules.append(ac.read_entries(cmd[cmd.index("-r") + 1]))
        return FakePopen(cmd, returncode=returncode, raise_interrupt=raise_interrupt)

    with (
        patch.object(main_module.subprocess, "Popen", fake_popen),
        patch.object(main_module, "_coverage_enabled", True),
        patch.object(main_module, "non_interactive", False),
        patch("builtins.input", lambda *a: answer),
    ):
        main_module._run_hcat_cmd(cmd, attack_name="Dictionary", coverage=spec)
    return launched


def _spec(env, **kw):
    kw.setdefault("wordlists", (env["wordlist"],))
    kw.setdefault("rule_files", (env["rules"],))
    return ac.CoverageSpec(hash_file=env["hashes"], **kw)


# --- recording -------------------------------------------------------------


def test_clean_run_records_coverage(main_module, store, env):
    cmd = ["hashcat", env["hashes"], env["wordlist"], "-r", env["rules"]]
    assert _run(main_module, cmd, _spec(env))
    plan = ac.plan_run(_spec(env), store.covered, store=store)
    assert plan.skip is True, "a completed run should leave the attack fully covered"


def test_interrupted_run_records_nothing(main_module, store, env):
    cmd = ["hashcat", env["hashes"], env["wordlist"], "-r", env["rules"]]
    _run(main_module, cmd, _spec(env), raise_interrupt=True)
    plan = ac.plan_run(_spec(env), store.covered, store=store)
    assert plan.covered_count == 0, "ctrl-C must not claim ground that was not covered"


def test_hashcat_error_records_nothing(main_module, store, env):
    cmd = ["hashcat", env["hashes"], env["wordlist"], "-r", env["rules"]]
    _run(main_module, cmd, _spec(env), returncode=255)
    plan = ac.plan_run(_spec(env), store.covered, store=store)
    assert plan.covered_count == 0


def test_exhausted_and_cracked_both_count_as_covered(main_module, store, env):
    for code in (0, 1):
        store.forget_target(ac.target_id(env["hashes"]))
        cmd = ["hashcat", env["hashes"], env["wordlist"], "-r", env["rules"]]
        _run(main_module, cmd, _spec(env), returncode=code)
        plan = ac.plan_run(_spec(env), store.covered, store=store)
        assert plan.skip is True, f"exit {code} should count as covered"


# --- filtering -------------------------------------------------------------


def test_partial_overlap_rewrites_the_rule_file(main_module, store, env):
    partial = env["tmp"] / "partial.rule"
    partial.write_text("c\n$1\n")
    cmd = ["hashcat", env["hashes"], env["wordlist"], "-r", str(partial)]
    _run(main_module, cmd, _spec(env, rule_files=(str(partial),)))

    seen = []
    cmd = ["hashcat", env["hashes"], env["wordlist"], "-r", env["rules"]]
    launched = _run(main_module, cmd, _spec(env), seen_rules=seen)

    rule_arg = launched[0][launched[0].index("-r") + 1]
    assert rule_arg != env["rules"], "the original rule file should be replaced"
    assert seen == [["u"]], "only the untried rule should reach hashcat"


def test_the_filtered_temp_file_is_cleaned_up(main_module, store, env):
    partial = env["tmp"] / "partial.rule"
    partial.write_text("c\n$1\n")
    cmd = ["hashcat", env["hashes"], env["wordlist"], "-r", str(partial)]
    _run(main_module, cmd, _spec(env, rule_files=(str(partial),)))

    cmd = ["hashcat", env["hashes"], env["wordlist"], "-r", env["rules"]]
    launched = _run(main_module, cmd, _spec(env))
    assert not os.path.exists(launched[0][launched[0].index("-r") + 1])


def test_full_overlap_never_launches_hashcat(main_module, store, env):
    cmd = ["hashcat", env["hashes"], env["wordlist"], "-r", env["rules"]]
    _run(main_module, cmd, _spec(env))
    launched = _run(main_module, cmd, _spec(env))
    assert launched == [], "a complete repeat should skip the hashcat launch"


def test_declining_the_prompt_runs_everything(main_module, store, env):
    partial = env["tmp"] / "partial.rule"
    partial.write_text("c\n$1\n")
    cmd = ["hashcat", env["hashes"], env["wordlist"], "-r", str(partial)]
    _run(main_module, cmd, _spec(env, rule_files=(str(partial),)))

    cmd = ["hashcat", env["hashes"], env["wordlist"], "-r", env["rules"]]
    launched = _run(main_module, cmd, _spec(env), answer="n")
    assert launched[0][launched[0].index("-r") + 1] == env["rules"]


def test_no_prompt_when_there_is_no_overlap(main_module, store, env):
    """A fresh engagement must not be interrupted by a question."""
    cmd = ["hashcat", env["hashes"], env["wordlist"], "-r", env["rules"]]

    def explode(*args, **kwargs):
        raise AssertionError("prompted with no overlap to report")

    with (
        patch.object(main_module.subprocess, "Popen", lambda cmd, **kw: FakePopen(cmd)),
        patch.object(main_module, "_coverage_enabled", True),
        patch("builtins.input", explode),
    ):
        main_module._run_hcat_cmd(cmd, attack_name="Dictionary", coverage=_spec(env))


# --- opting out ------------------------------------------------------------


def test_no_coverage_flag_neither_reads_nor_writes(main_module, store, env):
    cmd = ["hashcat", env["hashes"], env["wordlist"], "-r", env["rules"]]
    launched = []

    with (
        patch.object(
            main_module.subprocess,
            "Popen",
            lambda cmd, **kw: launched.append(list(cmd)) or FakePopen(cmd),
        ),
        patch.object(main_module, "_coverage_enabled", False),
    ):
        main_module._run_hcat_cmd(cmd, attack_name="Dictionary", coverage=_spec(env))
        main_module._run_hcat_cmd(cmd, attack_name="Dictionary", coverage=_spec(env))

    assert len(launched) == 2, "--no-coverage must not skip the second run"
    plan = ac.plan_run(_spec(env), store.covered, store=store)
    assert plan.covered_count == 0, "--no-coverage must not write to the store"


def test_a_run_with_no_spec_is_untouched(main_module, store, env):
    cmd = ["hashcat", env["hashes"], env["wordlist"]]
    launched = []
    with (
        patch.object(
            main_module.subprocess,
            "Popen",
            lambda cmd, **kw: launched.append(list(cmd)) or FakePopen(cmd),
        ),
        patch.object(main_module, "_coverage_enabled", True),
    ):
        main_module._run_hcat_cmd(cmd, attack_name="PRINCE")
    assert launched == [cmd]


# --- attack functions pass a spec -----------------------------------------


def test_eligible_attacks_pass_a_coverage_spec(main_module):
    """The five wired attack functions; dynamic generators stay unwired."""
    source = inspect.getsource(main_module)
    for func in (
        "hcatDictionary",
        "hcatTopMask",
        "hcatAdHocMask",
        "hcatCorporateMasks",
        "hcatGoodMeasure",
    ):
        body = source.split(f"def {func}(", 1)[1].split("\ndef ", 1)[0]
        assert "coverage=_coverage.CoverageSpec" in body, f"{func} passes no spec"


def test_dynamic_generators_do_not_pass_a_spec(main_module):
    """PRINCE/PCFG/OMEN/Markov/LLM enumerate nothing fixed, so filtering them
    would silently drop candidates the store cannot account for."""
    source = inspect.getsource(main_module)
    for func in ("hcatPrince", "hcatOllama", "hcatMarkovBruteForce"):
        if f"def {func}(" not in source:
            continue
        body = source.split(f"def {func}(", 1)[1].split("\ndef ", 1)[0]
        assert "coverage=" not in body, f"{func} must not be coverage-filtered"
