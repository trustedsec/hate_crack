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


def test_shared_decision_cache_prompts_only_once(main_module, store, env):
    """Two rule files run back to back against the same wordlist -- as Quick
    Crack and Loopback do via a shared coverage_decision dict -- must ask
    the 'skip already-covered ground?' question once, and reuse that answer
    to filter each run's own overlap without asking again."""
    cmd = ["hashcat", env["hashes"], env["wordlist"], "-r", env["rules"]]
    _run(main_module, cmd, _spec(env))  # fully covers "c", "$1", "u"

    partial_a = env["tmp"] / "partial_a.rule"
    partial_a.write_text("c\n$1\nq\n")  # 2 of 3 already covered
    partial_b = env["tmp"] / "partial_b.rule"
    partial_b.write_text("c\nz\n")  # 1 of 2 already covered

    prompts = []

    def counting_input(prompt=""):
        prompts.append(prompt)
        return "y"

    seen_rules = []

    def fake_popen(cmd, **kwargs):
        if "-r" in cmd:
            seen_rules.append(ac.read_entries(cmd[cmd.index("-r") + 1]))
        return FakePopen(cmd)

    decision_cache: dict = {}
    with (
        patch.object(main_module.subprocess, "Popen", fake_popen),
        patch.object(main_module, "_coverage_enabled", True),
        patch.object(main_module, "non_interactive", False),
        patch("builtins.input", counting_input),
    ):
        main_module._run_hcat_cmd(
            ["hashcat", env["hashes"], env["wordlist"], "-r", str(partial_a)],
            attack_name="Quick Crack",
            coverage=_spec(env, rule_files=(str(partial_a),)),
            coverage_decision=decision_cache,
        )
        main_module._run_hcat_cmd(
            ["hashcat", env["hashes"], env["wordlist"], "-r", str(partial_b)],
            attack_name="Quick Crack",
            coverage=_spec(env, rule_files=(str(partial_b),)),
            coverage_decision=decision_cache,
        )

    assert len(prompts) == 1, "the second run must reuse the first's answer"
    assert seen_rules == [["q"], ["z"]], "each run's own overlap must still be filtered"


def test_shared_decision_cache_honors_a_declined_prompt(main_module, store, env):
    """Declining the one shared prompt must make every run in the batch run
    unfiltered, not just the first."""
    cmd = ["hashcat", env["hashes"], env["wordlist"], "-r", env["rules"]]
    _run(main_module, cmd, _spec(env))  # fully covers "c", "$1", "u"

    partial_a = env["tmp"] / "partial_a.rule"
    partial_a.write_text("c\n$1\nq\n")
    partial_b = env["tmp"] / "partial_b.rule"
    partial_b.write_text("c\nz\n")

    launched = []

    def fake_popen(cmd, **kwargs):
        launched.append(list(cmd))
        return FakePopen(cmd)

    decision_cache: dict = {}
    with (
        patch.object(main_module.subprocess, "Popen", fake_popen),
        patch.object(main_module, "_coverage_enabled", True),
        patch.object(main_module, "non_interactive", False),
        patch("builtins.input", lambda *a: "n"),
    ):
        main_module._run_hcat_cmd(
            ["hashcat", env["hashes"], env["wordlist"], "-r", str(partial_a)],
            attack_name="Quick Crack",
            coverage=_spec(env, rule_files=(str(partial_a),)),
            coverage_decision=decision_cache,
        )
        main_module._run_hcat_cmd(
            ["hashcat", env["hashes"], env["wordlist"], "-r", str(partial_b)],
            attack_name="Quick Crack",
            coverage=_spec(env, rule_files=(str(partial_b),)),
            coverage_decision=decision_cache,
        )

    assert launched[0][launched[0].index("-r") + 1] == str(partial_a)
    assert launched[1][launched[1].index("-r") + 1] == str(partial_b)


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
    """The wired attack functions; dynamic generators stay unwired."""
    source = inspect.getsource(main_module)
    for func in (
        "hcatDictionary",
        "hcatQuickDictionary",
        "hcatTopMask",
        "hcatAdHocMask",
        "hcatCorporateMasks",
        "hcatGoodMeasure",
    ):
        body = source.split(f"def {func}(", 1)[1].split("\ndef ", 1)[0]
        assert "coverage=" in body, f"{func} passes no coverage spec"


def test_dynamic_generators_do_not_pass_a_spec(main_module):
    """PRINCE/PCFG/OMEN/Markov/LLM enumerate nothing fixed, so filtering them
    would silently drop candidates the store cannot account for."""
    source = inspect.getsource(main_module)
    for func in ("hcatPrince", "hcatOllama", "hcatMarkovBruteForce"):
        if f"def {func}(" not in source:
            continue
        body = source.split(f"def {func}(", 1)[1].split("\ndef ", 1)[0]
        assert "coverage=" not in body, f"{func} must not be coverage-filtered"


# --- argument rewriting must not hit look-alike paths ----------------------


def test_dropping_a_wordlist_leaves_a_matching_output_path_alone(main_module):
    """A covered wordlist can share its name with an -o value."""
    cmd = ["hashcat", "h.txt", "-o", "wl.txt", "wl.txt", "keep.txt"]
    out = main_module._drop_wordlist_args(cmd, {"wl.txt"}, "h.txt")
    assert out == ["hashcat", "h.txt", "-o", "wl.txt", "keep.txt"], (
        "only the bare positional wordlist should be dropped"
    )


def test_a_wordlist_that_is_also_the_hash_file_is_never_dropped(main_module):
    """Positionally indistinguishable, so the safe answer is to keep it: a
    wrongly dropped wordlist skips untried candidates, a kept one wastes time."""
    cmd = ["hashcat", "same.txt", "same.txt"]
    assert main_module._drop_wordlist_args(cmd, {"same.txt"}, "same.txt") == cmd


def test_dropping_a_wordlist_never_removes_a_flag_value(main_module):
    cmd = ["hashcat", "--session", "wl.txt", "wl.txt"]
    assert main_module._drop_wordlist_args(cmd, {"wl.txt"}, "h.txt") == [
        "hashcat",
        "--session",
        "wl.txt",
    ]


def test_rule_replacement_is_scoped_to_the_r_flag(main_module):
    cmd = ["hashcat", "r.rule", "-o", "r.rule", "-r", "r.rule"]
    out = main_module._replace_rule_arg(cmd, "r.rule", "/tmp/new.rule", "rule")
    assert out == ["hashcat", "r.rule", "-o", "r.rule", "-r", "/tmp/new.rule"]


def test_mask_replacement_skips_flag_values(main_module):
    cmd = ["hashcat", "-o", "m.hcmask", "m.hcmask"]
    out = main_module._replace_rule_arg(cmd, "m.hcmask", "/tmp/new.hcmask", "mask")
    assert out == ["hashcat", "-o", "m.hcmask", "/tmp/new.hcmask"]


# --- the prompt ------------------------------------------------------------


def test_prompt_pluralises_both_counts_independently(main_module, capsys):
    """The covered count and the remaining count pluralise separately -- one
    was previously driven by the other, producing "the 1 new rules"."""
    prompts = []
    plan = ac.RunPlan(kind="rule", covered_count=3, total_count=4, target="t")
    with (
        patch.object(main_module, "non_interactive", False),
        patch("builtins.input", lambda prompt="": prompts.append(prompt) or "y"),
    ):
        main_module._prompt_coverage_filter(plan, "Dictionary")
    assert "3 of 4 rules" in capsys.readouterr().out
    assert "only the 1 rule?" in prompts[0], prompts[0]


def test_prompt_pluralises_a_single_covered_entry(main_module, capsys):
    prompts = []
    plan = ac.RunPlan(kind="mask", covered_count=1, total_count=3, target="t")
    with (
        patch.object(main_module, "non_interactive", False),
        patch("builtins.input", lambda prompt="": prompts.append(prompt) or "y"),
    ):
        main_module._prompt_coverage_filter(plan, "Top Mask")
    assert "1 of 3 mask " in capsys.readouterr().out
    assert "only the 2 masks?" in prompts[0], prompts[0]


def test_prompt_names_the_wordlists_the_overlap_was_measured_against(
    main_module, capsys
):
    """ "against this hash file" alone reads as a claim about the rule file the
    operator just picked, which is what made a correct full-overlap report look
    like a bug."""
    plan = ac.RunPlan(kind="rule", covered_count=7337, total_count=7337, target="t")
    spec = ac.CoverageSpec(
        hash_file="ntlm.txt",
        wordlists=("/Passwords/rockyou.txt",),
        rule_files=("top50.rule",),
    )
    with (
        patch.object(main_module, "non_interactive", False),
        patch("builtins.input", lambda prompt="": "y"),
    ):
        main_module._prompt_coverage_filter(plan, "Quick Crack", spec)
    out = capsys.readouterr().out
    assert "with rockyou.txt" in out
    assert "tracked individually" in out


def test_prompt_scope_omits_wordlists_for_a_wordlist_diff(main_module, capsys):
    """The wordlists *are* the entries being diffed, so naming them again would
    say "3 of 3 wordlists ... against this hash file with <those 3 wordlists>"."""
    plan = ac.RunPlan(kind="wordlist", covered_count=1, total_count=2, target="t")
    spec = ac.CoverageSpec(hash_file="ntlm.txt", wordlists=("/Passwords/rockyou.txt",))
    with (
        patch.object(main_module, "non_interactive", False),
        patch("builtins.input", lambda prompt="": "y"),
    ):
        main_module._prompt_coverage_filter(plan, "Quick Crack", spec)
    out = capsys.readouterr().out
    assert "against this hash file." in out
    assert "rockyou" not in out


def test_prompt_scope_truncates_a_long_wordlist_directory(main_module, capsys):
    plan = ac.RunPlan(kind="rule", covered_count=1, total_count=2, target="t")
    spec = ac.CoverageSpec(
        hash_file="ntlm.txt",
        wordlists=tuple(f"/w/list{i}.txt" for i in range(6)),
        rule_files=("best64.rule",),
    )
    with (
        patch.object(main_module, "non_interactive", False),
        patch("builtins.input", lambda prompt="": "y"),
    ):
        main_module._prompt_coverage_filter(plan, "Dictionary", spec)
    out = capsys.readouterr().out
    assert "list0.txt, list1.txt, list2.txt, +3 more" in out


def test_closed_stdin_takes_the_default_instead_of_crashing(main_module, capsys):
    """A piped or cron-driven run that never set non_interactive."""

    def eof(*args, **kwargs):
        raise EOFError

    plan = ac.RunPlan(kind="rule", covered_count=1, total_count=2, target="t")
    with (
        patch.object(main_module, "non_interactive", False),
        patch("builtins.input", eof),
    ):
        assert main_module._prompt_coverage_filter(plan, "Dictionary") is True
    assert "No input available" in capsys.readouterr().out


# --- hcatQuickDictionary ---------------------------------------------------


def test_quick_dictionary_extracts_rule_files_from_the_chain(main_module):
    spec = main_module._quick_dictionary_coverage(
        "h.txt", "-r a.rule -r b.rule", "wl.txt", False
    )
    assert spec.rule_files == ("a.rule", "b.rule")
    assert spec.wordlists == ("wl.txt",)


def test_quick_dictionary_handles_a_rule_less_chain(main_module):
    spec = main_module._quick_dictionary_coverage(
        "h.txt", "", ["a.txt", "b.txt"], False
    )
    assert spec.rule_files == ()
    assert spec.wordlists == ("a.txt", "b.txt")


def test_quick_dictionary_ignores_a_trailing_dash_r(main_module):
    """A malformed chain must not index past the end."""
    spec = main_module._quick_dictionary_coverage("h.txt", "-r", "wl.txt", False)
    assert spec.rule_files == ()


# --- exit codes ------------------------------------------------------------


def test_exit_zero_does_not_record_coverage(main_module, store, env):
    """hashcat exits 0 when all hashes cracked -- without finishing the
    keyspace, and possibly having enumerated nothing at all ("All hashes found
    as potfile entries"). Recording that would skip untried candidates later."""
    cmd = ["hashcat", env["hashes"], env["wordlist"], "-r", env["rules"]]
    _run(main_module, cmd, _spec(env), returncode=0)
    plan = ac.plan_run(_spec(env), store.covered, store=store)
    assert plan.covered_count == 0


def test_only_exhausted_records_coverage(main_module, store, env):
    cmd = ["hashcat", env["hashes"], env["wordlist"], "-r", env["rules"]]
    _run(main_module, cmd, _spec(env), returncode=1)
    plan = ac.plan_run(_spec(env), store.covered, store=store)
    assert plan.skip is True


# --- ad-hoc mask spec ------------------------------------------------------


def test_a_mask_file_is_tracked_per_line_not_by_path(main_module, tmp_path):
    """Menu option 2 passes a .hcmask path. Tracked as a literal it would be
    keyed on the path, so appending masks and re-running would look like a
    repeat and be skipped."""
    masks = tmp_path / "corp.hcmask"
    masks.write_text("?u?l?l?l?d?d\n?d?d?d?d\n")
    spec = main_module._adhoc_mask_coverage("h.txt", str(masks), "", False, "", "")
    assert spec.mask_files == (str(masks),)
    assert spec.masks == ()


def test_a_literal_mask_is_tracked_as_a_mask(main_module):
    spec = main_module._adhoc_mask_coverage("h.txt", "?a?a?a?a", "", False, "", "")
    assert spec.masks == ("?a?a?a?a",)
    assert spec.mask_files == ()


def test_increment_with_blank_bounds_differs_from_no_increment(main_module):
    """Blank bounds are the documented way to increment over the full keyspace,
    so this is the default incremental answer, not a corner case."""
    without = main_module._adhoc_mask_coverage(
        "h.txt", "?1?1?1", "-1 ?l?d", False, "", ""
    )
    with_inc = main_module._adhoc_mask_coverage(
        "h.txt", "?1?1?1", "-1 ?l?d", True, "", ""
    )
    assert without.variant != with_inc.variant


# --- run history for unfiltered attacks ------------------------------------


def test_an_unfiltered_attack_is_logged_as_having_run(main_module, store, env):
    """Dynamic generators are never filtered, but the issue asks that they be
    logged so an operator can ask "did I already run PRINCE on this?"."""
    with (
        patch.object(main_module.subprocess, "Popen", lambda cmd, **kw: FakePopen(cmd)),
        patch.object(main_module, "_coverage_enabled", True),
    ):
        main_module._run_hcat_cmd(
            ["hashcat", env["hashes"]], attack_name="PRINCE", hash_file=env["hashes"]
        )
    assert [row[0] for row in store.history(ac.target_id(env["hashes"]))] == ["PRINCE"]


def test_an_interrupted_unfiltered_attack_is_not_logged(main_module, store, env):
    with (
        patch.object(
            main_module.subprocess,
            "Popen",
            lambda cmd, **kw: FakePopen(cmd, raise_interrupt=True),
        ),
        patch.object(main_module, "_coverage_enabled", True),
    ):
        main_module._run_hcat_cmd(
            ["hashcat", env["hashes"]], attack_name="PRINCE", hash_file=env["hashes"]
        )
    assert store.history(ac.target_id(env["hashes"])) == []


def test_no_coverage_flag_logs_no_history(main_module, store, env):
    with (
        patch.object(main_module.subprocess, "Popen", lambda cmd, **kw: FakePopen(cmd)),
        patch.object(main_module, "_coverage_enabled", False),
    ):
        main_module._run_hcat_cmd(
            ["hashcat", env["hashes"]], attack_name="PRINCE", hash_file=env["hashes"]
        )
    assert store.history(ac.target_id(env["hashes"])) == []


# --- a full repeat is still the operator's call ----------------------------


def test_declining_a_full_skip_runs_the_attack(main_module, store, env):
    """Without this, re-running a covered attack meant restarting the tool."""
    cmd = ["hashcat", env["hashes"], env["wordlist"], "-r", env["rules"]]
    _run(main_module, cmd, _spec(env))
    launched = _run(main_module, cmd, _spec(env), answer="n")
    assert len(launched) == 1, "declining the skip must run the attack"


def test_a_full_skip_defaults_to_skipping(main_module, store, env):
    cmd = ["hashcat", env["hashes"], env["wordlist"], "-r", env["rules"]]
    _run(main_module, cmd, _spec(env))
    assert _run(main_module, cmd, _spec(env), answer="") == []


def test_a_scripted_full_repeat_skips_without_prompting(main_module, store, env):
    cmd = ["hashcat", env["hashes"], env["wordlist"], "-r", env["rules"]]
    _run(main_module, cmd, _spec(env))
    launched = []

    def explode(*a, **kw):
        raise AssertionError("a scripted run must never prompt")

    with (
        patch.object(
            main_module.subprocess,
            "Popen",
            lambda cmd, **kw: launched.append(list(cmd)) or FakePopen(cmd),
        ),
        patch.object(main_module, "_coverage_enabled", True),
        patch.object(main_module, "non_interactive", True),
        patch("builtins.input", explode),
    ):
        main_module._run_hcat_cmd(
            cmd, attack_name="Dictionary", hash_file=env["hashes"], coverage=_spec(env)
        )
    assert launched == []


# --- loopback records but is never filtered --------------------------------


def test_loopback_builds_a_record_only_spec(main_module):
    spec = main_module._quick_dictionary_coverage("h.txt", "-r a.rule", "wl.txt", True)
    assert spec is not None, "loopback should record, not opt out entirely"
    assert spec.record_only is True
    assert spec.rule_files == ("a.rule",)


def test_non_loopback_spec_is_filterable(main_module):
    spec = main_module._quick_dictionary_coverage("h.txt", "-r a.rule", "wl.txt", False)
    assert spec.record_only is False


def _quick(main_module, env, launched, loopback):
    with (
        patch.object(
            main_module.subprocess,
            "Popen",
            lambda cmd, **kw: launched.append(list(cmd)) or FakePopen(cmd),
        ),
        patch.object(main_module, "_coverage_enabled", True),
        patch.object(main_module, "non_interactive", False),
        patch.object(main_module, "hcatBin", "hashcat"),
        patch.object(main_module, "hcatTuning", ""),
        patch.object(main_module, "hcatPotfilePath", ""),
        patch.object(main_module, "generate_session_id", lambda *_: "s"),
        patch("builtins.input", lambda *a: "y"),
    ):
        main_module.hcatQuickDictionary(
            "1000",
            env["hashes"],
            f"-r {env['rules']}",
            env["wordlist"],
            loopback=loopback,
        )


def test_a_loopback_repeat_still_runs_in_full(main_module, store, env):
    launched = []
    _quick(main_module, env, launched, loopback=True)
    _quick(main_module, env, launched, loopback=True)
    assert len(launched) == 2, "loopback covers new ground each time"


def test_a_loopback_run_covers_a_later_plain_run(main_module, store, env):
    launched = []
    _quick(main_module, env, launched, loopback=True)
    _quick(main_module, env, launched, loopback=False)
    assert len(launched) == 1, "the plain repeat should be skipped as covered"


def test_an_interrupted_loopback_run_records_nothing(main_module, store, env):
    with (
        patch.object(
            main_module.subprocess,
            "Popen",
            lambda cmd, **kw: FakePopen(cmd, raise_interrupt=True),
        ),
        patch.object(main_module, "_coverage_enabled", True),
        patch.object(main_module, "hcatBin", "hashcat"),
        patch.object(main_module, "hcatTuning", ""),
        patch.object(main_module, "hcatPotfilePath", ""),
        patch.object(main_module, "generate_session_id", lambda *_: "s"),
    ):
        main_module.hcatQuickDictionary(
            "1000", env["hashes"], f"-r {env['rules']}", env["wordlist"], loopback=True
        )
    plan = ac.plan_run(_spec(env), store.covered, store=store)
    assert plan.covered_count == 0
