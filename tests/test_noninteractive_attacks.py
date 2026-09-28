"""Non-interactive subcommands for the menu attacks (issue #340).

``tests/test_noninteractive.py`` covers the original four commands (quick,
dict, brute, topmask) and the ``build_rule_chains`` grammar. This file covers
the seventeen added for #340 and the spec table that drives them.
"""

import os
from types import SimpleNamespace

import pytest

from hate_crack import noninteractive as ni


# --------------------------------------------------------------------------
# Spec table contract
# --------------------------------------------------------------------------


def test_attack_commands_is_derived_from_the_spec_table():
    """ATTACK_COMMANDS must not be a hand-maintained tuple that can drift from
    the dispatcher -- main.py keys `non_interactive` off membership in it, so a
    name present in one and absent from the other silently runs an attack with
    the interactive prompts still live."""
    assert ni.ATTACK_COMMANDS == tuple(spec.name for spec in ni.ATTACK_SPECS)


def test_every_spec_has_a_runner_and_unique_name():
    names = [spec.name for spec in ni.ATTACK_SPECS]
    assert len(names) == len(set(names)), "duplicate subcommand name"
    for spec in ni.ATTACK_SPECS:
        assert callable(spec.run), f"{spec.name} has no runner"
        assert spec.help, f"{spec.name} has no help text"


def test_every_spec_registers_a_subparser():
    import argparse

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    ni.add_attack_subparsers(subparsers)
    registered = set(subparsers.choices)
    assert set(ni.ATTACK_COMMANDS) <= registered


def test_issue_340_attacks_are_all_present():
    """The seventeen names #340 asks for, plus the original four."""
    expected = {
        "quick",
        "dict",
        "brute",
        "topmask",
        # no-argument tier
        "fingerprint",
        "combinator",
        "hybrid",
        "pathwell",
        "prince",
        "pcfg",
        "princeling",
        "smartmask",
        "corporate",
        # one-argument tier
        "bandrel",
        "permute",
        "adhocmask",
        "ngram",
        "combipow",
        "spoonman",
        "omen",
        "loopback",
    }
    assert set(ni.ATTACK_COMMANDS) == expected


def test_unknown_command_returns_2():
    """#340 consistency note 2: exit 2 must never be conflated with "ran".
    A caller pointed at an older hate_crack gets 2 on every invocation."""
    ctx = SimpleNamespace()
    assert ni.run_noninteractive(ctx, SimpleNamespace(command="no-such-attack")) == 2


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _spy_ctx(tmp_path, **overrides):
    """A stand-in for the main module recording every hcat* call."""
    calls = []

    def rec(name):
        def _fn(*a, **k):
            calls.append((name, a, k))

        return _fn

    wordlists = tmp_path / "wordlists"
    wordlists.mkdir(exist_ok=True)
    rules = tmp_path / "rules"
    rules.mkdir(exist_ok=True)

    ctx = SimpleNamespace(
        calls=calls,
        hcatHashType="1000",
        hcatHashFile=str(tmp_path / "hashes.txt"),
        rulesDirectory=str(rules),
        hcatWordlists=str(wordlists),
        hcatFingerprintWordlist=[],
        hcatCombinationWordlist=[],
        hcatHybridlist=[],
        resolve_path=lambda p: os.path.abspath(os.path.expanduser(p)) if p else None,
        _prime_coverage_decision=lambda *a, **k: {},
        _omen_model_dir=lambda: str(tmp_path / "omen-model"),
        _omen_model_is_valid=lambda d: True,
        _open_wordlist=lambda p: open(p),
    )
    for name in (
        "hcatFingerprint",
        "hcatCombination",
        "hcatHybrid",
        "hcatPathwellBruteForce",
        "hcatPrince",
        "hcatPCFG",
        "hcatPrinceLing",
        "hcatSmartMask",
        "hcatCorporateMasks",
        "hcatBandrel",
        "hcatPermute",
        "hcatAdHocMask",
        "hcatNgramX",
        "hcatCombipow",
        "hcatSpoonman",
        "hcatOmen",
        "hcatQuickDictionary",
    ):
        setattr(ctx, name, rec(name))
    for k, v in overrides.items():
        setattr(ctx, k, v)
    return ctx


def _parse(argv):
    """Parse through the real subparsers, so defaults are the shipped ones."""
    import argparse

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    ni.add_attack_subparsers(subparsers)
    return parser.parse_args(argv)


def _wordlist(tmp_path, name, lines=("password",)):
    p = tmp_path / name
    p.write_text("\n".join(lines) + "\n")
    return p


# --------------------------------------------------------------------------
# No-argument tier
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command,func",
    [
        ("pathwell", "hcatPathwellBruteForce"),
        ("prince", "hcatPrince"),
        ("pcfg", "hcatPCFG"),
        ("princeling", "hcatPrinceLing"),
    ],
)
def test_bare_attacks_dispatch_with_hashtype_and_hashfile(tmp_path, command, func):
    ctx = _spy_ctx(tmp_path)
    args = _parse([command, ctx.hcatHashFile, "1000"])
    assert ni.run_noninteractive(ctx, args) == 0
    assert ctx.calls == [(func, ("1000", ctx.hcatHashFile), {})]


def test_fingerprint_passes_every_flag_through(tmp_path):
    wl = _wordlist(tmp_path, "frags.txt")
    ctx = _spy_ctx(tmp_path)
    args = _parse(
        [
            "fingerprint",
            ctx.hcatHashFile,
            "1000",
            "--max-expander-len",
            "24",
            "--run-hybrid-on-expanded",
            "--dictionary-wordlist",
            str(wl),
            "--keyspace-limit",
            "1000",
        ]
    )
    assert ni.run_noninteractive(ctx, args) == 0
    name, a, k = ctx.calls[0]
    assert name == "hcatFingerprint"
    assert a == ("1000", ctx.hcatHashFile)
    assert k["max_expander_len"] == 24
    assert k["run_hybrid_on_expanded"] is True
    assert k["dictionary_wordlist"] == os.path.abspath(str(wl))
    assert k["keyspace_limit"] == 1000


def test_fingerprint_defaults_match_the_function_defaults(tmp_path):
    """A bare `fingerprint` must reproduce hcatFingerprint's own defaults --
    None for the wordlist means "fall back to config", which is not the same
    as "" (skip)."""
    ctx = _spy_ctx(tmp_path)
    args = _parse(["fingerprint", ctx.hcatHashFile, "1000"])
    assert ni.run_noninteractive(ctx, args) == 0
    _, _, k = ctx.calls[0]
    assert k["max_expander_len"] == 21
    assert k["run_hybrid_on_expanded"] is False
    assert k["dictionary_wordlist"] is None
    assert k["keyspace_limit"] is None


def test_fingerprint_no_dictionary_wordlist_skips_rather_than_defaulting(tmp_path):
    ctx = _spy_ctx(tmp_path)
    args = _parse(["fingerprint", ctx.hcatHashFile, "1000", "--no-dictionary-wordlist"])
    assert ni.run_noninteractive(ctx, args) == 0
    assert ctx.calls[0][2]["dictionary_wordlist"] == ""


@pytest.mark.parametrize("bad", ["6", "37", "0"])
def test_fingerprint_rejects_out_of_range_expander_length(tmp_path, bad):
    """The interactive prompt enforces 7-36; the scripted path must too,
    rather than handing hashcat a length that silently does nothing."""
    ctx = _spy_ctx(tmp_path)
    args = _parse(["fingerprint", ctx.hcatHashFile, "1000", "--max-expander-len", bad])
    assert ni.run_noninteractive(ctx, args) == 1
    assert ctx.calls == []


def test_fingerprint_rejects_negative_keyspace_limit(tmp_path):
    ctx = _spy_ctx(tmp_path)
    args = _parse(["fingerprint", ctx.hcatHashFile, "1000", "--keyspace-limit", "-1"])
    assert ni.run_noninteractive(ctx, args) == 1
    assert ctx.calls == []


def test_fingerprint_missing_dictionary_wordlist_returns_1(tmp_path):
    ctx = _spy_ctx(tmp_path)
    args = _parse(
        [
            "fingerprint",
            ctx.hcatHashFile,
            "1000",
            "--dictionary-wordlist",
            str(tmp_path / "nope.txt"),
        ]
    )
    assert ni.run_noninteractive(ctx, args) == 1
    assert ctx.calls == []


def test_smartmask_passes_keyspace_limit(tmp_path):
    ctx = _spy_ctx(tmp_path)
    args = _parse(["smartmask", ctx.hcatHashFile, "1000", "--keyspace-limit", "500"])
    assert ni.run_noninteractive(ctx, args) == 0
    assert ctx.calls[0] == (
        "hcatSmartMask",
        ("1000", ctx.hcatHashFile),
        {"keyspace_limit": 500},
    )


def test_smartmask_defaults_to_none(tmp_path):
    ctx = _spy_ctx(tmp_path)
    args = _parse(["smartmask", ctx.hcatHashFile, "1000"])
    assert ni.run_noninteractive(ctx, args) == 0
    assert ctx.calls[0][2]["keyspace_limit"] is None


def test_corporate_omits_unset_lengths_so_function_defaults_apply(tmp_path):
    ctx = _spy_ctx(tmp_path)
    args = _parse(["corporate", ctx.hcatHashFile, "1000"])
    assert ni.run_noninteractive(ctx, args) == 0
    assert ctx.calls[0] == ("hcatCorporateMasks", ("1000", ctx.hcatHashFile), {})


def test_corporate_passes_explicit_lengths(tmp_path):
    ctx = _spy_ctx(tmp_path)
    args = _parse(["corporate", ctx.hcatHashFile, "1000", "--min", "9", "--max", "12"])
    assert ni.run_noninteractive(ctx, args) == 0
    assert ctx.calls[0][2] == {"minLen": 9, "maxLen": 12}


@pytest.mark.parametrize(
    "command,func,config_attr",
    [
        ("combinator", "hcatCombination", "hcatCombinationWordlist"),
        ("hybrid", "hcatHybrid", "hcatHybridlist"),
    ],
)
def test_wordlist_attacks_default_to_config(tmp_path, command, func, config_attr):
    """No --wordlist means None, which is the sentinel each function uses to
    fall back to its configured list."""
    ctx = _spy_ctx(tmp_path)
    args = _parse([command, ctx.hcatHashFile, "1000"])
    assert ni.run_noninteractive(ctx, args) == 0
    assert ctx.calls[0] == (func, ("1000", ctx.hcatHashFile), {"wordlists": None})


def test_combinator_accepts_multiple_wordlists(tmp_path):
    a = _wordlist(tmp_path, "a.txt")
    b = _wordlist(tmp_path, "b.txt")
    ctx = _spy_ctx(tmp_path)
    args = _parse(
        ["combinator", ctx.hcatHashFile, "1000", "--wordlist", str(a), str(b)]
    )
    assert ni.run_noninteractive(ctx, args) == 0
    assert ctx.calls[0][2]["wordlists"] == [
        os.path.abspath(str(a)),
        os.path.abspath(str(b)),
    ]


def test_combinator_rejects_a_single_wordlist(tmp_path):
    """hcatCombination needs at least two; one would abort inside the attack
    after the run had already been reported as started."""
    a = _wordlist(tmp_path, "a.txt")
    ctx = _spy_ctx(tmp_path)
    args = _parse(["combinator", ctx.hcatHashFile, "1000", "--wordlist", str(a)])
    assert ni.run_noninteractive(ctx, args) == 1
    assert ctx.calls == []


def test_hybrid_accepts_a_single_wordlist(tmp_path):
    a = _wordlist(tmp_path, "a.txt")
    ctx = _spy_ctx(tmp_path)
    args = _parse(["hybrid", ctx.hcatHashFile, "1000", "--wordlist", str(a)])
    assert ni.run_noninteractive(ctx, args) == 0
    assert ctx.calls[0][2]["wordlists"] == [os.path.abspath(str(a))]


def test_wordlist_attacks_reject_a_missing_file(tmp_path):
    ctx = _spy_ctx(tmp_path)
    args = _parse(
        [
            "combinator",
            ctx.hcatHashFile,
            "1000",
            "--wordlist",
            str(tmp_path / "gone.txt"),
            str(tmp_path / "also-gone.txt"),
        ]
    )
    assert ni.run_noninteractive(ctx, args) == 1
    assert ctx.calls == []


# --------------------------------------------------------------------------
# One-argument tier
# --------------------------------------------------------------------------


def test_bandrel_passes_company_without_prompting(tmp_path):
    ctx = _spy_ctx(tmp_path)
    args = _parse(["bandrel", ctx.hcatHashFile, "1000", "--company", "Acme,Acme Corp"])
    assert ni.run_noninteractive(ctx, args) == 0
    assert ctx.calls[0] == (
        "hcatBandrel",
        ("1000", ctx.hcatHashFile),
        {"company_name": "Acme,Acme Corp"},
    )


def test_bandrel_requires_company(tmp_path):
    with pytest.raises(SystemExit):
        _parse(["bandrel", str(tmp_path / "h.txt"), "1000"])


def test_bandrel_rejects_a_blank_company(tmp_path):
    """The interactive loop refuses an empty answer; --company "" must not
    slip past it into a baseword list built from nothing."""
    ctx = _spy_ctx(tmp_path)
    args = _parse(["bandrel", ctx.hcatHashFile, "1000", "--company", "   "])
    assert ni.run_noninteractive(ctx, args) == 1
    assert ctx.calls == []


def test_permute_dispatches_with_wordlist(tmp_path):
    wl = _wordlist(tmp_path, "names.txt")
    ctx = _spy_ctx(tmp_path)
    args = _parse(["permute", ctx.hcatHashFile, "1000", "--wordlist", str(wl)])
    assert ni.run_noninteractive(ctx, args) == 0
    assert ctx.calls[0] == (
        "hcatPermute",
        ("1000", ctx.hcatHashFile, os.path.abspath(str(wl))),
        {},
    )


def test_permute_missing_wordlist_returns_1(tmp_path):
    ctx = _spy_ctx(tmp_path)
    args = _parse(
        ["permute", ctx.hcatHashFile, "1000", "--wordlist", str(tmp_path / "no.txt")]
    )
    assert ni.run_noninteractive(ctx, args) == 1
    assert ctx.calls == []


def test_adhocmask_dispatches_a_literal_mask(tmp_path):
    ctx = _spy_ctx(tmp_path)
    args = _parse(["adhocmask", ctx.hcatHashFile, "1000", "--mask", "?u?l?l?d?d"])
    assert ni.run_noninteractive(ctx, args) == 0
    name, a, k = ctx.calls[0]
    assert name == "hcatAdHocMask"
    assert a == ("1000", ctx.hcatHashFile, "?u?l?l?d?d")
    assert k["increment"] is False


def test_adhocmask_increment_flags_enable_increment(tmp_path):
    ctx = _spy_ctx(tmp_path)
    args = _parse(
        [
            "adhocmask",
            ctx.hcatHashFile,
            "1000",
            "--mask",
            "?a?a?a?a",
            "--increment-min",
            "4",
            "--increment-max",
            "8",
        ]
    )
    assert ni.run_noninteractive(ctx, args) == 0
    k = ctx.calls[0][2]
    assert k["increment"] is True
    assert k["increment_min"] == "4"
    assert k["increment_max"] == "8"


def test_adhocmask_rejects_inverted_increment_range(tmp_path):
    ctx = _spy_ctx(tmp_path)
    args = _parse(
        [
            "adhocmask",
            ctx.hcatHashFile,
            "1000",
            "--mask",
            "?a?a",
            "--increment-min",
            "9",
            "--increment-max",
            "3",
        ]
    )
    assert ni.run_noninteractive(ctx, args) == 1
    assert ctx.calls == []


def test_adhocmask_accepts_an_hcmask_file(tmp_path):
    maskfile = tmp_path / "corp.hcmask"
    maskfile.write_text("?u?l?l?l?d?d?d\n")
    ctx = _spy_ctx(tmp_path)
    args = _parse(["adhocmask", ctx.hcatHashFile, "1000", "--mask", str(maskfile)])
    assert ni.run_noninteractive(ctx, args) == 0
    assert ctx.calls[0][1][2] == str(maskfile)


def test_ngram_dispatches_with_corpus_and_group_size(tmp_path):
    corpus = _wordlist(tmp_path, "corpus.txt")
    ctx = _spy_ctx(tmp_path)
    args = _parse(
        [
            "ngram",
            ctx.hcatHashFile,
            "1000",
            "--corpus",
            str(corpus),
            "--group-size",
            "4",
        ]
    )
    assert ni.run_noninteractive(ctx, args) == 0
    assert ctx.calls[0] == (
        "hcatNgramX",
        ("1000", ctx.hcatHashFile, os.path.abspath(str(corpus))),
        {"group_size": 4},
    )


def test_ngram_group_size_defaults_to_3(tmp_path):
    corpus = _wordlist(tmp_path, "corpus.txt")
    ctx = _spy_ctx(tmp_path)
    args = _parse(["ngram", ctx.hcatHashFile, "1000", "--corpus", str(corpus)])
    assert ni.run_noninteractive(ctx, args) == 0
    assert ctx.calls[0][2]["group_size"] == 3


def test_combipow_dispatches_with_spaces_by_default(tmp_path):
    wl = _wordlist(tmp_path, "words.txt", ["alpha", "beta", "gamma"])
    ctx = _spy_ctx(tmp_path)
    args = _parse(["combipow", ctx.hcatHashFile, "1000", "--wordlist", str(wl)])
    assert ni.run_noninteractive(ctx, args) == 0
    assert ctx.calls[0][1][3] is True


def test_combipow_no_spaces_flag(tmp_path):
    wl = _wordlist(tmp_path, "words.txt", ["alpha", "beta"])
    ctx = _spy_ctx(tmp_path)
    args = _parse(
        ["combipow", ctx.hcatHashFile, "1000", "--wordlist", str(wl), "--no-spaces"]
    )
    assert ni.run_noninteractive(ctx, args) == 0
    assert ctx.calls[0][1][3] is False


def test_combipow_rejects_an_oversized_wordlist(tmp_path):
    """combipow generates 2^n-1 combinations; the interactive path refuses
    over 63 lines and the scripted path must too rather than launching a run
    that cannot finish."""
    wl = _wordlist(tmp_path, "big.txt", [f"w{i}" for i in range(64)])
    ctx = _spy_ctx(tmp_path)
    args = _parse(["combipow", ctx.hcatHashFile, "1000", "--wordlist", str(wl)])
    assert ni.run_noninteractive(ctx, args) == 1
    assert ctx.calls == []


def test_combipow_accepts_exactly_63_lines(tmp_path):
    wl = _wordlist(tmp_path, "edge.txt", [f"w{i}" for i in range(63)])
    ctx = _spy_ctx(tmp_path)
    args = _parse(["combipow", ctx.hcatHashFile, "1000", "--wordlist", str(wl)])
    assert ni.run_noninteractive(ctx, args) == 0


def test_spoonman_dispatches_with_corpus(tmp_path):
    corpus = _wordlist(tmp_path, "cracked.txt")
    ctx = _spy_ctx(tmp_path)
    args = _parse(["spoonman", ctx.hcatHashFile, "1000", "--corpus", str(corpus)])
    assert ni.run_noninteractive(ctx, args) == 0
    name, a, k = ctx.calls[0]
    assert name == "hcatSpoonman"
    assert a == ("1000", ctx.hcatHashFile, os.path.abspath(str(corpus)))
    assert k == {"coverage": None, "baseword_cap": None}


def test_spoonman_passes_rule_coverage_and_baseword_cap(tmp_path):
    corpus = _wordlist(tmp_path, "cracked.txt")
    ctx = _spy_ctx(tmp_path)
    args = _parse(
        [
            "spoonman",
            ctx.hcatHashFile,
            "1000",
            "--corpus",
            str(corpus),
            "--rule-coverage",
            "95",
            "--baseword-cap",
            "5000",
        ]
    )
    assert ni.run_noninteractive(ctx, args) == 0
    assert ctx.calls[0][2] == {"coverage": 95, "baseword_cap": 5000}


def test_omen_dispatches_with_max_candidates(tmp_path):
    ctx = _spy_ctx(tmp_path)
    args = _parse(["omen", ctx.hcatHashFile, "1000", "--max-candidates", "1000000"])
    assert ni.run_noninteractive(ctx, args) == 0
    assert ctx.calls[0] == (
        "hcatOmen",
        ("1000", ctx.hcatHashFile, 1000000),
        {},
    )


def test_omen_without_a_trained_model_returns_1(tmp_path):
    """Training needs a corpus and is a long separate operation, so the
    scripted path refuses rather than silently training."""
    ctx = _spy_ctx(tmp_path, _omen_model_is_valid=lambda d: False)
    args = _parse(["omen", ctx.hcatHashFile, "1000", "--max-candidates", "100"])
    assert ni.run_noninteractive(ctx, args) == 1
    assert ctx.calls == []


def test_omen_rejects_non_positive_max_candidates(tmp_path):
    ctx = _spy_ctx(tmp_path)
    args = _parse(["omen", ctx.hcatHashFile, "1000", "--max-candidates", "0"])
    assert ni.run_noninteractive(ctx, args) == 1
    assert ctx.calls == []


# --------------------------------------------------------------------------
# Loopback -- mirrors attacks.loopback_attack, NOT hcatRecycle
# --------------------------------------------------------------------------


def test_loopback_runs_quick_dictionary_against_an_empty_wordlist(tmp_path):
    """Menu option 11 builds an empty wordlist and re-runs rules against the
    already-cracked plaintexts via hcatQuickDictionary(loopback=True). It does
    not call hcatRecycle, whose count argument is an internal gate used only by
    extensive_crack."""
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "best64.rule").write_text(":\n")
    ctx = _spy_ctx(tmp_path)
    args = _parse(["loopback", ctx.hcatHashFile, "1000", "--rules", "best64.rule"])
    assert ni.run_noninteractive(ctx, args) == 0
    name, a, k = ctx.calls[0]
    assert name == "hcatQuickDictionary"
    assert k["loopback"] is True
    assert k["attack_name"] == "Loopback"
    empty = a[3]
    assert os.path.basename(empty) == "empty.txt"
    assert os.path.isfile(empty)
    assert os.path.getsize(empty) == 0


def test_loopback_runs_each_rule_token_as_its_own_pass(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "best64.rule").write_text(":\n")
    (rules / "d3ad0ne.rule").write_text(":\n")
    ctx = _spy_ctx(tmp_path)
    args = _parse(
        [
            "loopback",
            ctx.hcatHashFile,
            "1000",
            "--rules",
            "best64.rule",
            "d3ad0ne.rule",
        ]
    )
    assert ni.run_noninteractive(ctx, args) == 0
    assert len(ctx.calls) == 2


def test_loopback_shares_one_coverage_decision_across_passes(tmp_path):
    """attacks.loopback_attack primes the decision once so the skip prompt
    reflects the whole batch; the scripted path must pass the same object."""
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "a.rule").write_text(":\n")
    (rules / "b.rule").write_text(":\n")
    sentinel = {"primed": True}
    ctx = _spy_ctx(tmp_path, _prime_coverage_decision=lambda *a, **k: sentinel)
    args = _parse(["loopback", ctx.hcatHashFile, "1000", "--rules", "a.rule", "b.rule"])
    assert ni.run_noninteractive(ctx, args) == 0
    assert [c[2]["coverage_decision"] for c in ctx.calls] == [sentinel, sentinel]


def test_loopback_unknown_rule_returns_1(tmp_path):
    ctx = _spy_ctx(tmp_path)
    args = _parse(["loopback", ctx.hcatHashFile, "1000", "--rules", "ghost.rule"])
    assert ni.run_noninteractive(ctx, args) == 1
    assert ctx.calls == []


# --------------------------------------------------------------------------
# --exit-code-on-skip applies uniformly to the new commands
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["fingerprint"],
        ["prince"],
        ["smartmask"],
        ["corporate"],
        ["permute", "--wordlist", "WL"],
        ["ngram", "--corpus", "WL"],
    ],
)
def test_exit_code_on_skip_applies_to_new_commands(tmp_path, argv):
    """#340 consistency note 1: exit 3 when coverage judged the attack
    redundant and launched nothing."""
    wl = _wordlist(tmp_path, "wl.txt")
    argv = [a if a != "WL" else str(wl) for a in argv]
    ctx = _spy_ctx(tmp_path)
    ctx.reset_run_counters = lambda: None
    ctx.run_counters = lambda: (0, 3)  # nothing launched, three skipped
    args = _parse([argv[0], ctx.hcatHashFile, "1000"] + argv[1:])
    args.exit_code_on_skip = True
    assert ni.run_noninteractive(ctx, args) == ni.SKIPPED_BY_COVERAGE


def test_skip_exit_code_is_not_returned_without_the_flag(tmp_path):
    ctx = _spy_ctx(tmp_path)
    ctx.reset_run_counters = lambda: None
    ctx.run_counters = lambda: (0, 3)
    args = _parse(["prince", ctx.hcatHashFile, "1000"])
    assert ni.run_noninteractive(ctx, args) == 0


def test_skip_exit_code_not_returned_when_something_launched(tmp_path):
    ctx = _spy_ctx(tmp_path)
    ctx.reset_run_counters = lambda: None
    ctx.run_counters = lambda: (1, 2)
    args = _parse(["prince", ctx.hcatHashFile, "1000"])
    args.exit_code_on_skip = True
    assert ni.run_noninteractive(ctx, args) == 0


# --------------------------------------------------------------------------
# End-to-end through main(), which is where `non_interactive` gets set
# --------------------------------------------------------------------------


def _run_main(monkeypatch, argv):
    import sys

    import hate_crack.main as hc_main

    monkeypatch.setattr(sys, "argv", ["hate_crack.py"] + argv)
    # main()'s pre-dispatch potfile-recovery step shells out to the real
    # hashcat binary, which is absent in CI.
    monkeypatch.setattr(hc_main, "_run_hashcat_show", lambda *a, **k: None)
    with pytest.raises(SystemExit) as excinfo:
        hc_main.main()
    return excinfo.value.code


def _ntlm_hashfile(tmp_path):
    hf = tmp_path / "hashes.txt"
    hf.write_text("aad3b435b51404eeaad3b435b51404ee\n")
    return hf


@pytest.mark.parametrize(
    "command,func",
    [
        ("fingerprint", "hcatFingerprint"),
        ("prince", "hcatPrince"),
        ("pcfg", "hcatPCFG"),
        ("pathwell", "hcatPathwellBruteForce"),
        ("smartmask", "hcatSmartMask"),
        ("corporate", "hcatCorporateMasks"),
    ],
)
def test_main_dispatches_new_commands_without_prompting(
    monkeypatch, tmp_path, command, func
):
    """Membership in ATTACK_COMMANDS is what sets main()'s `non_interactive`
    global, which in turn suppresses the coverage prompts these attacks reach
    via _prompt_coverage_filter. If a name were registered as a subparser but
    missing from the tuple, this would hang on input() instead."""
    import hate_crack.main as hc_main

    hf = _ntlm_hashfile(tmp_path)
    calls = []
    monkeypatch.setattr(hc_main, func, lambda *a, **k: calls.append((a, k)))
    monkeypatch.setattr(
        "builtins.input",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("prompted")),
    )
    assert _run_main(monkeypatch, [command, str(hf), "1000"]) == 0
    assert len(calls) == 1


def test_main_bandrel_does_not_prompt_for_company(monkeypatch, tmp_path):
    import hate_crack.main as hc_main

    hf = _ntlm_hashfile(tmp_path)
    calls = []
    monkeypatch.setattr(hc_main, "hcatBandrel", lambda *a, **k: calls.append((a, k)))
    monkeypatch.setattr(
        "builtins.input",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("prompted")),
    )
    code = _run_main(monkeypatch, ["bandrel", str(hf), "1000", "--company", "Acme"])
    assert code == 0
    assert calls[0][1]["company_name"] == "Acme"


def test_main_reports_bad_input_as_exit_1(monkeypatch, tmp_path):
    hf = _ntlm_hashfile(tmp_path)
    code = _run_main(
        monkeypatch,
        ["permute", str(hf), "1000", "--wordlist", str(tmp_path / "missing.txt")],
    )
    assert code == 1


def test_main_unknown_subcommand_exits_2(monkeypatch, tmp_path):
    """#340 consistency note 2, end to end: argparse itself exits 2 for a
    subcommand this version does not have, so a caller running against an
    older hate_crack can tell "unsupported" from "ran and found nothing"."""
    hf = _ntlm_hashfile(tmp_path)
    assert _run_main(monkeypatch, ["prince", str(hf), "1000", "--bogus-flag"]) == 2
