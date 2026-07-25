import os
from types import SimpleNamespace

import pytest

from hate_crack import noninteractive as ni


def _ctx_with_rules(tmp_path, *rule_names):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    for name in rule_names:
        (rules_dir / name).write_text(":\n")
    return SimpleNamespace(rulesDirectory=str(rules_dir))


def test_build_rule_chains_no_rules_returns_empty_chain(tmp_path):
    ctx = _ctx_with_rules(tmp_path)
    assert ni.build_rule_chains(ctx, []) == [""]
    assert ni.build_rule_chains(ctx, None) == [""]


def test_build_rule_chains_single_rule(tmp_path):
    ctx = _ctx_with_rules(tmp_path, "best64.rule")
    chains = ni.build_rule_chains(ctx, ["best64.rule"])
    expected = os.path.join(ctx.rulesDirectory, "best64.rule")
    assert chains == [f"-r {expected}"]


def test_build_rule_chains_chained_token(tmp_path):
    ctx = _ctx_with_rules(tmp_path, "best64.rule", "d3ad0ne.rule")
    chains = ni.build_rule_chains(ctx, ["best64.rule+d3ad0ne.rule"])
    a = os.path.join(ctx.rulesDirectory, "best64.rule")
    b = os.path.join(ctx.rulesDirectory, "d3ad0ne.rule")
    assert chains == [f"-r {a} -r {b}"]


def test_build_rule_chains_multiple_tokens_are_separate_passes(tmp_path):
    ctx = _ctx_with_rules(tmp_path, "best64.rule", "d3ad0ne.rule")
    chains = ni.build_rule_chains(ctx, ["best64.rule", "d3ad0ne.rule"])
    a = os.path.join(ctx.rulesDirectory, "best64.rule")
    b = os.path.join(ctx.rulesDirectory, "d3ad0ne.rule")
    assert chains == [f"-r {a}", f"-r {b}"]


def test_build_rule_chains_missing_file_raises(tmp_path):
    ctx = _ctx_with_rules(tmp_path)
    with pytest.raises(FileNotFoundError, match="nope.rule"):
        ni.build_rule_chains(ctx, ["nope.rule"])


def test_build_rule_chains_empty_token_raises(tmp_path):
    ctx = _ctx_with_rules(tmp_path, "best64.rule")
    with pytest.raises(ValueError):
        ni.build_rule_chains(ctx, ["+"])


def _spy_ctx(tmp_path, **overrides):
    calls = []

    def rec(name):
        def _fn(*a, **k):
            calls.append((name, a, k))
        return _fn

    ctx = SimpleNamespace(
        calls=calls,
        hcatHashType="1000",
        hcatHashFile=str(tmp_path / "hashes.txt"),
        rulesDirectory=str(tmp_path / "rules"),
        resolve_path=lambda p: os.path.abspath(os.path.expanduser(p)) if p else None,
        hcatQuickDictionary=rec("hcatQuickDictionary"),
        hcatDictionary=rec("hcatDictionary"),
        hcatBruteForce=rec("hcatBruteForce"),
        hcatTopMask=rec("hcatTopMask"),
    )
    for k, v in overrides.items():
        setattr(ctx, k, v)
    return ctx


def test_dispatch_quick_calls_quick_dictionary(tmp_path):
    (tmp_path / "rules").mkdir()
    (tmp_path / "rules" / "best64.rule").write_text(":\n")
    wl = tmp_path / "rockyou.txt"
    wl.write_text("password\n")
    ctx = _spy_ctx(tmp_path)
    args = SimpleNamespace(command="quick", wordlist=str(wl), rules=["best64.rule"])
    code = ni.run_noninteractive(ctx, args)
    assert code == 0
    assert [c[0] for c in ctx.calls] == ["hcatQuickDictionary"]
    name, a, k = ctx.calls[0]
    assert a[0] == "1000"
    assert a[1] == ctx.hcatHashFile
    assert a[2] == f"-r {os.path.join(ctx.rulesDirectory, 'best64.rule')}"
    assert a[3] == os.path.abspath(str(wl))


def test_dispatch_quick_missing_wordlist_returns_1(tmp_path):
    (tmp_path / "rules").mkdir()
    ctx = _spy_ctx(tmp_path)
    args = SimpleNamespace(command="quick", wordlist=str(tmp_path / "nope.txt"), rules=[])
    assert ni.run_noninteractive(ctx, args) == 1
    assert ctx.calls == []


def test_dispatch_quick_unknown_rule_returns_1(tmp_path):
    (tmp_path / "rules").mkdir()
    wl = tmp_path / "rockyou.txt"
    wl.write_text("password\n")
    ctx = _spy_ctx(tmp_path)
    args = SimpleNamespace(command="quick", wordlist=str(wl), rules=["ghost.rule"])
    assert ni.run_noninteractive(ctx, args) == 1
    assert ctx.calls == []


def test_dispatch_dict_calls_dictionary(tmp_path):
    ctx = _spy_ctx(tmp_path)
    args = SimpleNamespace(command="dict")
    assert ni.run_noninteractive(ctx, args) == 0
    assert ctx.calls[0][0] == "hcatDictionary"
    assert ctx.calls[0][1] == ("1000", ctx.hcatHashFile)


def test_dispatch_brute_calls_bruteforce_with_lengths(tmp_path):
    ctx = _spy_ctx(tmp_path)
    args = SimpleNamespace(command="brute", min_len=2, max_len=6)
    assert ni.run_noninteractive(ctx, args) == 0
    assert ctx.calls[0] == ("hcatBruteForce", ("1000", ctx.hcatHashFile, 2, 6), {})


def test_dispatch_topmask_converts_hours_to_seconds(tmp_path):
    ctx = _spy_ctx(tmp_path)
    args = SimpleNamespace(command="topmask", target_time=4)
    assert ni.run_noninteractive(ctx, args) == 0
    assert ctx.calls[0] == ("hcatTopMask", ("1000", ctx.hcatHashFile, 4 * 3600), {})
