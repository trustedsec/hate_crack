import os
import sys
from types import SimpleNamespace

import pytest

import hate_crack.main as hc_main
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
    args = SimpleNamespace(command="quick", wordlist=str(wl), rule_files=["best64.rule"])
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
    args = SimpleNamespace(command="quick", wordlist=str(tmp_path / "nope.txt"), rule_files=[])
    assert ni.run_noninteractive(ctx, args) == 1
    assert ctx.calls == []


def test_dispatch_quick_unknown_rule_returns_1(tmp_path):
    (tmp_path / "rules").mkdir()
    wl = tmp_path / "rockyou.txt"
    wl.write_text("password\n")
    ctx = _spy_ctx(tmp_path)
    args = SimpleNamespace(command="quick", wordlist=str(wl), rule_files=["ghost.rule"])
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


def test_dispatch_unknown_command_returns_2(tmp_path):
    ctx = _spy_ctx(tmp_path)
    args = SimpleNamespace(command="bogus")
    assert ni.run_noninteractive(ctx, args) == 2
    assert ctx.calls == []


def test_dispatch_quick_multiple_rules_runs_each_as_separate_pass(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "best64.rule").write_text(":\n")
    (rules / "d3ad0ne.rule").write_text(":\n")
    wl = tmp_path / "rockyou.txt"
    wl.write_text("password\n")
    ctx = _spy_ctx(tmp_path)
    args = SimpleNamespace(
        command="quick", wordlist=str(wl), rule_files=["best64.rule", "d3ad0ne.rule"]
    )
    assert ni.run_noninteractive(ctx, args) == 0
    assert len(ctx.calls) == 2
    chains = [c[1][2] for c in ctx.calls]
    assert chains == [
        f"-r {os.path.join(ctx.rulesDirectory, 'best64.rule')}",
        f"-r {os.path.join(ctx.rulesDirectory, 'd3ad0ne.rule')}",
    ]


def _run_main(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["hate_crack.py"] + argv)
    # main()'s pre-dispatch potfile-recovery step shells out to the real hashcat
    # binary, which is absent in CI. Stub it — these tests exercise dispatch
    # routing and prompt suppression, not potfile recovery.
    monkeypatch.setattr(hc_main, "_run_hashcat_show", lambda *a, **k: None)
    with pytest.raises(SystemExit) as excinfo:
        hc_main.main()
    return excinfo.value.code


def _make_ntlm_hashfile(tmp_path):
    # Bare 32-hex NTLM hash: exercises the non-pwdump preprocessing branch.
    hf = tmp_path / "hashes.txt"
    hf.write_text("aad3b435b51404eeaad3b435b51404ee\n")
    return hf


def test_main_quick_dispatches_without_prompting(monkeypatch, tmp_path):
    hf = _make_ntlm_hashfile(tmp_path)
    wl = tmp_path / "rockyou.txt"
    wl.write_text("password\n")
    calls = []
    monkeypatch.setattr(
        hc_main, "hcatQuickDictionary", lambda *a, **k: calls.append((a, k))
    )
    monkeypatch.setattr(
        "builtins.input",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("prompted")),
    )
    code = _run_main(monkeypatch, ["quick", str(hf), "1000", "--wordlist", str(wl)])
    assert code == 0
    assert len(calls) == 1


def test_main_brute_dispatches(monkeypatch, tmp_path):
    hf = _make_ntlm_hashfile(tmp_path)
    calls = []
    monkeypatch.setattr(hc_main, "hcatBruteForce", lambda *a, **k: calls.append(a))
    code = _run_main(
        monkeypatch, ["brute", str(hf), "1000", "--min", "1", "--max", "8"]
    )
    assert code == 0
    assert calls[0][2] == 1 and calls[0][3] == 8


def test_main_quick_bad_hashtype_errors(monkeypatch, tmp_path):
    hf = _make_ntlm_hashfile(tmp_path)
    wl = tmp_path / "w.txt"
    wl.write_text("x\n")
    code = _run_main(
        monkeypatch, ["quick", str(hf), "notanumber", "--wordlist", str(wl)]
    )
    assert code != 0


def test_main_quick_with_rules_dispatches(monkeypatch, tmp_path):
    hf = _make_ntlm_hashfile(tmp_path)
    wl = tmp_path / "rockyou.txt"
    wl.write_text("password\n")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "best64.rule").write_text(":\n")
    monkeypatch.setattr(hc_main, "rulesDirectory", str(rules_dir))
    calls = []
    monkeypatch.setattr(
        hc_main, "hcatQuickDictionary", lambda *a, **k: calls.append(a)
    )
    code = _run_main(
        monkeypatch,
        ["quick", str(hf), "1000", "--wordlist", str(wl), "--rules", "best64.rule"],
    )
    assert code == 0
    assert len(calls) == 1
    # the rule chain (4th positional arg) must reference best64.rule
    assert "best64.rule" in calls[0][2]


def test_main_debug_flag_before_subcommand(monkeypatch, tmp_path):
    hf = _make_ntlm_hashfile(tmp_path)
    wl = tmp_path / "w.txt"
    wl.write_text("x\n")
    calls = []
    monkeypatch.setattr(
        hc_main, "hcatQuickDictionary", lambda *a, **k: calls.append(a)
    )
    code = _run_main(
        monkeypatch,
        ["--debug", "quick", str(hf), "1000", "--wordlist", str(wl)],
    )
    assert code == 0
    assert len(calls) == 1
