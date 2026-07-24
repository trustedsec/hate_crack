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
    assert len(chains) == 2


def test_build_rule_chains_missing_file_raises(tmp_path):
    ctx = _ctx_with_rules(tmp_path)
    with pytest.raises(FileNotFoundError):
        ni.build_rule_chains(ctx, ["nope.rule"])
