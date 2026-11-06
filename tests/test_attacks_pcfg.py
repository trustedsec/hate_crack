from unittest.mock import MagicMock, patch

import pytest

from hate_crack.attacks import (
    _prompt_pcfg_constraints,
    pcfg_attack,
    pcfg_hints_attack,
    prince_ling_attack,
)


class _ScriptedUI:
    """Fake UI feeding scripted answers to ask() and recording the rest."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.prompts = []
        self.errors = []

    def ask(self, prompt="", **_kwargs):
        self.prompts.append(prompt)
        if not self.answers:
            raise AssertionError(f"unexpected prompt: {prompt!r}")
        return self.answers.pop(0)

    def error(self, msg):
        self.errors.append(msg)

    def say(self, *_a, **_k):
        pass

    def warn(self, *_a, **_k):
        pass


def _ui(answers):
    ui = _ScriptedUI(answers)
    return ui, patch("hate_crack.attacks.get_ui", return_value=ui)


def _no_rulesets():
    return _rulesets([])


def _rulesets(names):
    return patch("hate_crack.attacks.pcfg_native.list_rulesets", return_value=names)


def _make_ctx(hash_type: str = "1000", hash_file: str = "/tmp/hashes.txt") -> MagicMock:
    ctx = MagicMock()
    ctx.hcatHashType = hash_type
    ctx.hcatHashFile = hash_file
    return ctx


def test_pcfg_attack_invokes_hcatPCFG():
    ctx = _make_ctx()
    ctx.pcfg_engine.return_value = "legacy"
    pcfg_attack(ctx)
    ctx.hcatPCFG.assert_called_once_with("1000", "/tmp/hashes.txt")
    ctx.hcatPCFGNative.assert_not_called()


def test_pcfg_attack_uses_native_when_engine_native():
    ctx = _make_ctx()
    ctx.pcfg_engine.return_value = "native"
    ui, p = _ui(["", "", "", ""])
    with p, _no_rulesets():
        pcfg_attack(ctx)
    ctx.hcatPCFGNative.assert_called_once_with("1000", "/tmp/hashes.txt")
    ctx.hcatPCFG.assert_not_called()


def test_pcfg_attack_native_passes_mask():
    ctx = _make_ctx()
    ctx.pcfg_engine.return_value = "native"
    ui, p = _ui(["?u?l?l?l?d?d"])
    with p, _no_rulesets():
        pcfg_attack(ctx)
    ctx.hcatPCFGNative.assert_called_once_with(
        "1000", "/tmp/hashes.txt", mask="?u?l?l?l?d?d"
    )
    assert not any("ontain" in pr or "length" in pr for pr in ui.prompts)


def test_pcfg_attack_native_aborts_on_bad_constraint():
    ctx = _make_ctx()
    ctx.pcfg_engine.return_value = "native"
    ui, p = _ui(["", "", "abc"])
    with p, _no_rulesets():
        pcfg_attack(ctx)
    ctx.hcatPCFGNative.assert_not_called()
    assert ui.errors


def test_pcfg_attack_legacy_asks_nothing():
    ctx = _make_ctx()
    ctx.pcfg_engine.return_value = "legacy"
    ui, p = _ui([])
    with p:
        pcfg_attack(ctx)
    assert ui.prompts == []
    ctx.hcatPCFG.assert_called_once_with("1000", "/tmp/hashes.txt")


_TWO = ["default-passwords", "keyboard-walks-russian", "keyboard-walks-thai"]


def _kw_run(answers, installed=_TWO, ruleset="default-passwords"):
    ctx = _make_ctx()
    ctx.pcfg_engine.return_value = "native"
    ctx.pcfgNativeRuleset = ruleset
    ui, p = _ui(answers)
    with p, _rulesets(installed):
        pcfg_attack(ctx)
    return ctx, ui


def test_keyboard_walk_choice_merges_rulesets():
    ctx, _ = _kw_run(["", "", "", "", "1"])
    ctx.hcatPCFGNative.assert_called_once_with(
        "1000",
        "/tmp/hashes.txt",
        rulesets=["default-passwords", "keyboard-walks-russian"],
        weights=[9, 1],
    )


def test_keyboard_walk_blank_skips():
    ctx, ui = _kw_run(["", "", "", "", ""])
    ctx.hcatPCFGNative.assert_called_once_with("1000", "/tmp/hashes.txt")
    assert any("keyboard-walk" in p for p in ui.prompts)


def test_keyboard_walk_not_offered_when_none_installed():
    ctx, ui = _kw_run(["", "", "", "", "1"], installed=["default-passwords"])
    assert not any("keyboard-walk" in p for p in ui.prompts)
    assert ui.answers == ["1"]
    ctx.hcatPCFGNative.assert_called_once_with("1000", "/tmp/hashes.txt")


@pytest.mark.parametrize("bad", ["9", "abc", "0"])
def test_keyboard_walk_invalid_selection_aborts(bad):
    ctx, ui = _kw_run(["", "", "", "", bad])
    ctx.hcatPCFGNative.assert_not_called()
    assert ui.errors


def test_keyboard_walk_empty_default_ruleset_falls_back():
    ctx, _ = _kw_run(["", "", "", "", "2"], ruleset="")
    ctx.hcatPCFGNative.assert_called_once_with(
        "1000",
        "/tmp/hashes.txt",
        rulesets=["default-passwords", "keyboard-walks-thai"],
        weights=[9, 1],
    )


def test_keyboard_walk_keeps_constraints():
    ctx, _ = _kw_run(["?u?l?l?l?d?d", "1"])
    kw = ctx.hcatPCFGNative.call_args.kwargs
    assert kw["mask"] == "?u?l?l?l?d?d"
    assert kw["weights"] == [9, 1]


def _hints_ctx():
    ctx = _make_ctx()
    ctx.pcfg_engine.return_value = "native"
    return ctx


def test_hints_words_list():
    ctx = _hints_ctx()
    ui, p = _ui(["alpha, beta", "", "", "", ""])
    with p:
        pcfg_hints_attack(ctx)
    ctx.hcatPCFGHints.assert_called_once_with(
        "1000", "/tmp/hashes.txt", hintwords=["alpha", "beta"], hintfile=None
    )


def test_hints_existing_file_becomes_hintfile(tmp_path):
    f = tmp_path / "hints.txt"
    f.write_text("alpha\n")
    ctx = _hints_ctx()
    ui, p = _ui([str(f), "", "", "", ""])
    with p:
        pcfg_hints_attack(ctx)
    ctx.hcatPCFGHints.assert_called_once_with(
        "1000", "/tmp/hashes.txt", hintwords=None, hintfile=str(f)
    )


def test_hints_mask_skips_contains_prompt():
    ctx = _hints_ctx()
    ui, p = _ui(["alpha", "?u?l?l?l?d?d"])
    with p:
        pcfg_hints_attack(ctx)
    ctx.hcatPCFGHints.assert_called_once_with(
        "1000",
        "/tmp/hashes.txt",
        hintwords=["alpha"],
        hintfile=None,
        mask="?u?l?l?l?d?d",
    )
    assert not any("ontain" in pr for pr in ui.prompts)


def test_mask_skips_length_prompts():
    ui, p = _ui(["?u?l?l?l?d?d"])
    with p:
        assert _prompt_pcfg_constraints(MagicMock()) == {"mask": "?u?l?l?l?d?d"}
    assert len(ui.prompts) == 1
    assert not any("length" in pr for pr in ui.prompts)


def test_hints_contains_list_and_lengths():
    ctx = _hints_ctx()
    ui, p = _ui(["alpha", "", "beta, ,gamma", "6", "12"])
    with p:
        pcfg_hints_attack(ctx)
    ctx.hcatPCFGHints.assert_called_once_with(
        "1000",
        "/tmp/hashes.txt",
        hintwords=["alpha"],
        hintfile=None,
        contains=["beta", "gamma"],
        pwmin=6,
        pwmax=12,
    )


def test_hints_non_integer_pwmin_aborts():
    ctx = _hints_ctx()
    ui, p = _ui(["alpha", "", "", "abc"])
    with p:
        pcfg_hints_attack(ctx)
    ctx.hcatPCFGHints.assert_not_called()
    assert ui.errors


def test_constraints_non_positive_returns_none():
    ui, p = _ui(["", "", "0"])
    with p:
        assert _prompt_pcfg_constraints(MagicMock()) is None
    assert ui.errors


def test_hints_empty_answer_calls_nothing():
    ctx = _hints_ctx()
    ui, p = _ui(["  "])
    with p:
        pcfg_hints_attack(ctx)
    ctx.hcatPCFGHints.assert_not_called()


def test_hints_legacy_engine_errors():
    ctx = _make_ctx()
    ctx.pcfg_engine.return_value = "legacy"
    ui, p = _ui([])
    with p, patch("hate_crack.attacks._notify.prompt_notify_for_attack") as notify:
        pcfg_hints_attack(ctx)
    ctx.hcatPCFGHints.assert_not_called()
    assert ui.errors
    assert ui.prompts == []
    notify.assert_not_called()


def test_prince_ling_attack_invokes_hcatPrinceLing():
    ctx = _make_ctx()
    prince_ling_attack(ctx)
    ctx.hcatPrinceLing.assert_called_once_with("1000", "/tmp/hashes.txt")


def test_hints_pipal_keyword_uses_pipal_basewords():
    ctx = _hints_ctx()
    ctx.pipal.return_value = ["alpha", "beta"]
    ui, p = _ui(["pipal", "", "", "", ""])
    with p:
        pcfg_hints_attack(ctx)
    ctx.pipal.assert_called_once_with()
    ctx.hcatPCFGHints.assert_called_once_with(
        "1000", "/tmp/hashes.txt", hintwords=["alpha", "beta"], hintfile=None
    )


@pytest.mark.parametrize("pipal_result", [None, []])
def test_hints_pipal_without_basewords_aborts(pipal_result):
    ctx = _hints_ctx()
    ctx.pipal.return_value = pipal_result
    ui, p = _ui(["PIPAL"])
    with p:
        pcfg_hints_attack(ctx)
    ctx.hcatPCFGHints.assert_not_called()
    assert ui.errors
