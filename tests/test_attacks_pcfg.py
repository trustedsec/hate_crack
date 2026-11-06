from unittest.mock import MagicMock, patch

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
        return self.answers.pop(0) if self.answers else ""

    def error(self, msg):
        self.errors.append(msg)

    def say(self, *_a, **_k):
        pass

    def warn(self, *_a, **_k):
        pass


def _ui(answers):
    ui = _ScriptedUI(answers)
    return ui, patch("hate_crack.attacks.get_ui", return_value=ui)


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
    with p:
        pcfg_attack(ctx)
    ctx.hcatPCFGNative.assert_called_once_with("1000", "/tmp/hashes.txt")
    ctx.hcatPCFG.assert_not_called()


def test_pcfg_attack_native_passes_mask():
    ctx = _make_ctx()
    ctx.pcfg_engine.return_value = "native"
    ui, p = _ui(["?u?l?l?l?d?d", "", ""])
    with p:
        pcfg_attack(ctx)
    ctx.hcatPCFGNative.assert_called_once_with(
        "1000", "/tmp/hashes.txt", mask="?u?l?l?l?d?d"
    )


def test_pcfg_attack_native_aborts_on_bad_constraint():
    ctx = _make_ctx()
    ctx.pcfg_engine.return_value = "native"
    ui, p = _ui(["", "", "abc"])
    with p:
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
    ui, p = _ui(["alpha", "?u?l?l?l?d?d", "", ""])
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
    ui, p = _ui(["alpha"])
    with p:
        pcfg_hints_attack(ctx)
    ctx.hcatPCFGHints.assert_not_called()
    assert ui.errors


def test_prince_ling_attack_invokes_hcatPrinceLing():
    ctx = _make_ctx()
    prince_ling_attack(ctx)
    ctx.hcatPrinceLing.assert_called_once_with("1000", "/tmp/hashes.txt")
