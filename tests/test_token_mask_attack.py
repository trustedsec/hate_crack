"""Tests for the Token Mask attack (menu 27): hcatTokenMask and its handler."""

from unittest.mock import MagicMock, patch

import pytest

from hate_crack.attacks import token_mask_crack


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


class _ScriptedUI:
    def __init__(self, answers):
        self.answers = list(answers)
        self.prompts = []
        self.said = []
        self.warned = []
        self.errors = []

    def ask(self, prompt="", **_kwargs):
        self.prompts.append(prompt)
        if not self.answers:
            raise AssertionError(f"unexpected prompt: {prompt!r}")
        return self.answers.pop(0)

    def say(self, msg="", *_a, **_k):
        self.said.append(msg)

    def warn(self, msg="", *_a, **_k):
        self.warned.append(msg)

    def error(self, msg="", *_a, **_k):
        self.errors.append(msg)


def _run_wrapper(main_module, *args, supported=True, ui=None, **kwargs):
    ui = ui or _ScriptedUI([])
    with (
        patch("hate_crack.main.tokenmask.supports_tokenmask", return_value=supported),
        patch("hate_crack.main._run_hcat_cmd") as mock_run,
        patch("hate_crack.main.get_ui", return_value=ui),
        patch.object(main_module, "hcatBin", "hashcat"),
        patch.object(main_module, "hcatTuning", "--force"),
        patch.object(main_module, "hcatPotfilePath", "/tmp/pot"),
        patch.object(main_module, "_should_use_optimized_kernel", return_value=True),
    ):
        result = main_module.hcatTokenMask(*args, **kwargs)
    return result, mock_run, ui


class TestHcatTokenMask:
    def test_command_order(self, main_module):
        result, run, _ = _run_wrapper(
            main_module,
            "1000",
            "/tmp/h.txt",
            "?1?1?d",
            {1: "/t/french.tokenset"},
        )
        assert result is True
        cmd = run.call_args.args[0]
        a = cmd.index("-a")
        assert cmd[a : a + 2] == ["-a", "13"]
        assert cmd[a + 2 :][:3] == ["-1", "/t/french.tokenset", "?1?1?d"]
        assert cmd.index("--force") > cmd.index("?1?1?d")
        assert "--potfile-path=/tmp/pot" in cmd[cmd.index("--force") + 1 :]
        assert cmd[:4] == ["hashcat", "-m", "1000", "/tmp/h.txt"]
        assert cmd[cmd.index("-o") + 1] == "/tmp/h.txt.out"

    def test_no_optimized_flag(self, main_module):
        _, run, _ = _run_wrapper(main_module, "0", "/tmp/h", "?1", {1: "?l"})
        assert "-O" not in run.call_args.args[0]

    def test_attack_name_and_no_coverage(self, main_module):
        _, run, _ = _run_wrapper(main_module, "0", "/tmp/h", "?1", {1: "?l"})
        kwargs = run.call_args.kwargs
        assert kwargs["attack_name"] == "Token Mask"
        assert kwargs["hash_file"] == "/tmp/h"
        assert kwargs.get("coverage") is None

    def test_charsets_ascending(self, main_module):
        _, run, _ = _run_wrapper(main_module, "0", "/tmp/h", "?1?2", {2: "?d", 1: "?l"})
        cmd = run.call_args.args[0]
        i = cmd.index("-1")
        assert cmd[i : i + 4] == ["-1", "?l", "-2", "?d"]

    def test_increment_variants(self, main_module):
        _, run, _ = _run_wrapper(main_module, "0", "/tmp/h", "?1?1", {1: "?l"})
        assert not any(p.startswith("--increment") for p in run.call_args.args[0])

        _, run, _ = _run_wrapper(
            main_module, "0", "/tmp/h", "?1?1", {1: "?l"}, increment=True
        )
        cmd = run.call_args.args[0]
        assert "--increment" in cmd
        assert not any(p.startswith("--increment-") for p in cmd)

        _, run, _ = _run_wrapper(
            main_module,
            "0",
            "/tmp/h",
            "?1?1",
            {1: "?l"},
            increment=True,
            increment_min="1",
            increment_max="2",
        )
        cmd = run.call_args.args[0]
        assert "--increment-min=1" in cmd and "--increment-max=2" in cmd
        assert cmd.index("--increment") < cmd.index("?1?1")

    def test_unsupported_refuses(self, main_module):
        result, run, ui = _run_wrapper(
            main_module, "0", "/tmp/h", "?1", {1: "?l"}, supported=False
        )
        assert result is False
        run.assert_not_called()
        assert any("13" in e for e in ui.errors)

    def test_bad_slot_refuses(self, main_module):
        result, run, ui = _run_wrapper(main_module, "0", "/tmp/h", "?1", {9: "?l"})
        assert result is False
        run.assert_not_called()
        assert ui.errors


def _ctx(supported=True):
    ctx = MagicMock()
    ctx.hcatHashType = "1000"
    ctx.hcatHashFile = "/tmp/h.txt"
    ctx.hcatBin = "hashcat"
    ctx.hcatPath = "/opt/hashcat"
    ctx.hcatTokenMask.return_value = True
    return ctx


def _drive(answers, tokensets=None, supported=True):
    ui = _ScriptedUI(answers)
    ctx = _ctx()
    with (
        patch("hate_crack.attacks.get_ui", return_value=ui),
        patch("hate_crack.attacks._notify.prompt_notify_for_attack"),
        patch(
            "hate_crack.attacks.tokenmask.supports_tokenmask", return_value=supported
        ),
        patch(
            "hate_crack.attacks.tokenmask.list_tokensets",
            return_value=tokensets if tokensets is not None else [],
        ),
    ):
        token_mask_crack(ctx)
    return ctx, ui


SETS = [("french", "/t/french.tokenset"), ("greek", "/t/greek.tokenset")]


class TestTokenMaskHandler:
    def test_unsupported_returns_without_asking(self):
        ctx, ui = _drive([], supported=False)
        assert ui.prompts == []
        assert ui.warned
        ctx.hcatTokenMask.assert_not_called()

    def test_blank_mask_returns(self):
        ctx, _ = _drive([""])
        ctx.hcatTokenMask.assert_not_called()

    def test_mask_without_slots_returns(self):
        ctx, ui = _drive(["?l?l?d"])
        ctx.hcatTokenMask.assert_not_called()
        assert any("14" in w for w in ui.warned)

    def test_numbered_pick_resolves_to_path(self):
        ctx, _ = _drive(["?1?1", "2", "n"], tokensets=SETS)
        args = ctx.hcatTokenMask.call_args
        assert args.args[2] == "?1?1"
        assert args.args[3] == {1: "/t/greek.tokenset"}
        assert args.kwargs["increment"] is False

    def test_inline_passthrough(self):
        ctx, _ = _drive(["?1?2", "?l?d", "abc", "n"], tokensets=SETS)
        assert ctx.hcatTokenMask.call_args.args[3] == {1: "?l?d", 2: "abc"}

    def test_out_of_range_and_blank_reask(self):
        ctx, ui = _drive(["?1", "9", "", "?d", "n"], tokensets=SETS)
        assert ctx.hcatTokenMask.call_args.args[3] == {1: "?d"}
        assert ui.warned

    def test_latin_set_widened_by_default(self):
        ctx, _ = _drive(["?1?1", "1", "", "n"], tokensets=SETS)
        assert ctx.hcatTokenMask.call_args.args[3] == {
            1: "?l?u?2",
            2: "/t/french.tokenset",
        }

    def test_latin_set_declined_keeps_file(self):
        ctx, _ = _drive(["?1?1", "1", "n", "n"], tokensets=SETS)
        assert ctx.hcatTokenMask.call_args.args[3] == {1: "/t/french.tokenset"}

    def test_increment_passthrough(self):
        ctx, ui = _drive(["?1?1", "?l", "y", "1", "2"])
        kwargs = ctx.hcatTokenMask.call_args.kwargs
        assert kwargs == {
            "increment": True,
            "increment_min": "1",
            "increment_max": "2",
        }
        assert any("token" in s.lower() and "byte" in s.lower() for s in ui.said)
