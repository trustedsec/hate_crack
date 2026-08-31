"""Tests for --no-optimized-kernel, the global -O off switch.

The flag has to close both routes -O reaches hashcat: the per-attack
``optimizedKernelAttacks`` config list, and a literal ``-O`` sitting in
``hcatTuning`` (which is appended verbatim to every invocation).

Every test monkeypatches the globals the flag mutates before running main(),
because ``hate_crack.main`` is shared across the session and a leaked
``_optimized_kernel_disabled = True`` would silently un-optimize later tests.
"""

import sys
from unittest.mock import MagicMock, patch

import pytest

import hate_crack.main as hc_main


def _run_main(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["hate_crack.py"] + argv)
    monkeypatch.setattr(hc_main, "_optimized_kernel_disabled", False)
    monkeypatch.setattr(hc_main, "hcatTuning", "-w 4 -O")
    monkeypatch.setattr(hc_main, "ascii_art", lambda: None)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "5")
    with pytest.raises(SystemExit) as exc:
        hc_main.main()
    return exc.value.code


@pytest.mark.parametrize("flag", ["--no-optimized-kernel", "--no-optimize"])
def test_flag_disables_optimized_kernel_for_every_attack(monkeypatch, flag):
    _run_main(monkeypatch, [flag])
    assert hc_main._optimized_kernel_disabled is True
    # hcatDictionary is optimized by default; the flag must override that.
    assert hc_main._should_use_optimized_kernel("hcatDictionary") is False


@pytest.mark.parametrize("flag", ["--no-optimized-kernel", "--no-optimize"])
def test_flag_strips_hand_written_optimize_from_tuning(monkeypatch, flag):
    _run_main(monkeypatch, [flag])
    assert "-O" not in hc_main.hcatTuning.split()
    assert "-w" in hc_main.hcatTuning.split(), "unrelated tuning must survive"


def test_without_the_flag_optimization_is_unchanged(monkeypatch):
    _run_main(monkeypatch, [])
    assert hc_main._optimized_kernel_disabled is False
    assert hc_main._should_use_optimized_kernel("hcatDictionary") is True
    assert "-O" in hc_main.hcatTuning.split()


class TestStripOptimizedFlags:
    @pytest.mark.parametrize(
        "tuning, expected",
        [
            ("-O", ""),
            ("--optimized-kernel-enable", ""),
            ("-w 4 -O", "-w 4"),
            ("-O -w 3 --optimized-kernel-enable", "-w 3"),
            ("-w 4", "-w 4"),
            ("", ""),
            (None, ""),
        ],
    )
    def test_removes_only_the_optimize_tokens(self, tuning, expected):
        assert hc_main._strip_optimized_flags(tuning) == expected

    def test_preserves_quoting_of_other_tokens(self):
        assert (
            hc_main._strip_optimized_flags('-O --session "my run"')
            == "--session 'my run'"
        )


class TestCommandLineHasNoOptimizeFlag:
    """An actual hashcat invocation carries no -O once the switch is on."""

    def test_dictionary_attack_omits_optimize(self, monkeypatch, tmp_path):
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text("")
        (tmp_path / "hashes.txt.out").write_text("")
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("token1\n")

        captured = []

        def fake_popen(cmd, **kwargs):
            captured.append(list(cmd))
            proc = MagicMock()
            proc.stdout = MagicMock()
            proc.stderr = MagicMock()
            proc.wait.return_value = None
            proc.returncode = 0
            return proc

        with (
            patch("hate_crack.main.subprocess.Popen", side_effect=fake_popen),
            patch.object(hc_main, "_optimized_kernel_disabled", True),
            patch.object(hc_main, "hcatBin", "hashcat"),
            patch.object(hc_main, "hcatTuning", ""),
            patch.object(hc_main, "hcatPotfilePath", ""),
            patch.object(hc_main, "hcatRules", []),
            patch("hate_crack.main.generate_session_id", return_value="s"),
        ):
            hc_main.hcatQuickDictionary("1000", str(hash_file), "", str(wordlist))

        hashcat_cmds = [cmd for cmd in captured if cmd and cmd[0] == "hashcat"]
        assert hashcat_cmds, "expected at least one hashcat invocation"
        for cmd in hashcat_cmds:
            assert "-O" not in cmd
            assert "--optimized-kernel-enable" not in cmd
