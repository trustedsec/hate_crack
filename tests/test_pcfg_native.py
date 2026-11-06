import subprocess
from unittest.mock import patch

import pytest

from hate_crack import pcfg_native

HELP_WITH_PCFG = """- [ Attack Modes ] -

  # | Mode
 ===+======
  0 | Straight
  3 | Brute-force
  4 | PCFG, a trained grammar makes the candidates
  9 | Association
"""
HELP_WITHOUT_PCFG = HELP_WITH_PCFG.replace(
    "  4 | PCFG, a trained grammar makes the candidates\n", ""
)


def _completed(stdout):
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")


def setup_function(_):
    pcfg_native.supports_pcfg.cache_clear()


def test_supports_pcfg_true_when_mode_listed():
    with patch(
        "hate_crack.pcfg_native.subprocess.run", return_value=_completed(HELP_WITH_PCFG)
    ):
        assert pcfg_native.supports_pcfg("hashcat") is True


def test_supports_pcfg_false_on_stock_help():
    with patch(
        "hate_crack.pcfg_native.subprocess.run",
        return_value=_completed(HELP_WITHOUT_PCFG),
    ):
        assert pcfg_native.supports_pcfg("hashcat") is False


def test_supports_pcfg_false_when_binary_missing():
    with patch("hate_crack.pcfg_native.subprocess.run", side_effect=FileNotFoundError):
        assert pcfg_native.supports_pcfg("nope") is False


def test_supports_pcfg_false_on_timeout():
    err = subprocess.TimeoutExpired(cmd="hashcat", timeout=30)
    with patch("hate_crack.pcfg_native.subprocess.run", side_effect=err):
        assert pcfg_native.supports_pcfg("hashcat") is False


def test_list_rulesets_merges_dirs_and_strips_suffix(tmp_path):
    user = tmp_path / "user"
    shared = tmp_path / "shared"
    (user / "mine").mkdir(parents=True)
    (user / "hints.tar.xz").write_text("x")
    (shared).mkdir()
    (shared / "hints.tar.xz").write_text("x")
    (shared / "default-passwords.tar.xz").write_text("x")
    (shared / "notes.txt").write_text("x")
    names = pcfg_native.list_rulesets([str(user), str(shared)])
    assert names == ["hints", "mine", "default-passwords"]
    assert len(names) == len(set(names))
    assert "notes" not in names and "notes.txt" not in names


def test_list_rulesets_skips_missing_dirs(tmp_path):
    assert pcfg_native.list_rulesets([str(tmp_path / "absent")]) == []


def test_build_settings_empty_by_default():
    assert pcfg_native.build_settings() == []


def test_build_settings_costmax():
    assert pcfg_native.build_settings(costmax=48) == ["costmax=48"]


@pytest.mark.parametrize("bad", [0, -1])
def test_build_settings_rejects_nonpositive_costmax(bad):
    with pytest.raises(ValueError, match="costmax"):
        pcfg_native.build_settings(costmax=bad)
