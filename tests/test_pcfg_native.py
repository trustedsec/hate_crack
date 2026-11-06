import os
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


def teardown_function(_):
    pcfg_native.supports_pcfg.cache_clear()


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


def test_list_rulesets_skips_unreadable_dir(tmp_path, monkeypatch):
    locked = tmp_path / "locked"
    readable = tmp_path / "readable"
    locked.mkdir()
    (readable / "hints").mkdir(parents=True)
    real_listdir = pcfg_native.os.listdir

    def listdir(path):
        if os.path.abspath(path) == str(locked):
            raise PermissionError(13, "Permission denied", path)
        return real_listdir(path)

    monkeypatch.setattr(pcfg_native.os, "listdir", listdir)
    assert pcfg_native.list_rulesets([str(locked), str(readable)]) == ["hints"]


def test_build_settings_empty_by_default():
    assert pcfg_native.build_settings() == []


def test_build_settings_costmax():
    assert pcfg_native.build_settings(costmax=48) == ["costmax=48"]


@pytest.mark.parametrize("bad", [0, -1])
def test_build_settings_rejects_nonpositive_costmax(bad):
    with pytest.raises(ValueError, match="costmax"):
        pcfg_native.build_settings(costmax=bad)


def test_mask_and_contains_exclusive():
    with pytest.raises(ValueError, match="mask.*contains"):
        pcfg_native.build_settings(mask="?l?l?d", contains=["ab"])


@pytest.mark.parametrize("kw", [{"mask": "?l?l"}, {"contains": ["ab"]}])
def test_omen_on_conflicts_with_shape_filters(kw):
    with pytest.raises(ValueError, match="omen"):
        pcfg_native.build_settings(omen=True, **kw)


def test_omen_off_is_allowed_with_mask():
    out = pcfg_native.build_settings(mask="?l?l", omen=False)
    assert out == ["mask=?l?l", "omen=0"]


def test_pwmin_above_pwmax_rejected():
    with pytest.raises(ValueError, match="pwmin"):
        pcfg_native.build_settings(pwmin=12, pwmax=8)


def test_contains_pieces_comma_joined():
    assert pcfg_native.build_settings(contains=["alpha", "?d?d"]) == [
        "contains=alpha,?d?d"
    ]


def test_contains_duplicate_piece_rejected():
    with pytest.raises(ValueError, match="twice"):
        pcfg_native.build_settings(contains=["ab", "cd", "ab"])


@pytest.mark.parametrize("piece", ["", "   "])
def test_contains_empty_piece_rejected(piece):
    with pytest.raises(ValueError, match="empty"):
        pcfg_native.build_settings(contains=["ab", piece])


def test_contains_comma_message_has_no_charset_advice():
    with pytest.raises(ValueError) as info:
        pcfg_native.build_settings(contains=["a,b"])
    assert str(info.value) == "a contains piece cannot hold a comma"


def test_contains_piece_with_comma_rejected():
    with pytest.raises(ValueError, match="comma"):
        pcfg_native.build_settings(contains=["a,b"])


def test_hintwords_joined_and_trimmed():
    assert pcfg_native.build_settings(hintwords=[" alpha ", "beta"]) == [
        "hintwords=alpha,beta"
    ]


@pytest.mark.parametrize("bad", ["", "a,b", "a b"])
def test_hintword_validation(bad):
    with pytest.raises(ValueError, match="hint"):
        pcfg_native.build_settings(hintwords=["ok", bad])


def test_hintwords_and_hintfile_are_exclusive():
    with pytest.raises(ValueError, match="hintwords.*hintfile"):
        pcfg_native.build_settings(hintwords=["a"], hintfile="/tmp/f")


def test_hintrank_choices():
    assert pcfg_native.build_settings(hintrank="flat") == ["hintrank=flat"]
    with pytest.raises(ValueError, match="hintrank"):
        pcfg_native.build_settings(hintrank="nope")


def test_hintrepeat_flag():
    assert pcfg_native.build_settings(hintrepeat=True) == ["hintrepeat=1"]


def test_weights_must_match_ruleset_count():
    assert pcfg_native.build_settings(weights=[9, 1], ruleset_count=2) == [
        "weights=9:1"
    ]
    with pytest.raises(ValueError, match="weights"):
        pcfg_native.build_settings(weights=[9, 1], ruleset_count=3)
    with pytest.raises(ValueError, match="weights"):
        pcfg_native.build_settings(weights=[0, 0], ruleset_count=2)
