import os
import subprocess
from unittest.mock import patch

import pytest

from hate_crack import hashcat_paths, tokenmask

HELP_WITH = """- [ Attack Modes ] -

  # | Mode
 ===+======
  0 | Straight
  3 | Brute-force
 13 | Token Mask, a mask built from token sets
"""
HELP_WITHOUT = HELP_WITH.replace(" 13 | Token Mask, a mask built from token sets\n", "")


def setup_function(_):
    hashcat_paths.reset_help_cache()


def teardown_function(_):
    hashcat_paths.reset_help_cache()


def _completed(stdout):
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")


def test_supports_tokenmask_true():
    with patch(
        "hate_crack.hashcat_paths.subprocess.run", return_value=_completed(HELP_WITH)
    ):
        assert tokenmask.supports_tokenmask("hashcat") is True


def test_supports_tokenmask_false():
    with patch(
        "hate_crack.hashcat_paths.subprocess.run",
        return_value=_completed(HELP_WITHOUT),
    ):
        assert tokenmask.supports_tokenmask("hashcat") is False


def test_supports_tokenmask_false_when_binary_missing():
    with patch(
        "hate_crack.hashcat_paths.subprocess.run", side_effect=FileNotFoundError
    ):
        assert tokenmask.supports_tokenmask("nope") is False


def test_cache_clear_shim_is_reset_help_cache():
    assert getattr(tokenmask.supports_tokenmask, "cache_clear") is (
        hashcat_paths.reset_help_cache
    )


def test_suffix():
    assert tokenmask.TOKENSET_SUFFIX == ".tokenset"


def test_search_dirs_default_order(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    hc = tmp_path / "hc"
    dirs = tokenmask.tokenset_search_dirs("", str(hc))
    assert dirs == [
        str(hc / "tokensets"),
        str(tmp_path / "xdg" / "hashcat" / "tokensets"),
        "/usr/local/share/hashcat/tokensets",
        "/usr/share/hashcat/tokensets",
    ]


def test_search_dirs_default_xdg(monkeypatch):
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    dirs = tokenmask.tokenset_search_dirs()
    assert dirs[0] == os.path.expanduser("~/.local/share/hashcat/tokensets")


def test_search_dirs_binary_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    binary = tmp_path / "build" / "hashcat"
    binary.parent.mkdir()
    binary.write_text("")
    dirs = tokenmask.tokenset_search_dirs(str(binary), "")
    assert dirs[0] == os.path.join(os.path.realpath(binary.parent), "tokensets")


def test_search_dirs_dedupes_by_realpath(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    binary = tmp_path / "hashcat"
    binary.write_text("")
    dirs = tokenmask.tokenset_search_dirs(str(binary), str(tmp_path))
    reals = [os.path.realpath(d) for d in dirs]
    assert len(reals) == len(set(reals))
    assert dirs[0] == str(tmp_path / "tokensets")


def test_list_tokensets(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "zulu.tokenset").write_text("")
    (a / "french.tokenset").write_text("")
    (a / "notes.txt").write_text("")
    (a / "sub.tokenset").mkdir()
    (b / "french.tokenset").write_text("")
    (b / "alpha.tokenset").write_text("")
    got = tokenmask.list_tokensets([str(a), str(b), str(tmp_path / "missing")])
    assert got == [
        ("alpha", str(b / "alpha.tokenset")),
        ("french", str(a / "french.tokenset")),
        ("zulu", str(a / "zulu.tokenset")),
    ]


def test_resolve_charset_file(tmp_path, monkeypatch):
    f = tmp_path / "mine.txt"
    f.write_text("x")
    monkeypatch.chdir(tmp_path)
    assert tokenmask.resolve_charset("mine.txt", []) == str(f)


def test_resolve_charset_name_and_suffix():
    ts = [("french", "/x/french.tokenset")]
    assert tokenmask.resolve_charset("french", ts) == "/x/french.tokenset"
    assert tokenmask.resolve_charset("french.tokenset", ts) == "/x/french.tokenset"


def test_resolve_charset_inline_and_strip():
    assert tokenmask.resolve_charset("  ?l?u ", [("french", "/p")]) == "?l?u"


def test_resolve_charset_empty():
    with pytest.raises(ValueError, match="empty charset"):
        tokenmask.resolve_charset("   ", [])


def test_latin_sets():
    assert len(tokenmask.LATIN_ACCENT_SETS) == 13
    assert "french" in tokenmask.LATIN_ACCENT_SETS
    assert isinstance(tokenmask.LATIN_ACCENT_SETS, frozenset)


def test_widen_basic():
    assert tokenmask.widen_with_ascii({1: "french"}, 1, "/p", [1]) == {
        1: "?l?u?2",
        2: "/p",
    }


def test_widen_skips_used_and_assigned_and_no_mutation():
    src = {1: "french", 2: "?d"}
    out = tokenmask.widen_with_ascii(src, 1, "/p", [1, 3])
    assert out == {1: "?l?u?4", 2: "?d", 4: "/p"}
    assert src == {1: "french", 2: "?d"}


def test_widen_no_free_slot():
    src = {i: "?d" for i in range(1, 8)}
    with pytest.raises(ValueError, match="no free charset slot"):
        tokenmask.widen_with_ascii(src, 1, "/p", [8])


def test_build_charset_args_order():
    assert tokenmask.build_charset_args({3: "c", 1: "a"}) == ["-1", "a", "-3", "c"]
    assert tokenmask.build_charset_args({}) == []


@pytest.mark.parametrize("slot", [0, 9, -1])
def test_build_charset_args_bad_slot(slot):
    with pytest.raises(ValueError):
        tokenmask.build_charset_args({slot: "x"})


def test_missing_tokenset_bare_name_warns(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    resolved = tokenmask.resolve_charset("cyrilic", [("cyrillic", "/x/c.tokenset")])
    assert tokenmask.looks_like_missing_tokenset("cyrilic", resolved)
    # A bare run of letters is also literal bytes; the warning says so.
    assert tokenmask.looks_like_missing_tokenset("abc", "abc")


def test_missing_tokenset_inline_and_path_forms_do_not_warn(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for value in ("?l?d", "?1", "./missing.tokenset", "/no/such.tokenset"):
        resolved = tokenmask.resolve_charset(value, [])
        assert not tokenmask.looks_like_missing_tokenset(value, resolved)


def test_missing_tokenset_existing_file_and_known_name_do_not_warn(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "mine.txt").write_text("x")
    ts = [("french", "/x/french.tokenset")]
    for value in ("mine.txt", "french", "french.tokenset"):
        resolved = tokenmask.resolve_charset(value, ts)
        assert not tokenmask.looks_like_missing_tokenset(value, resolved)
