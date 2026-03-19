import os
from unittest.mock import MagicMock, patch

import pytest

from hate_crack.attacks import permute_crack


def _make_ctx(hash_type="1000", hash_file="/tmp/hashes.txt"):
    ctx = MagicMock()
    ctx.hcatHashType = hash_type
    ctx.hcatHashFile = hash_file
    ctx.hcatWordlists = "/tmp/wordlists"
    return ctx


class TestPermuteCrack:
    def test_calls_hcatPermute_with_valid_wordlist(self, tmp_path):
        ctx = _make_ctx()
        wl = tmp_path / "target.txt"
        wl.write_text("abc\ndef\n")
        with patch("builtins.input", return_value=str(wl)):
            permute_crack(ctx)
        ctx.hcatPermute.assert_called_once_with(
            ctx.hcatHashType, ctx.hcatHashFile, str(wl)
        )

    def test_rejects_nonexistent_wordlist_then_accepts_valid(self, tmp_path):
        ctx = _make_ctx()
        wl = tmp_path / "real.txt"
        wl.write_text("test\n")
        with patch(
            "builtins.input",
            side_effect=["/nonexistent/path.txt", str(wl)],
        ):
            permute_crack(ctx)
        ctx.hcatPermute.assert_called_once_with(
            ctx.hcatHashType, ctx.hcatHashFile, str(wl)
        )

    def test_rejects_directory_then_accepts_file(self, tmp_path):
        ctx = _make_ctx()
        wl = tmp_path / "words.txt"
        wl.write_text("ab\n")
        with patch("builtins.input", side_effect=[str(tmp_path), str(wl)]):
            permute_crack(ctx)
        ctx.hcatPermute.assert_called_once_with(
            ctx.hcatHashType, ctx.hcatHashFile, str(wl)
        )

    def test_warns_about_factorial_scaling(self, tmp_path, capsys):
        ctx = _make_ctx()
        wl = tmp_path / "words.txt"
        wl.write_text("abc\n")
        with patch("builtins.input", return_value=str(wl)):
            permute_crack(ctx)
        captured = capsys.readouterr()
        assert "WARNING" in captured.out or "factorial" in captured.out.lower() or "N!" in captured.out

    def test_prints_header(self, tmp_path, capsys):
        ctx = _make_ctx()
        wl = tmp_path / "words.txt"
        wl.write_text("abc\n")
        with patch("builtins.input", return_value=str(wl)):
            permute_crack(ctx)
        captured = capsys.readouterr()
        assert "PERMUTATION" in captured.out.upper()
