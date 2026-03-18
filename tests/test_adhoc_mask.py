"""Tests for ad-hoc mask attack, markov brute force, and combinator submenu."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def _make_ctx(hash_type: str = "1000", hash_file: str = "/tmp/hashes.txt") -> MagicMock:
    ctx = MagicMock()
    ctx.hcatHashType = hash_type
    ctx.hcatHashFile = hash_file
    ctx.hcatWordlists = "/tmp/wordlists"
    return ctx


class TestAdHocMaskHandler:
    """Test the adhoc_mask_crack handler for user input and flow."""

    def test_basic_mask(self) -> None:
        """User enters mask, no custom charsets."""
        from hate_crack.attacks import adhoc_mask_crack

        ctx = _make_ctx()
        with patch("builtins.input", side_effect=["?l?l?l?l", ""]):
            adhoc_mask_crack(ctx)

        ctx.hcatAdHocMask.assert_called_once_with("1000", "/tmp/hashes.txt", "?l?l?l?l", "")

    def test_empty_mask_aborts(self) -> None:
        """Empty mask string causes early return."""
        from hate_crack.attacks import adhoc_mask_crack

        ctx = _make_ctx()
        with patch("builtins.input", return_value=""):
            adhoc_mask_crack(ctx)

        ctx.hcatAdHocMask.assert_not_called()

    def test_custom_charset_passed(self) -> None:
        """User enters custom charset -1."""
        from hate_crack.attacks import adhoc_mask_crack

        ctx = _make_ctx()
        with patch("builtins.input", side_effect=["?1?1?1?1", "abc", ""]):
            adhoc_mask_crack(ctx)

        ctx.hcatAdHocMask.assert_called_once()
        call_args = ctx.hcatAdHocMask.call_args
        assert call_args[0][2] == "?1?1?1?1"
        assert "-1" in call_args[0][3]
        assert "abc" in call_args[0][3]


class TestMarkovBruteForceHandler:
    """Test markov_brute_force handler logic with table reuse options."""

    def test_use_existing_table(self, tmp_path: Path) -> None:
        """User chooses to use existing .hcstat2 table."""
        from hate_crack.attacks import markov_brute_force

        ctx = _make_ctx()
        hash_file = str(tmp_path / "hashes.txt")
        ctx.hcatHashFile = hash_file
        hcstat2_path = f"{hash_file}.hcstat2"
        Path(hcstat2_path).touch()

        with patch("builtins.input", side_effect=["1", "1", "7"]):
            markov_brute_force(ctx)

        ctx.hcatMarkovTrain.assert_not_called()
        ctx.hcatMarkovBruteForce.assert_called_once()

    def test_no_table_requires_training(self, tmp_path: Path) -> None:
        """No table exists, training is triggered."""
        from hate_crack.attacks import markov_brute_force

        ctx = _make_ctx()
        hash_file = str(tmp_path / "hashes.txt")
        ctx.hcatHashFile = hash_file
        ctx.hcatMarkovTrain.return_value = True
        ctx.list_wordlist_files.return_value = ["test.txt"]

        with patch("builtins.input", side_effect=["1", "1", "6"]):
            markov_brute_force(ctx)

        ctx.hcatMarkovTrain.assert_called_once()
        ctx.hcatMarkovBruteForce.assert_called_once()

    def test_training_failure_aborts(self, tmp_path: Path) -> None:
        """Training failure aborts without calling brute force."""
        from hate_crack.attacks import markov_brute_force

        ctx = _make_ctx()
        hash_file = str(tmp_path / "hashes.txt")
        ctx.hcatHashFile = hash_file
        ctx.hcatMarkovTrain.return_value = False
        ctx.list_wordlist_files.return_value = ["test.txt"]

        with patch("builtins.input", side_effect=["1", "1"]):
            markov_brute_force(ctx)

        ctx.hcatMarkovTrain.assert_called_once()
        ctx.hcatMarkovBruteForce.assert_not_called()
