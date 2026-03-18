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


class TestHcatAdHocMask:
    """Test the hcatAdHocMask wrapper function."""

    def test_mask_attack_command(self, tmp_path: Path) -> None:
        """Verify mask attack command structure."""
        from hate_crack import main

        hash_file = str(tmp_path / "hashes.txt")

        with patch("subprocess.Popen") as mock_popen:
            mock_process = MagicMock()
            mock_process.wait.return_value = None
            mock_popen.return_value = mock_process

            main.hcatAdHocMask("1000", hash_file, "?l?l?d?d", "")

            call_args = mock_popen.call_args[0][0]
            assert "-m" in call_args
            assert "1000" in call_args
            assert hash_file in call_args
            assert "-a" in call_args
            assert "3" in call_args
            assert "?l?l?d?d" in call_args


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


class TestHcatMarkovBruteForce:
    """Test hcatMarkovBruteForce wrapper function."""

    def test_markov_flags_in_cmd(self, tmp_path: Path) -> None:
        """Verify markov attack command includes table and increment flags."""
        from hate_crack import main

        hash_file = str(tmp_path / "hashes.txt")
        hcstat2_path = f"{hash_file}.hcstat2"
        Path(hcstat2_path).touch()

        with patch("subprocess.Popen") as mock_popen:
            mock_process = MagicMock()
            mock_process.wait.return_value = None
            mock_popen.return_value = mock_process

            main.hcatMarkovBruteForce("1000", hash_file, 1, 7)

            call_args = mock_popen.call_args[0][0]
            assert "--markov-hcstat2" in call_args
            assert hcstat2_path in call_args
            assert "--increment" in call_args
            assert "--increment-min=1" in call_args
            assert "--increment-max=7" in call_args


class TestHcatMarkovTrain:
    """Test hcatMarkovTrain wrapper function."""

    def test_success_with_output(self, tmp_path: Path) -> None:
        """Training succeeds when output file is non-empty."""
        from hate_crack import main

        source_file = str(tmp_path / "source.txt")
        source_file_path = Path(source_file)
        source_file_path.write_text("password1\npassword2\n")

        hash_file = str(tmp_path / "hashes.txt")
        hcstat2_path = f"{hash_file}.hcstat2"

        with patch("subprocess.Popen") as mock_popen:
            mock_process = MagicMock()
            mock_process.wait.return_value = None
            mock_popen.return_value = mock_process

            with patch("os.path.isfile", return_value=True):
                with patch("os.path.getsize", return_value=1024):
                    result = main.hcatMarkovTrain(source_file, hash_file)

            assert result is True
