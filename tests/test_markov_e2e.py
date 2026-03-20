"""End-to-end tests for markov brute force attack flow."""

import gzip
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


class TestMarkovE2E:
    """End-to-end tests for complete markov attack workflow."""

    def test_markov_training_plain_text(self, tmp_path: Path) -> None:
        """Test markov training with plain text wordlist."""
        from hate_crack import main

        # Setup paths
        main.hate_path = Path(__file__).resolve().parents[1]
        main.hcatHcstat2genBin = "hcstat2gen.bin"
        bin_path = main.hate_path / "hashcat-utils" / "bin" / "hcstat2gen.bin"
        if not bin_path.is_file():
            pytest.skip(f"hcstat2gen.bin not compiled: {bin_path}")

        # Create test wordlist
        wordlist = tmp_path / "wordlist.txt"
        wordlist.write_text("\n".join(["password", "123456", "admin", "letmein", "qwerty"]))

        # Create test hash file
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text("dummy")

        # Run markov training
        result = main.hcatMarkovTrain(str(wordlist), str(hash_file))

        # Verify result
        assert result is True, "Markov training should succeed"

        hcstat2_path = Path(str(hash_file) + ".hcstat2")
        assert hcstat2_path.exists(), ".hcstat2 file should be created"
        assert hcstat2_path.stat().st_size > 0, ".hcstat2 file should not be empty"

    def test_markov_training_gzipped(self, tmp_path: Path) -> None:
        """Test markov training with gzipped wordlist."""
        from hate_crack import main

        # Setup paths
        main.hate_path = Path(__file__).resolve().parents[1]
        main.hcatHcstat2genBin = "hcstat2gen.bin"
        bin_path = main.hate_path / "hashcat-utils" / "bin" / "hcstat2gen.bin"
        if not bin_path.is_file():
            pytest.skip(f"hcstat2gen.bin not compiled: {bin_path}")

        # Create test wordlist (gzipped)
        wordlist_plain = tmp_path / "wordlist.txt"
        wordlist_plain.write_text("\n".join(["password", "123456", "admin", "letmein", "qwerty"]))

        wordlist_gz = tmp_path / "wordlist.txt.gz"
        with open(wordlist_plain, "rb") as f_in:
            with gzip.open(wordlist_gz, "wb") as f_out:
                f_out.write(f_in.read())

        # Create test hash file
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text("dummy")

        # Run markov training with gzipped wordlist
        result = main.hcatMarkovTrain(str(wordlist_gz), str(hash_file))

        # Verify result
        assert result is True, "Markov training with gzipped input should succeed"

        hcstat2_path = Path(str(hash_file) + ".hcstat2")
        assert hcstat2_path.exists(), ".hcstat2 file should be created from gzipped wordlist"
        assert hcstat2_path.stat().st_size > 0, ".hcstat2 file should not be empty"

    def test_markov_brute_force_handler_use_existing_table(self, tmp_path: Path) -> None:
        """Test handler when .hcstat2 table already exists."""
        from hate_crack.attacks import markov_brute_force

        # Setup context
        ctx = MagicMock()
        hash_file = str(tmp_path / "hashes.txt")
        ctx.hcatHashFile = hash_file
        ctx.hcatHashType = "1000"
        ctx.list_wordlist_files.return_value = ["rockyou.txt"]
        ctx.hcatWordlists = str(tmp_path / "wordlists")

        # Create existing .hcstat2 file
        hcstat2_path = f"{hash_file}.hcstat2"
        Path(hcstat2_path).write_text("mock_hcstat2_data")

        # User chooses to use existing table
        with patch("builtins.input", side_effect=["1", "1", "7"]):
            markov_brute_force(ctx)

        # Verify training was NOT called (using existing)
        ctx.hcatMarkovTrain.assert_not_called()
        # Verify brute force WAS called
        ctx.hcatMarkovBruteForce.assert_called_once()
        args = ctx.hcatMarkovBruteForce.call_args[0]
        assert args[0] == "1000"  # hash type
        assert args[1] == hash_file  # hash file
        assert args[2] == 1  # min length
        assert args[3] == 7  # max length

    def test_markov_brute_force_handler_generate_new(self, tmp_path: Path) -> None:
        """Test handler when user chooses to generate new table."""
        from hate_crack.attacks import markov_brute_force

        # Setup context
        ctx = MagicMock()
        hash_file = str(tmp_path / "hashes.txt")
        ctx.hcatHashFile = hash_file
        ctx.hcatHashType = "1000"
        ctx.hcatMarkovTrain.return_value = True
        ctx.list_wordlist_files.return_value = ["rockyou.txt"]
        ctx.hcatWordlists = str(tmp_path / "wordlists")

        # Create existing .hcstat2 file
        hcstat2_path = f"{hash_file}.hcstat2"
        Path(hcstat2_path).write_text("old_data")

        # User chooses to regenerate and select first wordlist
        with patch("builtins.input", side_effect=["2", "1", "2", "8"]):
            markov_brute_force(ctx)

        # Verify training WAS called
        ctx.hcatMarkovTrain.assert_called_once()
        # Verify brute force WAS called
        ctx.hcatMarkovBruteForce.assert_called_once()
        args = ctx.hcatMarkovBruteForce.call_args[0]
        assert args[0] == "1000"
        assert args[2] == 2  # min length
        assert args[3] == 8  # max length

    def test_markov_brute_force_handler_use_cracked_passwords(self, tmp_path: Path) -> None:
        """Test handler when using cracked passwords as training source."""
        from hate_crack.attacks import markov_brute_force

        # Setup context
        ctx = MagicMock()
        hash_file = str(tmp_path / "hashes.txt")
        ctx.hcatHashFile = hash_file
        ctx.hcatHashType = "1000"
        ctx.hcatMarkovTrain.return_value = True
        ctx.list_wordlist_files.return_value = ["rockyou.txt"]
        ctx.hcatWordlists = str(tmp_path / "wordlists")

        # Create .out file with cracked passwords
        out_path = f"{hash_file}.out"
        Path(out_path).write_text("password123\nadmin\nletmein\n")

        # No .hcstat2 table exists, so it goes straight to source picker
        # User selects option 0 (cracked passwords), then min=1, max=6
        with patch("builtins.input", side_effect=["0", "1", "6"]):
            markov_brute_force(ctx)

        # Verify training was called with .out file
        ctx.hcatMarkovTrain.assert_called_once_with(out_path, hash_file)
        # Verify brute force was called
        ctx.hcatMarkovBruteForce.assert_called_once()

    def test_markov_brute_force_handler_cancel(self, tmp_path: Path) -> None:
        """Test handler when user cancels from table menu."""
        from hate_crack.attacks import markov_brute_force

        # Setup context
        ctx = MagicMock()
        hash_file = str(tmp_path / "hashes.txt")
        ctx.hcatHashFile = hash_file
        ctx.hcatHashType = "1000"

        # Create existing .hcstat2 file
        hcstat2_path = f"{hash_file}.hcstat2"
        Path(hcstat2_path).write_text("mock_data")

        # User chooses to cancel
        with patch("builtins.input", return_value="3"):
            markov_brute_force(ctx)

        # Verify nothing was called
        ctx.hcatMarkovTrain.assert_not_called()
        ctx.hcatMarkovBruteForce.assert_not_called()

    def test_markov_brute_force_handler_no_table_requires_training(self, tmp_path: Path) -> None:
        """Test handler when no table exists - training is required."""
        from hate_crack.attacks import markov_brute_force

        # Setup context
        ctx = MagicMock()
        hash_file = str(tmp_path / "hashes.txt")
        ctx.hcatHashFile = hash_file
        ctx.hcatHashType = "1000"
        ctx.hcatMarkovTrain.return_value = True
        ctx.list_wordlist_files.return_value = ["rockyou.txt"]
        ctx.hcatWordlists = str(tmp_path / "wordlists")

        # No .hcstat2 file exists
        hcstat2_path = f"{hash_file}.hcstat2"
        assert not Path(hcstat2_path).exists()

        # No .out file exists, so only wordlists shown
        # User selects first wordlist (option 1), min=3, max=9
        with patch("builtins.input", side_effect=["1", "3", "9"]):
            markov_brute_force(ctx)

        # Verify training was called
        ctx.hcatMarkovTrain.assert_called_once()
        # Verify brute force was called with correct parameters
        ctx.hcatMarkovBruteForce.assert_called_once()
        args = ctx.hcatMarkovBruteForce.call_args[0]
        assert args[0] == "1000"
        assert args[2] == 3  # min length
        assert args[3] == 9  # max length

    def test_markov_brute_force_handler_training_fails(self, tmp_path: Path) -> None:
        """Test handler when training fails."""
        from hate_crack.attacks import markov_brute_force

        # Setup context
        ctx = MagicMock()
        hash_file = str(tmp_path / "hashes.txt")
        ctx.hcatHashFile = hash_file
        ctx.hcatHashType = "1000"
        ctx.hcatMarkovTrain.return_value = False  # Training fails
        ctx.list_wordlist_files.return_value = ["rockyou.txt"]
        ctx.hcatWordlists = str(tmp_path / "wordlists")

        # No existing table
        with patch("builtins.input", side_effect=["1"]):
            markov_brute_force(ctx)

        # Verify training was called
        ctx.hcatMarkovTrain.assert_called_once()
        # Verify brute force was NOT called (training failed)
        ctx.hcatMarkovBruteForce.assert_not_called()
