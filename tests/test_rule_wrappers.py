"""Tests for rules_cleanup and rules_optimize subprocess wrappers in main.py."""
import subprocess
from unittest.mock import MagicMock, mock_open, patch

import pytest


def _load_main():
    import importlib
    import os
    import sys

    os.environ.setdefault("HATE_CRACK_SKIP_INIT", "1")
    if "hate_crack.main" in sys.modules:
        return sys.modules["hate_crack.main"]
    return importlib.import_module("hate_crack.main")


class TestRulesCleanupWrapper:
    def test_runs_cleanup_binary_with_file_io(self, tmp_path):
        main = _load_main()
        infile = tmp_path / "input.rule"
        infile.write_text("l\nu\n")
        outfile = tmp_path / "output.rule"

        fake_result = MagicMock()
        fake_result.returncode = 0

        with patch("subprocess.run", return_value=fake_result) as mock_run:
            result = main.rules_cleanup(str(infile), str(outfile))

        assert result is True
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        cmd = call_args[0][0]
        assert cmd[0].endswith("cleanup-rules.bin")

    def test_returns_false_on_nonzero_exit(self, tmp_path):
        main = _load_main()
        infile = tmp_path / "input.rule"
        infile.write_text("l\n")
        outfile = tmp_path / "output.rule"

        fake_result = MagicMock()
        fake_result.returncode = 1

        with patch("subprocess.run", return_value=fake_result):
            result = main.rules_cleanup(str(infile), str(outfile))

        assert result is False

    def test_binary_path_uses_hate_path(self, tmp_path):
        main = _load_main()
        infile = tmp_path / "input.rule"
        infile.write_text("l\n")
        outfile = tmp_path / "output.rule"

        fake_result = MagicMock()
        fake_result.returncode = 0

        with patch("subprocess.run", return_value=fake_result) as mock_run:
            main.rules_cleanup(str(infile), str(outfile))

        cmd = mock_run.call_args[0][0]
        expected_suffix = "hashcat-utils/bin/cleanup-rules.bin"
        assert cmd[0].endswith(expected_suffix), f"Expected path ending with {expected_suffix}, got {cmd[0]}"


class TestRulesOptimizeWrapper:
    def test_runs_optimize_binary_with_file_io(self, tmp_path):
        main = _load_main()
        infile = tmp_path / "input.rule"
        infile.write_text("l\nu\n")
        outfile = tmp_path / "output.rule"

        fake_result = MagicMock()
        fake_result.returncode = 0

        with patch("subprocess.run", return_value=fake_result) as mock_run:
            result = main.rules_optimize(str(infile), str(outfile))

        assert result is True
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        cmd = call_args[0][0]
        assert cmd[0].endswith("rules_optimize.bin")

    def test_returns_false_on_nonzero_exit(self, tmp_path):
        main = _load_main()
        infile = tmp_path / "input.rule"
        infile.write_text("l\n")
        outfile = tmp_path / "output.rule"

        fake_result = MagicMock()
        fake_result.returncode = 1

        with patch("subprocess.run", return_value=fake_result):
            result = main.rules_optimize(str(infile), str(outfile))

        assert result is False

    def test_binary_path_uses_hate_path(self, tmp_path):
        main = _load_main()
        infile = tmp_path / "input.rule"
        infile.write_text("l\n")
        outfile = tmp_path / "output.rule"

        fake_result = MagicMock()
        fake_result.returncode = 0

        with patch("subprocess.run", return_value=fake_result) as mock_run:
            main.rules_optimize(str(infile), str(outfile))

        cmd = mock_run.call_args[0][0]
        expected_suffix = "hashcat-utils/bin/rules_optimize.bin"
        assert cmd[0].endswith(expected_suffix), f"Expected path ending with {expected_suffix}, got {cmd[0]}"
