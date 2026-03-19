import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch, call
import importlib.util

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CLI_SPEC = importlib.util.spec_from_file_location(
    "hate_crack_cli", PROJECT_ROOT / "hate_crack.py"
)
CLI_MODULE = importlib.util.module_from_spec(CLI_SPEC)
CLI_SPEC.loader.exec_module(CLI_MODULE)


def _get_main():
    import hate_crack.main as m
    return m


class TestWordlistFilterLenWrapper:
    def test_calls_len_bin_with_correct_args(self, tmp_path):
        m = _get_main()
        infile = tmp_path / "in.txt"
        infile.write_text("test\n")
        outfile = tmp_path / "out.txt"
        with patch("hate_crack.main.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = m.wordlist_filter_len(str(infile), str(outfile), 4, 8)
        assert result is True
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[1] == "4"
        assert cmd[2] == "8"
        assert "len.bin" in cmd[0]

    def test_returns_false_on_nonzero_returncode(self, tmp_path):
        m = _get_main()
        infile = tmp_path / "in.txt"
        infile.write_text("test\n")
        outfile = tmp_path / "out.txt"
        with patch("hate_crack.main.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            result = m.wordlist_filter_len(str(infile), str(outfile), 4, 8)
        assert result is False


class TestWordlistFilterReqIncludeWrapper:
    def test_calls_req_include_bin(self, tmp_path):
        m = _get_main()
        infile = tmp_path / "in.txt"
        infile.write_text("test\n")
        outfile = tmp_path / "out.txt"
        with patch("hate_crack.main.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = m.wordlist_filter_req_include(str(infile), str(outfile), 7)
        assert result is True
        cmd = mock_run.call_args[0][0]
        assert "req-include.bin" in cmd[0]
        assert cmd[1] == "7"


class TestWordlistFilterReqExcludeWrapper:
    def test_calls_req_exclude_bin(self, tmp_path):
        m = _get_main()
        infile = tmp_path / "in.txt"
        infile.write_text("test\n")
        outfile = tmp_path / "out.txt"
        with patch("hate_crack.main.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = m.wordlist_filter_req_exclude(str(infile), str(outfile), 8)
        assert result is True
        cmd = mock_run.call_args[0][0]
        assert "req-exclude.bin" in cmd[0]
        assert cmd[1] == "8"


class TestWordlistCutbWrapper:
    def test_calls_cutb_bin_with_offset_and_length(self, tmp_path):
        m = _get_main()
        infile = tmp_path / "in.txt"
        infile.write_text("test\n")
        outfile = tmp_path / "out.txt"
        with patch("hate_crack.main.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = m.wordlist_cutb(str(infile), str(outfile), 2, 4)
        assert result is True
        cmd = mock_run.call_args[0][0]
        assert "cutb.bin" in cmd[0]
        assert cmd[1] == "2"
        assert cmd[2] == "4"

    def test_calls_cutb_bin_without_length(self, tmp_path):
        m = _get_main()
        infile = tmp_path / "in.txt"
        infile.write_text("test\n")
        outfile = tmp_path / "out.txt"
        with patch("hate_crack.main.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = m.wordlist_cutb(str(infile), str(outfile), 2, None)
        assert result is True
        cmd = mock_run.call_args[0][0]
        assert "cutb.bin" in cmd[0]
        assert cmd[1] == "2"
        assert len(cmd) == 2  # only binary + offset, no length arg


class TestWordlistSplitlenWrapper:
    def test_calls_splitlen_bin(self, tmp_path):
        m = _get_main()
        infile = tmp_path / "in.txt"
        infile.write_text("test\n")
        outdir = tmp_path / "split"
        with patch("hate_crack.main.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = m.wordlist_splitlen(str(infile), str(outdir))
        assert result is True
        cmd = mock_run.call_args[0][0]
        assert "splitlen.bin" in cmd[0]
        assert cmd[1] == str(outdir)


class TestWordlistSubtractWrapper:
    def test_calls_rli_bin_with_multiple_files(self, tmp_path):
        m = _get_main()
        infile = tmp_path / "in.txt"
        infile.write_text("word1\n")
        outfile = tmp_path / "out.txt"
        remove1 = tmp_path / "r1.txt"
        remove1.write_text("word1\n")
        remove2 = tmp_path / "r2.txt"
        remove2.write_text("word2\n")
        with patch("hate_crack.main.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = m.wordlist_subtract(str(infile), str(outfile), str(remove1), str(remove2))
        assert result is True
        cmd = mock_run.call_args[0][0]
        assert "rli.bin" in cmd[0]
        assert cmd[1] == str(infile)
        assert cmd[2] == str(outfile)
        assert str(remove1) in cmd
        assert str(remove2) in cmd


class TestWordlistSubtractSingleWrapper:
    def test_calls_rli2_bin(self, tmp_path):
        m = _get_main()
        infile = tmp_path / "in.txt"
        infile.write_text("word1\n")
        removefile = tmp_path / "remove.txt"
        removefile.write_text("word1\n")
        outfile = tmp_path / "out.txt"
        with patch("hate_crack.main.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = m.wordlist_subtract_single(str(infile), str(removefile), str(outfile))
        assert result is True
        cmd = mock_run.call_args[0][0]
        assert "rli2.bin" in cmd[0]
        assert cmd[1] == str(infile)
        assert cmd[2] == str(removefile)


class TestWordlistGateWrapper:
    def test_calls_gate_bin(self, tmp_path):
        m = _get_main()
        infile = tmp_path / "in.txt"
        infile.write_text("word1\nword2\nword3\n")
        outfile = tmp_path / "shard.txt"
        with patch("hate_crack.main.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = m.wordlist_gate(str(infile), str(outfile), 3, 0)
        assert result is True
        cmd = mock_run.call_args[0][0]
        assert "gate.bin" in cmd[0]
        assert cmd[1] == "3"
        assert cmd[2] == "0"
