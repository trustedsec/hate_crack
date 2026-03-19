import os
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def main_module(hc_module):
    """Return the underlying hate_crack.main module for direct patching."""
    return hc_module._main


class TestHcatPermute:
    def test_uses_permute_bin(self, main_module, tmp_path):
        wl = tmp_path / "words.txt"
        wl.write_text("abc\n")
        hash_file = str(tmp_path / "hashes.txt")
        permute_bin_dir = tmp_path / "hashcat-utils" / "bin"
        permute_bin_dir.mkdir(parents=True)
        permute_bin = permute_bin_dir / "permute.bin"
        permute_bin.touch()

        mock_permute_proc = MagicMock()
        mock_permute_proc.stdout = MagicMock()
        mock_permute_proc.wait.return_value = None

        mock_hashcat_proc = MagicMock()
        mock_hashcat_proc.wait.return_value = None
        mock_hashcat_proc.pid = 99

        with patch.object(main_module, "hate_path", str(tmp_path)), \
             patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "generate_session_id", return_value="sess1"), \
             patch.object(main_module, "lineCount", return_value=0), \
             patch.object(main_module, "hcatHashCracked", 0, create=True), \
             patch("hate_crack.main.subprocess.Popen") as mock_popen:
            mock_popen.side_effect = [mock_permute_proc, mock_hashcat_proc]
            main_module.hcatPermute("1000", hash_file, str(wl))

        assert mock_popen.call_count == 2
        first_call_args = mock_popen.call_args_list[0][0][0]
        assert "permute.bin" in str(first_call_args)

    def test_pipes_permute_stdout_to_hashcat_stdin(self, main_module, tmp_path):
        wl = tmp_path / "words.txt"
        wl.write_text("abc\n")
        hash_file = str(tmp_path / "hashes.txt")
        permute_bin_dir = tmp_path / "hashcat-utils" / "bin"
        permute_bin_dir.mkdir(parents=True)
        (permute_bin_dir / "permute.bin").touch()

        mock_permute_proc = MagicMock()
        mock_permute_proc.stdout = MagicMock()
        mock_permute_proc.wait.return_value = None

        mock_hashcat_proc = MagicMock()
        mock_hashcat_proc.wait.return_value = None
        mock_hashcat_proc.pid = 99

        with patch.object(main_module, "hate_path", str(tmp_path)), \
             patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "generate_session_id", return_value="sess1"), \
             patch.object(main_module, "lineCount", return_value=0), \
             patch.object(main_module, "hcatHashCracked", 0, create=True), \
             patch("hate_crack.main.subprocess.Popen") as mock_popen:
            mock_popen.side_effect = [mock_permute_proc, mock_hashcat_proc]
            main_module.hcatPermute("1000", hash_file, str(wl))

        # Second call (hashcat) should use permute_proc.stdout as stdin
        second_call_kwargs = mock_popen.call_args_list[1][1]
        assert second_call_kwargs.get("stdin") == mock_permute_proc.stdout

    def test_hashcat_cmd_includes_hash_type_and_file(self, main_module, tmp_path):
        wl = tmp_path / "words.txt"
        wl.write_text("abc\n")
        hash_file = str(tmp_path / "hashes.txt")
        permute_bin_dir = tmp_path / "hashcat-utils" / "bin"
        permute_bin_dir.mkdir(parents=True)
        (permute_bin_dir / "permute.bin").touch()

        mock_permute_proc = MagicMock()
        mock_permute_proc.stdout = MagicMock()
        mock_permute_proc.wait.return_value = None

        mock_hashcat_proc = MagicMock()
        mock_hashcat_proc.wait.return_value = None
        mock_hashcat_proc.pid = 99

        with patch.object(main_module, "hate_path", str(tmp_path)), \
             patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "generate_session_id", return_value="sess1"), \
             patch.object(main_module, "lineCount", return_value=0), \
             patch.object(main_module, "hcatHashCracked", 0, create=True), \
             patch("hate_crack.main.subprocess.Popen") as mock_popen:
            mock_popen.side_effect = [mock_permute_proc, mock_hashcat_proc]
            main_module.hcatPermute("1000", hash_file, str(wl))

        hashcat_cmd = mock_popen.call_args_list[1][0][0]
        assert "hashcat" in hashcat_cmd
        assert "-m" in hashcat_cmd
        assert "1000" in hashcat_cmd
        assert hash_file in hashcat_cmd

    def test_keyboard_interrupt_kills_both_processes(self, main_module, tmp_path):
        wl = tmp_path / "words.txt"
        wl.write_text("abc\n")
        hash_file = str(tmp_path / "hashes.txt")
        permute_bin_dir = tmp_path / "hashcat-utils" / "bin"
        permute_bin_dir.mkdir(parents=True)
        (permute_bin_dir / "permute.bin").touch()

        mock_permute_proc = MagicMock()
        mock_permute_proc.stdout = MagicMock()
        mock_permute_proc.wait.return_value = None

        mock_hashcat_proc = MagicMock()
        mock_hashcat_proc.wait.side_effect = KeyboardInterrupt()
        mock_hashcat_proc.pid = 99

        with patch.object(main_module, "hate_path", str(tmp_path)), \
             patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "generate_session_id", return_value="sess1"), \
             patch.object(main_module, "lineCount", return_value=0), \
             patch.object(main_module, "hcatHashCracked", 0, create=True), \
             patch("hate_crack.main.subprocess.Popen") as mock_popen:
            mock_popen.side_effect = [mock_permute_proc, mock_hashcat_proc]
            main_module.hcatPermute("1000", hash_file, str(wl))

        mock_hashcat_proc.kill.assert_called_once()
        mock_permute_proc.kill.assert_called_once()

    def test_missing_permute_bin_prints_error(self, main_module, tmp_path, capsys):
        wl = tmp_path / "words.txt"
        wl.write_text("abc\n")
        hash_file = str(tmp_path / "hashes.txt")
        # No permute.bin created

        with patch.object(main_module, "hate_path", str(tmp_path)):
            main_module.hcatPermute("1000", hash_file, str(wl))

        captured = capsys.readouterr()
        assert "permute.bin" in captured.out

    def test_missing_wordlist_prints_error(self, main_module, tmp_path, capsys):
        hash_file = str(tmp_path / "hashes.txt")
        permute_bin_dir = tmp_path / "hashcat-utils" / "bin"
        permute_bin_dir.mkdir(parents=True)
        (permute_bin_dir / "permute.bin").touch()

        with patch.object(main_module, "hate_path", str(tmp_path)):
            main_module.hcatPermute("1000", hash_file, "/nonexistent/words.txt")

        captured = capsys.readouterr()
        assert "not found" in captured.out.lower() or "error" in captured.out.lower()
