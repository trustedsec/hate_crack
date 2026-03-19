"""Tests for hcatCombinator3 and hcatCombinatorX hashcat wrapper functions."""

from unittest.mock import MagicMock, patch

import pytest


def _make_mock_proc(wait_side_effect=None):
    proc = MagicMock()
    proc.stdout = MagicMock()
    if wait_side_effect is not None:
        proc.wait.side_effect = wait_side_effect
    else:
        proc.wait.return_value = None
    proc.pid = 12345
    return proc


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


class TestHcatCombinator3:
    def test_calls_combinator3_bin_with_three_files(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        wls = []
        for i in range(3):
            p = str(tmp_path / f"w{i}.txt")
            open(p, "w").close()
            wls.append(p)

        combinator_proc = _make_mock_proc()
        hashcat_proc = _make_mock_proc()

        def popen_side_effect(cmd, **kwargs):
            if "combinator3" in str(cmd[0]):
                return combinator_proc
            return hashcat_proc

        with (
            patch.object(main_module, "hcatBin", "hashcat"),
            patch.object(main_module, "hcatTuning", ""),
            patch.object(main_module, "hcatPotfilePath", ""),
            patch.object(main_module, "hcatWordlists", str(tmp_path)),
            patch.object(main_module, "generate_session_id", return_value="sess123"),
            patch.object(main_module, "lineCount", return_value=0),
            patch("hate_crack.main.subprocess.Popen", side_effect=popen_side_effect) as mock_popen,
        ):
            main_module.hcatCombinator3("1000", hash_file, wls)

        calls = mock_popen.call_args_list
        assert len(calls) == 2
        combinator_cmd = calls[0][0][0]
        assert "combinator3" in combinator_cmd[0]
        assert wls[0] in combinator_cmd
        assert wls[1] in combinator_cmd
        assert wls[2] in combinator_cmd

    def test_pipes_stdout_to_hashcat_stdin(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        wls = []
        for i in range(3):
            p = str(tmp_path / f"w{i}.txt")
            open(p, "w").close()
            wls.append(p)

        combinator_proc = _make_mock_proc()
        hashcat_proc = _make_mock_proc()

        def popen_side_effect(cmd, **kwargs):
            if "combinator3" in str(cmd[0]):
                return combinator_proc
            return hashcat_proc

        with (
            patch.object(main_module, "hcatBin", "hashcat"),
            patch.object(main_module, "hcatTuning", ""),
            patch.object(main_module, "hcatPotfilePath", ""),
            patch.object(main_module, "hcatWordlists", str(tmp_path)),
            patch.object(main_module, "generate_session_id", return_value="sess123"),
            patch.object(main_module, "lineCount", return_value=0),
            patch("hate_crack.main.subprocess.Popen", side_effect=popen_side_effect) as mock_popen,
        ):
            main_module.hcatCombinator3("1000", hash_file, wls)

        calls = mock_popen.call_args_list
        hashcat_call_kwargs = calls[1][1]
        assert hashcat_call_kwargs.get("stdin") == combinator_proc.stdout

    def test_aborts_with_fewer_than_3_wordlists(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        wl1 = str(tmp_path / "w1.txt")
        wl2 = str(tmp_path / "w2.txt")
        for p in [wl1, wl2]:
            open(p, "w").close()

        with patch("hate_crack.main.subprocess.Popen") as mock_popen:
            main_module.hcatCombinator3("1000", hash_file, [wl1, wl2])

        mock_popen.assert_not_called()

    def test_keyboard_interrupt_kills_both_processes(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        wls = []
        for i in range(3):
            p = str(tmp_path / f"w{i}.txt")
            open(p, "w").close()
            wls.append(p)

        combinator_proc = _make_mock_proc()
        hashcat_proc = _make_mock_proc(wait_side_effect=KeyboardInterrupt())

        def popen_side_effect(cmd, **kwargs):
            if "combinator3" in str(cmd[0]):
                return combinator_proc
            return hashcat_proc

        with (
            patch.object(main_module, "hcatBin", "hashcat"),
            patch.object(main_module, "hcatTuning", ""),
            patch.object(main_module, "hcatPotfilePath", ""),
            patch.object(main_module, "hcatWordlists", str(tmp_path)),
            patch.object(main_module, "generate_session_id", return_value="sess123"),
            patch.object(main_module, "lineCount", return_value=0),
            patch("hate_crack.main.subprocess.Popen", side_effect=popen_side_effect),
        ):
            main_module.hcatCombinator3("1000", hash_file, wls)

        hashcat_proc.kill.assert_called_once()
        combinator_proc.kill.assert_called_once()


class TestHcatCombinatorX:
    def test_calls_combinatorX_bin_with_file_flags(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        wls = []
        for i in range(2):
            p = str(tmp_path / f"w{i}.txt")
            open(p, "w").close()
            wls.append(p)

        combinator_proc = _make_mock_proc()
        hashcat_proc = _make_mock_proc()

        def popen_side_effect(cmd, **kwargs):
            if "combinatorX" in str(cmd[0]):
                return combinator_proc
            return hashcat_proc

        with (
            patch.object(main_module, "hcatBin", "hashcat"),
            patch.object(main_module, "hcatTuning", ""),
            patch.object(main_module, "hcatPotfilePath", ""),
            patch.object(main_module, "hcatWordlists", str(tmp_path)),
            patch.object(main_module, "generate_session_id", return_value="sess123"),
            patch.object(main_module, "lineCount", return_value=0),
            patch("hate_crack.main.subprocess.Popen", side_effect=popen_side_effect) as mock_popen,
        ):
            main_module.hcatCombinatorX("1000", hash_file, wls)

        calls = mock_popen.call_args_list
        assert len(calls) == 2
        combinator_cmd = calls[0][0][0]
        assert "combinatorX" in combinator_cmd[0]
        assert "--file1" in combinator_cmd
        assert "--file2" in combinator_cmd

    def test_passes_sepfill_when_separator_given(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        wls = []
        for i in range(2):
            p = str(tmp_path / f"w{i}.txt")
            open(p, "w").close()
            wls.append(p)

        combinator_proc = _make_mock_proc()
        hashcat_proc = _make_mock_proc()

        def popen_side_effect(cmd, **kwargs):
            if "combinatorX" in str(cmd[0]):
                return combinator_proc
            return hashcat_proc

        with (
            patch.object(main_module, "hcatBin", "hashcat"),
            patch.object(main_module, "hcatTuning", ""),
            patch.object(main_module, "hcatPotfilePath", ""),
            patch.object(main_module, "hcatWordlists", str(tmp_path)),
            patch.object(main_module, "generate_session_id", return_value="sess123"),
            patch.object(main_module, "lineCount", return_value=0),
            patch("hate_crack.main.subprocess.Popen", side_effect=popen_side_effect) as mock_popen,
        ):
            main_module.hcatCombinatorX("1000", hash_file, wls, separator="-")

        combinator_cmd = mock_popen.call_args_list[0][0][0]
        assert "--sepFill" in combinator_cmd
        sep_idx = combinator_cmd.index("--sepFill")
        assert combinator_cmd[sep_idx + 1] == "-"

    def test_no_sepfill_when_separator_is_none(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        wls = []
        for i in range(2):
            p = str(tmp_path / f"w{i}.txt")
            open(p, "w").close()
            wls.append(p)

        combinator_proc = _make_mock_proc()
        hashcat_proc = _make_mock_proc()

        def popen_side_effect(cmd, **kwargs):
            if "combinatorX" in str(cmd[0]):
                return combinator_proc
            return hashcat_proc

        with (
            patch.object(main_module, "hcatBin", "hashcat"),
            patch.object(main_module, "hcatTuning", ""),
            patch.object(main_module, "hcatPotfilePath", ""),
            patch.object(main_module, "hcatWordlists", str(tmp_path)),
            patch.object(main_module, "generate_session_id", return_value="sess123"),
            patch.object(main_module, "lineCount", return_value=0),
            patch("hate_crack.main.subprocess.Popen", side_effect=popen_side_effect) as mock_popen,
        ):
            main_module.hcatCombinatorX("1000", hash_file, wls, separator=None)

        combinator_cmd = mock_popen.call_args_list[0][0][0]
        assert "--sepFill" not in combinator_cmd

    def test_aborts_with_fewer_than_2_wordlists(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        wl1 = str(tmp_path / "w1.txt")
        open(wl1, "w").close()

        with patch("hate_crack.main.subprocess.Popen") as mock_popen:
            main_module.hcatCombinatorX("1000", hash_file, [wl1])

        mock_popen.assert_not_called()

    def test_supports_up_to_8_wordlists(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        wls = []
        for i in range(8):
            p = str(tmp_path / f"w{i}.txt")
            open(p, "w").close()
            wls.append(p)

        combinator_proc = _make_mock_proc()
        hashcat_proc = _make_mock_proc()

        def popen_side_effect(cmd, **kwargs):
            if "combinatorX" in str(cmd[0]):
                return combinator_proc
            return hashcat_proc

        with (
            patch.object(main_module, "hcatBin", "hashcat"),
            patch.object(main_module, "hcatTuning", ""),
            patch.object(main_module, "hcatPotfilePath", ""),
            patch.object(main_module, "hcatWordlists", str(tmp_path)),
            patch.object(main_module, "generate_session_id", return_value="sess123"),
            patch.object(main_module, "lineCount", return_value=0),
            patch("hate_crack.main.subprocess.Popen", side_effect=popen_side_effect) as mock_popen,
        ):
            main_module.hcatCombinatorX("1000", hash_file, wls)

        combinator_cmd = mock_popen.call_args_list[0][0][0]
        for i in range(1, 9):
            assert f"--file{i}" in combinator_cmd

    def test_keyboard_interrupt_kills_both_processes(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        wls = []
        for i in range(2):
            p = str(tmp_path / f"w{i}.txt")
            open(p, "w").close()
            wls.append(p)

        combinator_proc = _make_mock_proc()
        hashcat_proc = _make_mock_proc(wait_side_effect=KeyboardInterrupt())

        def popen_side_effect(cmd, **kwargs):
            if "combinatorX" in str(cmd[0]):
                return combinator_proc
            return hashcat_proc

        with (
            patch.object(main_module, "hcatBin", "hashcat"),
            patch.object(main_module, "hcatTuning", ""),
            patch.object(main_module, "hcatPotfilePath", ""),
            patch.object(main_module, "hcatWordlists", str(tmp_path)),
            patch.object(main_module, "generate_session_id", return_value="sess123"),
            patch.object(main_module, "lineCount", return_value=0),
            patch("hate_crack.main.subprocess.Popen", side_effect=popen_side_effect),
        ):
            main_module.hcatCombinatorX("1000", hash_file, wls)

        hashcat_proc.kill.assert_called_once()
        combinator_proc.kill.assert_called_once()
