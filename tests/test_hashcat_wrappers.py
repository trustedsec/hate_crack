from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def main_module(hc_module):
    """Return the underlying hate_crack.main module for direct patching."""
    return hc_module._main


def _make_mock_proc(wait_side_effect=None):
    proc = MagicMock()
    if wait_side_effect is not None:
        proc.wait.side_effect = wait_side_effect
    else:
        proc.wait.return_value = None
    proc.pid = 12345
    return proc


def _common_patches(main_module, tmp_path):
    """Return a list of patch context managers for the most common globals."""
    hash_file = str(tmp_path / "hashes.txt")
    return [
        patch.object(main_module, "hcatBin", "hashcat"),
        patch.object(main_module, "hcatTuning", ""),
        patch.object(main_module, "hcatPotfilePath", ""),
        patch.object(main_module, "hcatHashFile", hash_file, create=True),
        patch.object(main_module, "generate_session_id", return_value="test_session"),
    ]


class TestHcatBruteForce:
    def test_contains_attack_mode_3(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        mock_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mock_popen, \
             patch.object(main_module, "lineCount", return_value=0):
            main_module.hcatBruteForce("1000", hash_file, 1, 7)

        mock_popen.assert_called_once()
        cmd = mock_popen.call_args[0][0]
        assert "-a" in cmd
        assert "3" in cmd

    def test_increment_flags(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        mock_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mock_popen, \
             patch.object(main_module, "lineCount", return_value=0):
            main_module.hcatBruteForce("1000", hash_file, 3, 9)
            cmd = mock_popen.call_args[0][0]

        assert "--increment" in cmd
        assert "--increment-min=3" in cmd
        assert "--increment-max=9" in cmd

    def test_keyboard_interrupt_kills_process(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        mock_proc = _make_mock_proc(wait_side_effect=KeyboardInterrupt())

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc), \
             patch.object(main_module, "lineCount", return_value=0):
            main_module.hcatBruteForce("1000", hash_file, 1, 7)

        mock_proc.kill.assert_called_once()

    def test_hash_type_and_file_in_cmd(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        mock_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mock_popen, \
             patch.object(main_module, "lineCount", return_value=0):
            main_module.hcatBruteForce("500", hash_file, 1, 8)

        cmd = mock_popen.call_args[0][0]
        assert "-m" in cmd
        assert "500" in cmd
        assert hash_file in cmd


class TestHcatQuickDictionary:
    def test_wordlist_added_to_cmd(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        wordlist = str(tmp_path / "words.txt")
        mock_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mock_popen, \
             patch("hate_crack.main._add_debug_mode_for_rules", side_effect=lambda c: c), \
             patch("hate_crack.main._debug_cmd"):
            main_module.hcatQuickDictionary("1000", hash_file, "", wordlist)

        cmd = mock_popen.call_args[0][0]
        assert wordlist in cmd

    def test_loopback_flag_added(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        wordlist = str(tmp_path / "words.txt")
        mock_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mock_popen, \
             patch("hate_crack.main._add_debug_mode_for_rules", side_effect=lambda c: c), \
             patch("hate_crack.main._debug_cmd"):
            main_module.hcatQuickDictionary("1000", hash_file, "", wordlist, loopback=True)

        cmd = mock_popen.call_args[0][0]
        assert "--loopback" in cmd

    def test_no_loopback_by_default(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        wordlist = str(tmp_path / "words.txt")
        mock_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mock_popen, \
             patch("hate_crack.main._add_debug_mode_for_rules", side_effect=lambda c: c), \
             patch("hate_crack.main._debug_cmd"):
            main_module.hcatQuickDictionary("1000", hash_file, "", wordlist)

        cmd = mock_popen.call_args[0][0]
        assert "--loopback" not in cmd

    def test_chains_added_when_provided(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        wordlist = str(tmp_path / "words.txt")
        mock_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mock_popen, \
             patch("hate_crack.main._add_debug_mode_for_rules", side_effect=lambda c: c), \
             patch("hate_crack.main._debug_cmd"):
            main_module.hcatQuickDictionary(
                "1000", hash_file, "-r /fake/rule.rule", wordlist
            )

        cmd = mock_popen.call_args[0][0]
        assert "-r" in cmd
        assert "/fake/rule.rule" in cmd

    def test_list_of_wordlists_all_added(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        wl1 = str(tmp_path / "words1.txt")
        wl2 = str(tmp_path / "words2.txt")
        mock_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mock_popen, \
             patch("hate_crack.main._add_debug_mode_for_rules", side_effect=lambda c: c), \
             patch("hate_crack.main._debug_cmd"):
            main_module.hcatQuickDictionary("1000", hash_file, "", [wl1, wl2])

        cmd = mock_popen.call_args[0][0]
        assert wl1 in cmd
        assert wl2 in cmd


class TestHcatCombination:
    def test_contains_attack_mode_1(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        wl1 = tmp_path / "words1.txt"
        wl2 = tmp_path / "words2.txt"
        wl1.write_text("word1\n")
        wl2.write_text("word2\n")
        mock_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "hcatWordlists", str(tmp_path)), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mock_popen, \
             patch.object(main_module, "lineCount", return_value=0), \
             patch.object(main_module, "hcatHashCracked", 0, create=True):
            main_module.hcatCombination(
                "1000", hash_file, wordlists=[str(wl1), str(wl2)]
            )

        mock_popen.assert_called_once()
        cmd = mock_popen.call_args[0][0]
        assert "-a" in cmd
        assert "1" in cmd

    def test_aborts_with_fewer_than_two_wordlists(self, main_module, tmp_path, capsys):
        hash_file = str(tmp_path / "hashes.txt")
        wl1 = tmp_path / "words1.txt"
        wl1.write_text("word1\n")
        mock_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "hcatWordlists", str(tmp_path)), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mock_popen:
            main_module.hcatCombination("1000", hash_file, wordlists=[str(wl1)])

        mock_popen.assert_not_called()
        captured = capsys.readouterr()
        assert "requires at least 2" in captured.out


class TestHcatHybrid:
    def test_contains_attack_mode_6_or_7(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        wl = tmp_path / "words.txt"
        wl.write_text("word\n")
        mock_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "hcatWordlists", str(tmp_path)), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mock_popen, \
             patch.object(main_module, "lineCount", return_value=0), \
             patch.object(main_module, "hcatHashCracked", 0, create=True):
            main_module.hcatHybrid("1000", hash_file, wordlists=[str(wl)])

        assert mock_popen.call_count >= 1
        all_cmds = [c[0][0] for c in mock_popen.call_args_list]
        modes_used = set()
        for cmd in all_cmds:
            if "-a" in cmd:
                idx = cmd.index("-a")
                modes_used.add(cmd[idx + 1])
        assert modes_used & {"6", "7"}, f"Expected mode 6 or 7 in cmds, got modes: {modes_used}"

    def test_aborts_when_no_valid_wordlists(self, main_module, tmp_path, capsys):
        hash_file = str(tmp_path / "hashes.txt")
        mock_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "hcatWordlists", str(tmp_path)), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mock_popen:
            main_module.hcatHybrid(
                "1000", hash_file, wordlists=["/nonexistent/wordlist.txt"]
            )

        mock_popen.assert_not_called()
        captured = capsys.readouterr()
        assert "No valid wordlists" in captured.out


class TestHcatPathwellBruteForce:
    def test_popen_called(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        mock_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "hate_path", str(tmp_path)), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mock_popen:
            main_module.hcatPathwellBruteForce("1000", hash_file)

        mock_popen.assert_called_once()

    def test_attack_mode_3_in_cmd(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        mock_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "hate_path", str(tmp_path)), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mock_popen:
            main_module.hcatPathwellBruteForce("1000", hash_file)

        cmd = mock_popen.call_args[0][0]
        assert "-a" in cmd
        assert "3" in cmd

    def test_pathwell_mask_in_cmd(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        mock_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "hate_path", str(tmp_path)), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mock_popen:
            main_module.hcatPathwellBruteForce("1000", hash_file)

        cmd = mock_popen.call_args[0][0]
        assert any("pathwell.hcmask" in arg for arg in cmd)


class TestHcatPrince:
    def test_two_popen_calls_for_pipe(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        prince_base = tmp_path / "prince_base.txt"
        prince_base.write_text("password\n")
        prince_dir = tmp_path / "princeprocessor"
        prince_dir.mkdir()
        (prince_dir / "pp64.bin").touch()

        mock_prince_proc = MagicMock()
        mock_prince_proc.stdout = MagicMock()
        mock_prince_proc.wait.return_value = None
        mock_hashcat_proc = MagicMock()
        mock_hashcat_proc.wait.return_value = None
        mock_hashcat_proc.pid = 12345

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "hate_path", str(tmp_path)), \
             patch.object(main_module, "hcatPrinceBin", "pp64.bin"), \
             patch.object(main_module, "hcatPrinceBaseList", [str(prince_base)]), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch.object(main_module, "get_rule_path", return_value="/fake/prince_optimized.rule"), \
             patch("hate_crack.main._add_debug_mode_for_rules", side_effect=lambda c: c), \
             patch("hate_crack.main.subprocess.Popen") as mock_popen:
            mock_popen.side_effect = [mock_prince_proc, mock_hashcat_proc]
            main_module.hcatPrince("1000", hash_file)

        assert mock_popen.call_count == 2

    def test_prince_binary_first_call(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        prince_base = tmp_path / "prince_base.txt"
        prince_base.write_text("password\n")
        prince_dir = tmp_path / "princeprocessor"
        prince_dir.mkdir()
        pp_bin = prince_dir / "pp64.bin"
        pp_bin.touch()

        mock_prince_proc = MagicMock()
        mock_prince_proc.stdout = MagicMock()
        mock_prince_proc.wait.return_value = None
        mock_hashcat_proc = MagicMock()
        mock_hashcat_proc.wait.return_value = None
        mock_hashcat_proc.pid = 12345

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "hate_path", str(tmp_path)), \
             patch.object(main_module, "hcatPrinceBin", "pp64.bin"), \
             patch.object(main_module, "hcatPrinceBaseList", [str(prince_base)]), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch.object(main_module, "get_rule_path", return_value="/fake/prince_optimized.rule"), \
             patch("hate_crack.main._add_debug_mode_for_rules", side_effect=lambda c: c), \
             patch("hate_crack.main.subprocess.Popen") as mock_popen:
            mock_popen.side_effect = [mock_prince_proc, mock_hashcat_proc]
            main_module.hcatPrince("1000", hash_file)

        prince_cmd = mock_popen.call_args_list[0][0][0]
        assert str(pp_bin) in prince_cmd

    def test_aborts_when_prince_base_missing(self, main_module, tmp_path, capsys):
        hash_file = str(tmp_path / "hashes.txt")

        with patch.object(main_module, "hate_path", str(tmp_path)), \
             patch.object(main_module, "hcatPrinceBin", "pp64.bin"), \
             patch.object(main_module, "hcatPrinceBaseList", ["/nonexistent/base.txt"]), \
             patch.object(main_module, "get_rule_path", return_value="/fake/rule.rule"), \
             patch("hate_crack.main.subprocess.Popen") as mock_popen:
            main_module.hcatPrince("1000", hash_file)

        mock_popen.assert_not_called()
        captured = capsys.readouterr()
        assert "not found" in captured.out


class TestHcatRecycle:
    def test_skipped_when_count_zero(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")

        with patch("hate_crack.main.subprocess.Popen") as mock_popen:
            main_module.hcatRecycle("1000", hash_file, 0)

        mock_popen.assert_not_called()

    def test_popen_called_when_count_nonzero(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        out_file = tmp_path / "hashes.txt.out"
        out_file.write_text("hash1:password1\nhash2:password2\n")
        mock_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "hcatRules", ["best66.rule"]), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch.object(main_module, "get_rule_path", return_value="/fake/best66.rule"), \
             patch("hate_crack.main._write_delimited_field"), \
             patch("hate_crack.main.convert_hex", return_value=["password1", "password2"]), \
             patch("hate_crack.main._add_debug_mode_for_rules", side_effect=lambda c: c), \
             patch("builtins.open", create=True) as mock_open, \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mock_popen:
            mock_open.return_value.__enter__ = MagicMock(return_value=MagicMock())
            mock_open.return_value.__exit__ = MagicMock(return_value=False)
            main_module.hcatRecycle("1000", hash_file, 5)

        assert mock_popen.call_count >= 1

    def test_rule_path_in_cmd_when_count_nonzero(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        mock_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "hcatRules", ["best66.rule"]), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch.object(main_module, "get_rule_path", return_value="/fake/best66.rule"), \
             patch("hate_crack.main._write_delimited_field"), \
             patch("hate_crack.main.convert_hex", return_value=["pass1"]), \
             patch("hate_crack.main._add_debug_mode_for_rules", side_effect=lambda c: c), \
             patch("builtins.open", create=True) as mock_open, \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mock_popen:
            mock_open.return_value.__enter__ = MagicMock(return_value=MagicMock())
            mock_open.return_value.__exit__ = MagicMock(return_value=False)
            main_module.hcatRecycle("1000", hash_file, 3)

        cmd = mock_popen.call_args[0][0]
        assert "-r" in cmd
        assert "/fake/best66.rule" in cmd


class TestHcatGoodMeasure:
    def test_popen_called_at_least_once(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        mock_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "hcatGoodMeasureBaseList", "/fake/base.txt"), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch.object(main_module, "get_rule_path", return_value="/fake/rule.rule"), \
             patch("hate_crack.main._add_debug_mode_for_rules", side_effect=lambda c: c), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mock_popen, \
             patch.object(main_module, "lineCount", return_value=0), \
             patch.object(main_module, "hcatHashCracked", 0, create=True):
            main_module.hcatGoodMeasure("1000", hash_file)

        assert mock_popen.call_count >= 1

    def test_hash_type_in_cmd(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        mock_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "hcatGoodMeasureBaseList", "/fake/base.txt"), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch.object(main_module, "get_rule_path", return_value="/fake/rule.rule"), \
             patch("hate_crack.main._add_debug_mode_for_rules", side_effect=lambda c: c), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mock_popen, \
             patch.object(main_module, "lineCount", return_value=0), \
             patch.object(main_module, "hcatHashCracked", 0, create=True):
            main_module.hcatGoodMeasure("500", hash_file)

        cmd = mock_popen.call_args_list[0][0][0]
        assert "-m" in cmd
        assert "500" in cmd


class TestHcatMiddleCombinator:
    def test_popen_called_at_least_once(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        mock_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "hcatMiddleCombinatorMasks", ["!", "1"]), \
             patch.object(main_module, "hcatMiddleBaseList", "/fake/base.txt"), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mock_popen:
            main_module.hcatMiddleCombinator("1000", hash_file)

        assert mock_popen.call_count >= 1

    def test_attack_mode_1_in_cmd(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        mock_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "hcatMiddleCombinatorMasks", ["!"]), \
             patch.object(main_module, "hcatMiddleBaseList", "/fake/base.txt"), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mock_popen:
            main_module.hcatMiddleCombinator("1000", hash_file)

        cmd = mock_popen.call_args_list[0][0][0]
        assert "-a" in cmd
        assert "1" in cmd


class TestHcatThoroughCombinator:
    def test_popen_called_at_least_once(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        mock_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "hcatThoroughCombinatorMasks", ["!"]), \
             patch.object(main_module, "hcatThoroughBaseList", "/fake/base.txt"), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mock_popen:
            main_module.hcatThoroughCombinator("1000", hash_file)

        assert mock_popen.call_count >= 1


class TestHcatYoloCombination:
    def test_popen_called_once_then_keyboard_interrupt(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        wl_dir = tmp_path / "wordlists"
        wl_dir.mkdir()
        (wl_dir / "words.txt").write_text("word\n")

        mock_proc = MagicMock()
        mock_proc.pid = 12345
        mock_proc.wait.side_effect = KeyboardInterrupt()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "hcatWordlists", str(wl_dir)), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mock_popen:
            main_module.hcatYoloCombination("1000", hash_file)

        assert mock_popen.call_count >= 1
        mock_proc.kill.assert_called()

    def test_attack_mode_1_in_cmd(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        wl_dir = tmp_path / "wordlists"
        wl_dir.mkdir()
        (wl_dir / "words.txt").write_text("word\n")

        mock_proc = MagicMock()
        mock_proc.pid = 12345
        mock_proc.wait.side_effect = KeyboardInterrupt()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "hcatWordlists", str(wl_dir)), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mock_popen:
            main_module.hcatYoloCombination("1000", hash_file)

        cmd = mock_popen.call_args_list[0][0][0]
        assert "-a" in cmd
        assert "1" in cmd


class TestAppendPotfileArg:
    def test_appends_when_potfile_set(self, main_module):
        cmd = ["hashcat", "-m", "1000"]
        with patch.object(main_module, "hcatPotfilePath", "/fake/hashcat.pot"):
            main_module._append_potfile_arg(cmd)
        assert "--potfile-path=/fake/hashcat.pot" in cmd

    def test_no_append_when_empty(self, main_module):
        cmd = ["hashcat", "-m", "1000"]
        with patch.object(main_module, "hcatPotfilePath", ""):
            main_module._append_potfile_arg(cmd)
        assert not any(arg.startswith("--potfile-path") for arg in cmd)

    def test_no_append_when_use_potfile_false(self, main_module):
        cmd = ["hashcat", "-m", "1000"]
        with patch.object(main_module, "hcatPotfilePath", "/fake/hashcat.pot"):
            main_module._append_potfile_arg(cmd, use_potfile_path=False)
        assert not any(arg.startswith("--potfile-path") for arg in cmd)

    def test_explicit_potfile_path_overrides_global(self, main_module):
        cmd = ["hashcat", "-m", "1000"]
        with patch.object(main_module, "hcatPotfilePath", "/global/hashcat.pot"):
            main_module._append_potfile_arg(cmd, potfile_path="/override/custom.pot")
        assert "--potfile-path=/override/custom.pot" in cmd
        assert "--potfile-path=/global/hashcat.pot" not in cmd
