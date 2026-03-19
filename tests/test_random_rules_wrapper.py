from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


def _make_mock_proc(wait_side_effect=None):
    proc = MagicMock()
    if wait_side_effect is not None:
        proc.wait.side_effect = wait_side_effect
    else:
        proc.wait.return_value = None
    proc.pid = 12345
    return proc


class TestHcatGenerateRules:
    def test_calls_generate_rules_bin(self, main_module, tmp_path):
        wl = tmp_path / "words.txt"
        wl.write_text("test\n")
        hash_file = str(tmp_path / "hashes.txt")
        mock_proc = _make_mock_proc()
        mock_result = MagicMock()
        mock_result.stdout = "l\nu\nc\n"

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch.object(main_module, "lineCount", return_value=0), \
             patch.object(main_module, "hcatHashCracked", 0), \
             patch("hate_crack.main.subprocess.run", return_value=mock_result) as mock_run, \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc):
            main_module.hcatGenerateRules("1000", hash_file, 100, str(wl))

        run_calls = mock_run.call_args_list
        assert any("generate-rules.bin" in str(c) for c in run_calls)

    def test_calls_hashcat_with_rule_flag(self, main_module, tmp_path):
        wl = tmp_path / "words.txt"
        wl.write_text("test\n")
        hash_file = str(tmp_path / "hashes.txt")
        mock_proc = _make_mock_proc()
        mock_result = MagicMock()
        mock_result.stdout = "l\nu\n"

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch.object(main_module, "lineCount", return_value=0), \
             patch.object(main_module, "hcatHashCracked", 0), \
             patch("hate_crack.main.subprocess.run", return_value=mock_result), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mock_popen:
            main_module.hcatGenerateRules("1000", hash_file, 100, str(wl))

        popen_calls = mock_popen.call_args_list
        assert any("-r" in str(c) for c in popen_calls)

    def test_passes_rule_count_to_generate_rules_bin(self, main_module, tmp_path):
        wl = tmp_path / "words.txt"
        wl.write_text("test\n")
        hash_file = str(tmp_path / "hashes.txt")
        mock_proc = _make_mock_proc()
        mock_result = MagicMock()
        mock_result.stdout = "l\n"

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch.object(main_module, "lineCount", return_value=0), \
             patch.object(main_module, "hcatHashCracked", 0), \
             patch("hate_crack.main.subprocess.run", return_value=mock_result) as mock_run, \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc):
            main_module.hcatGenerateRules("1000", hash_file, 999, str(wl))

        run_calls = mock_run.call_args_list
        generate_call = next(
            (c for c in run_calls if "generate-rules.bin" in str(c)), None
        )
        assert generate_call is not None
        cmd_args = generate_call[0][0]
        assert "999" in cmd_args

    def test_cleans_up_temp_file(self, main_module, tmp_path):
        wl = tmp_path / "words.txt"
        wl.write_text("test\n")
        hash_file = str(tmp_path / "hashes.txt")
        mock_proc = _make_mock_proc()
        mock_result = MagicMock()
        mock_result.stdout = "l\nu\n"
        captured_paths = []

        import os as _os
        original_unlink = _os.unlink

        def capturing_unlink(path):
            captured_paths.append(path)
            original_unlink(path)

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch.object(main_module, "lineCount", return_value=0), \
             patch.object(main_module, "hcatHashCracked", 0), \
             patch("hate_crack.main.subprocess.run", return_value=mock_result), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc), \
             patch("hate_crack.main.os.unlink", side_effect=capturing_unlink):
            main_module.hcatGenerateRules("1000", hash_file, 50, str(wl))

        assert any("hate_crack_random_" in p for p in captured_paths), \
            f"Expected temp file cleanup, got: {captured_paths}"

    def test_keyboard_interrupt_kills_process(self, main_module, tmp_path):
        wl = tmp_path / "words.txt"
        wl.write_text("test\n")
        hash_file = str(tmp_path / "hashes.txt")
        mock_proc = _make_mock_proc(wait_side_effect=KeyboardInterrupt())
        mock_result = MagicMock()
        mock_result.stdout = "l\n"

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "generate_session_id", return_value="test_session"), \
             patch.object(main_module, "lineCount", return_value=0), \
             patch.object(main_module, "hcatHashCracked", 0), \
             patch("hate_crack.main.subprocess.run", return_value=mock_result), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc):
            main_module.hcatGenerateRules("1000", hash_file, 10, str(wl))

        mock_proc.kill.assert_called_once()

    def test_sets_hcatGenerateRulesCount(self, main_module, tmp_path):
        wl = tmp_path / "words.txt"
        wl.write_text("test\n")
        hash_file = str(tmp_path / "hashes.txt")
        mock_proc = _make_mock_proc()
        mock_result = MagicMock()
        mock_result.stdout = "l\nu\n"

        # patch.object won't patch reads of module-level globals; set directly
        original_cracked = main_module.hcatHashCracked
        main_module.hcatHashCracked = 2
        try:
            with patch.object(main_module, "hcatBin", "hashcat"), \
                 patch.object(main_module, "hcatTuning", ""), \
                 patch.object(main_module, "hcatPotfilePath", ""), \
                 patch.object(main_module, "generate_session_id", return_value="test_session"), \
                 patch.object(main_module, "lineCount", return_value=5), \
                 patch("hate_crack.main.subprocess.run", return_value=mock_result), \
                 patch("hate_crack.main.subprocess.Popen", return_value=mock_proc):
                main_module.hcatGenerateRules("1000", hash_file, 10, str(wl))
        finally:
            main_module.hcatHashCracked = original_cracked

        assert main_module.hcatGenerateRulesCount == 3  # 5 - 2
