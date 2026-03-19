import importlib.util
import os
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from hate_crack.attacks import ngram_attack

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _make_ctx(hash_type="1000", hash_file="/tmp/hashes.txt"):
    ctx = MagicMock()
    ctx.hcatHashType = hash_type
    ctx.hcatHashFile = hash_file
    return ctx


class TestNgramAttack:
    def test_calls_hcatNgramX_with_default_group_size_3(self, tmp_path):
        ctx = _make_ctx()
        corpus = tmp_path / "corpus.txt"
        corpus.write_text("the quick brown fox jumps over\n")
        with patch("builtins.input", side_effect=[str(corpus), ""]):
            ngram_attack(ctx)
        ctx.hcatNgramX.assert_called_once()
        call_args = ctx.hcatNgramX.call_args[0]
        assert call_args[3] == 3

    def test_calls_hcatNgramX_with_custom_group_size(self, tmp_path):
        ctx = _make_ctx()
        corpus = tmp_path / "corpus.txt"
        corpus.write_text("word1 word2 word3 word4\n")
        with patch("builtins.input", side_effect=[str(corpus), "2"]):
            ngram_attack(ctx)
        ctx.hcatNgramX.assert_called_once()
        call_args = ctx.hcatNgramX.call_args[0]
        assert call_args[3] == 2

    def test_rejects_zero_group_size(self, tmp_path):
        ctx = _make_ctx()
        corpus = tmp_path / "corpus.txt"
        corpus.write_text("word1 word2\n")
        with patch("builtins.input", side_effect=[str(corpus), "0"]):
            ngram_attack(ctx)
        ctx.hcatNgramX.assert_not_called()

    def test_rejects_negative_group_size(self, tmp_path):
        ctx = _make_ctx()
        corpus = tmp_path / "corpus.txt"
        corpus.write_text("word1 word2\n")
        with patch("builtins.input", side_effect=[str(corpus), "-1"]):
            ngram_attack(ctx)
        ctx.hcatNgramX.assert_not_called()

    def test_rejects_nonexistent_file(self, tmp_path):
        ctx = _make_ctx()
        corpus = tmp_path / "corpus.txt"
        corpus.write_text("word1 word2\n")
        with patch("builtins.input", side_effect=["/nonexistent.txt", str(corpus), ""]):
            ngram_attack(ctx)
        ctx.hcatNgramX.assert_called_once()

    def test_passes_correct_args_to_hcatNgramX(self, tmp_path):
        ctx = _make_ctx()
        corpus = tmp_path / "corpus.txt"
        corpus.write_text("word1 word2 word3\n")
        with patch("builtins.input", side_effect=[str(corpus), "4"]):
            ngram_attack(ctx)
        ctx.hcatNgramX.assert_called_once_with(
            ctx.hcatHashType, ctx.hcatHashFile, str(corpus), 4
        )


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


def _make_mock_proc(wait_side_effect=None):
    proc = MagicMock()
    if wait_side_effect is not None:
        proc.wait.side_effect = wait_side_effect
    else:
        proc.wait.return_value = None
    proc.pid = 42
    proc.stdout = MagicMock()
    return proc


class TestHcatNgramX:
    def test_passes_filename_and_group_size_to_ngramx(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        corpus = str(tmp_path / "corpus.txt")
        Path(corpus).write_text("word1 word2 word3\n")
        ngram_proc = _make_mock_proc()
        hashcat_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hate_path", str(tmp_path)), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "generate_session_id", return_value="sess"), \
             patch.object(main_module, "lineCount", return_value=0), \
             patch.object(main_module, "hcatHashCracked", 0), \
             patch("hate_crack.main.subprocess.Popen", side_effect=[ngram_proc, hashcat_proc]) as mock_popen:
            main_module.hcatNgramX("1000", hash_file, corpus, 3)

        # First Popen call is ngramX.bin
        first_call_args = mock_popen.call_args_list[0][0][0]
        assert first_call_args[1] == corpus
        assert first_call_args[2] == "3"
        assert "ngramX.bin" in first_call_args[0]

    def test_pipes_ngram_output_to_hashcat(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        corpus = str(tmp_path / "corpus.txt")
        Path(corpus).write_text("word1 word2 word3\n")
        ngram_proc = _make_mock_proc()
        hashcat_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hate_path", str(tmp_path)), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "generate_session_id", return_value="sess"), \
             patch.object(main_module, "lineCount", return_value=0), \
             patch.object(main_module, "hcatHashCracked", 0), \
             patch("hate_crack.main.subprocess.Popen", side_effect=[ngram_proc, hashcat_proc]) as mock_popen:
            main_module.hcatNgramX("1000", hash_file, corpus, 3)

        # Second Popen call (hashcat) receives stdin from ngram stdout
        second_call_kwargs = mock_popen.call_args_list[1][1]
        assert second_call_kwargs.get("stdin") == ngram_proc.stdout

    def test_kills_both_processes_on_keyboard_interrupt(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        corpus = str(tmp_path / "corpus.txt")
        Path(corpus).write_text("word1 word2\n")
        ngram_proc = _make_mock_proc(wait_side_effect=KeyboardInterrupt)
        hashcat_proc = _make_mock_proc(wait_side_effect=KeyboardInterrupt)

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hate_path", str(tmp_path)), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "generate_session_id", return_value="sess"), \
             patch.object(main_module, "lineCount", return_value=0), \
             patch.object(main_module, "hcatHashCracked", 0), \
             patch("hate_crack.main.subprocess.Popen", side_effect=[ngram_proc, hashcat_proc]):
            main_module.hcatNgramX("1000", hash_file, corpus, 2)

        hashcat_proc.kill.assert_called_once()
        ngram_proc.kill.assert_called_once()
