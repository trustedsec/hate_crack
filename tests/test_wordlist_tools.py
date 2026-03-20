import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from hate_crack.attacks import (
    wordlist_cut_substring,
    wordlist_filter_charclass_exclude,
    wordlist_filter_charclass_include,
    wordlist_filter_length,
    wordlist_shard,
    wordlist_split_by_length,
    wordlist_subtract_words,
    wordlist_tools_submenu,
)


def _make_ctx():
    ctx = MagicMock()
    ctx.wordlist_filter_len.return_value = True
    ctx.wordlist_filter_req_include.return_value = True
    ctx.wordlist_filter_req_exclude.return_value = True
    ctx.wordlist_cutb.return_value = True
    ctx.wordlist_splitlen.return_value = True
    ctx.wordlist_subtract.return_value = True
    ctx.wordlist_subtract_single.return_value = True
    ctx.wordlist_gate.return_value = True
    return ctx


class TestWordlistFilterLength:
    def test_calls_wordlist_filter_len(self, tmp_path):
        ctx = _make_ctx()
        infile = tmp_path / "in.txt"
        infile.write_text("test\n")
        outfile = tmp_path / "out.txt"
        ctx.select_file_with_autocomplete.side_effect = [str(infile), str(outfile)]
        with patch("builtins.input", side_effect=["4", "8"]):
            wordlist_filter_length(ctx)
        ctx.wordlist_filter_len.assert_called_once_with(str(infile), str(outfile), 4, 8)

    def test_rejects_nonexistent_infile(self, tmp_path):
        ctx = _make_ctx()
        ctx.select_file_with_autocomplete.return_value = "/nonexistent/file.txt"
        wordlist_filter_length(ctx)
        ctx.wordlist_filter_len.assert_not_called()

    def test_rejects_empty_outfile(self, tmp_path):
        ctx = _make_ctx()
        infile = tmp_path / "in.txt"
        infile.write_text("test\n")
        ctx.select_file_with_autocomplete.side_effect = [str(infile), ""]
        wordlist_filter_length(ctx)
        ctx.wordlist_filter_len.assert_not_called()

    def test_prints_success_message(self, tmp_path, capsys):
        ctx = _make_ctx()
        infile = tmp_path / "in.txt"
        infile.write_text("test\n")
        outfile = tmp_path / "out.txt"
        ctx.select_file_with_autocomplete.side_effect = [str(infile), str(outfile)]
        with patch("builtins.input", side_effect=["4", "8"]):
            wordlist_filter_length(ctx)
        out = capsys.readouterr().out
        assert "success" in out.lower() or "wrote" in out.lower() or str(outfile) in out

    def test_prints_failure_message(self, tmp_path, capsys):
        ctx = _make_ctx()
        ctx.wordlist_filter_len.return_value = False
        infile = tmp_path / "in.txt"
        infile.write_text("test\n")
        outfile = tmp_path / "out.txt"
        ctx.select_file_with_autocomplete.side_effect = [str(infile), str(outfile)]
        with patch("builtins.input", side_effect=["4", "8"]):
            wordlist_filter_length(ctx)
        out = capsys.readouterr().out
        assert "fail" in out.lower() or "error" in out.lower() or "!" in out


class TestWordlistFilterCharclassInclude:
    def test_calls_wordlist_filter_req_include(self, tmp_path):
        ctx = _make_ctx()
        infile = tmp_path / "in.txt"
        infile.write_text("test\n")
        outfile = tmp_path / "out.txt"
        ctx.select_file_with_autocomplete.side_effect = [str(infile), str(outfile)]
        with patch("builtins.input", side_effect=["7"]):
            wordlist_filter_charclass_include(ctx)
        ctx.wordlist_filter_req_include.assert_called_once_with(str(infile), str(outfile), 7)

    def test_rejects_nonexistent_infile(self, tmp_path):
        ctx = _make_ctx()
        ctx.select_file_with_autocomplete.return_value = "/nonexistent/file.txt"
        wordlist_filter_charclass_include(ctx)
        ctx.wordlist_filter_req_include.assert_not_called()


class TestWordlistFilterCharclassExclude:
    def test_calls_wordlist_filter_req_exclude(self, tmp_path):
        ctx = _make_ctx()
        infile = tmp_path / "in.txt"
        infile.write_text("test\n")
        outfile = tmp_path / "out.txt"
        ctx.select_file_with_autocomplete.side_effect = [str(infile), str(outfile)]
        with patch("builtins.input", side_effect=["8"]):
            wordlist_filter_charclass_exclude(ctx)
        ctx.wordlist_filter_req_exclude.assert_called_once_with(str(infile), str(outfile), 8)

    def test_rejects_nonexistent_infile(self, tmp_path):
        ctx = _make_ctx()
        ctx.select_file_with_autocomplete.return_value = "/nonexistent/file.txt"
        wordlist_filter_charclass_exclude(ctx)
        ctx.wordlist_filter_req_exclude.assert_not_called()


class TestWordlistCutSubstring:
    def test_calls_wordlist_cutb_with_length(self, tmp_path):
        ctx = _make_ctx()
        infile = tmp_path / "in.txt"
        infile.write_text("test\n")
        outfile = tmp_path / "out.txt"
        ctx.select_file_with_autocomplete.side_effect = [str(infile), str(outfile)]
        with patch("builtins.input", side_effect=["2", "4"]):
            wordlist_cut_substring(ctx)
        ctx.wordlist_cutb.assert_called_once_with(str(infile), str(outfile), 2, 4)

    def test_calls_wordlist_cutb_without_length(self, tmp_path):
        ctx = _make_ctx()
        infile = tmp_path / "in.txt"
        infile.write_text("test\n")
        outfile = tmp_path / "out.txt"
        ctx.select_file_with_autocomplete.side_effect = [str(infile), str(outfile)]
        with patch("builtins.input", side_effect=["2", ""]):
            wordlist_cut_substring(ctx)
        ctx.wordlist_cutb.assert_called_once_with(str(infile), str(outfile), 2, None)

    def test_rejects_nonexistent_infile(self, tmp_path):
        ctx = _make_ctx()
        ctx.select_file_with_autocomplete.return_value = "/nonexistent/file.txt"
        wordlist_cut_substring(ctx)
        ctx.wordlist_cutb.assert_not_called()


class TestWordlistSplitByLength:
    def test_calls_wordlist_splitlen(self, tmp_path):
        ctx = _make_ctx()
        infile = tmp_path / "in.txt"
        infile.write_text("test\n")
        outdir = tmp_path / "split"
        ctx.select_file_with_autocomplete.side_effect = [str(infile), str(outdir)]
        wordlist_split_by_length(ctx)
        ctx.wordlist_splitlen.assert_called_once_with(str(infile), str(outdir))

    def test_creates_outdir_if_missing(self, tmp_path):
        ctx = _make_ctx()
        infile = tmp_path / "in.txt"
        infile.write_text("test\n")
        outdir = tmp_path / "split" / "nested"
        ctx.select_file_with_autocomplete.side_effect = [str(infile), str(outdir)]
        wordlist_split_by_length(ctx)
        assert outdir.exists()

    def test_rejects_nonexistent_infile(self, tmp_path):
        ctx = _make_ctx()
        ctx.select_file_with_autocomplete.return_value = "/nonexistent/file.txt"
        wordlist_split_by_length(ctx)
        ctx.wordlist_splitlen.assert_not_called()


class TestWordlistSubtractWords:
    def test_single_remove_calls_wordlist_subtract_single(self, tmp_path):
        ctx = _make_ctx()
        infile = tmp_path / "in.txt"
        infile.write_text("word1\n")
        removefile = tmp_path / "remove.txt"
        removefile.write_text("word1\n")
        outfile = tmp_path / "out.txt"
        ctx.select_file_with_autocomplete.side_effect = [str(infile), str(removefile), str(outfile)]
        with patch("builtins.input", side_effect=["1"]):
            wordlist_subtract_words(ctx)
        ctx.wordlist_subtract_single.assert_called_once_with(str(infile), str(removefile), str(outfile))

    def test_multi_remove_calls_wordlist_subtract(self, tmp_path):
        ctx = _make_ctx()
        infile = tmp_path / "in.txt"
        infile.write_text("word1\nword2\n")
        removefile1 = tmp_path / "remove1.txt"
        removefile1.write_text("word1\n")
        removefile2 = tmp_path / "remove2.txt"
        removefile2.write_text("word2\n")
        outfile = tmp_path / "out.txt"
        ctx.select_file_with_autocomplete.side_effect = [
            str(infile),
            str(outfile),
            f"{removefile1},{removefile2}",
        ]
        with patch("builtins.input", side_effect=["2"]):
            wordlist_subtract_words(ctx)
        ctx.wordlist_subtract.assert_called_once_with(
            str(infile), str(outfile), str(removefile1), str(removefile2)
        )

    def test_single_remove_rejects_nonexistent_infile(self, tmp_path):
        ctx = _make_ctx()
        ctx.select_file_with_autocomplete.return_value = "/nonexistent.txt"
        with patch("builtins.input", side_effect=["1"]):
            wordlist_subtract_words(ctx)
        ctx.wordlist_subtract_single.assert_not_called()


class TestWordlistShard:
    def test_calls_wordlist_gate_with_correct_args(self, tmp_path):
        ctx = _make_ctx()
        infile = tmp_path / "in.txt"
        infile.write_text("word1\nword2\nword3\n")
        outfile = tmp_path / "shard.txt"
        ctx.select_file_with_autocomplete.side_effect = [str(infile), str(outfile)]
        with patch("builtins.input", side_effect=["3", "0"]):
            wordlist_shard(ctx)
        ctx.wordlist_gate.assert_called_once_with(str(infile), str(outfile), 3, 0)

    def test_rejects_offset_gte_mod(self, tmp_path):
        ctx = _make_ctx()
        infile = tmp_path / "in.txt"
        infile.write_text("word1\n")
        outfile = tmp_path / "shard.txt"
        ctx.select_file_with_autocomplete.side_effect = [str(infile), str(outfile)]
        with patch("builtins.input", side_effect=["3", "3"]):
            wordlist_shard(ctx)
        ctx.wordlist_gate.assert_not_called()

    def test_rejects_nonexistent_infile(self, tmp_path):
        ctx = _make_ctx()
        ctx.select_file_with_autocomplete.return_value = "/nonexistent/file.txt"
        wordlist_shard(ctx)
        ctx.wordlist_gate.assert_not_called()

    def test_rejects_mod_less_than_2(self, tmp_path):
        ctx = _make_ctx()
        infile = tmp_path / "in.txt"
        infile.write_text("word1\n")
        outfile = tmp_path / "shard.txt"
        ctx.select_file_with_autocomplete.side_effect = [str(infile), str(outfile)]
        with patch("builtins.input", side_effect=["1", "0"]):
            wordlist_shard(ctx)
        ctx.wordlist_gate.assert_not_called()


class TestWordlistToolsSubmenu:
    def test_submenu_dispatches_to_filter_length(self):
        ctx = _make_ctx()
        with patch("hate_crack.attacks.wordlist_filter_length") as mock_fn, \
             patch("hate_crack.attacks.interactive_menu", side_effect=["1", "99"]):
            wordlist_tools_submenu(ctx)
        mock_fn.assert_called_once_with(ctx)

    def test_submenu_dispatches_to_filter_charclass_include(self):
        ctx = _make_ctx()
        with patch("hate_crack.attacks.wordlist_filter_charclass_include") as mock_fn, \
             patch("hate_crack.attacks.interactive_menu", side_effect=["2", "99"]):
            wordlist_tools_submenu(ctx)
        mock_fn.assert_called_once_with(ctx)

    def test_submenu_dispatches_to_filter_charclass_exclude(self):
        ctx = _make_ctx()
        with patch("hate_crack.attacks.wordlist_filter_charclass_exclude") as mock_fn, \
             patch("hate_crack.attacks.interactive_menu", side_effect=["3", "99"]):
            wordlist_tools_submenu(ctx)
        mock_fn.assert_called_once_with(ctx)

    def test_submenu_dispatches_to_cut_substring(self):
        ctx = _make_ctx()
        with patch("hate_crack.attacks.wordlist_cut_substring") as mock_fn, \
             patch("hate_crack.attacks.interactive_menu", side_effect=["4", "99"]):
            wordlist_tools_submenu(ctx)
        mock_fn.assert_called_once_with(ctx)

    def test_submenu_dispatches_to_split_by_length(self):
        ctx = _make_ctx()
        with patch("hate_crack.attacks.wordlist_split_by_length") as mock_fn, \
             patch("hate_crack.attacks.interactive_menu", side_effect=["5", "99"]):
            wordlist_tools_submenu(ctx)
        mock_fn.assert_called_once_with(ctx)

    def test_submenu_dispatches_to_subtract_words(self):
        ctx = _make_ctx()
        with patch("hate_crack.attacks.wordlist_subtract_words") as mock_fn, \
             patch("hate_crack.attacks.interactive_menu", side_effect=["6", "99"]):
            wordlist_tools_submenu(ctx)
        mock_fn.assert_called_once_with(ctx)

    def test_submenu_dispatches_to_shard(self):
        ctx = _make_ctx()
        with patch("hate_crack.attacks.wordlist_shard") as mock_fn, \
             patch("hate_crack.attacks.interactive_menu", side_effect=["7", "99"]):
            wordlist_tools_submenu(ctx)
        mock_fn.assert_called_once_with(ctx)

    def test_submenu_exits_on_99(self):
        ctx = _make_ctx()
        with patch("hate_crack.attacks.interactive_menu", return_value="99"):
            wordlist_tools_submenu(ctx)

    def test_submenu_exits_on_none(self):
        ctx = _make_ctx()
        with patch("hate_crack.attacks.interactive_menu", return_value=None):
            wordlist_tools_submenu(ctx)
