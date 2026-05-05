import os
import shutil
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from hate_crack.attacks import (
    wordlist_cut_substring,
    wordlist_filter_charclass_exclude,
    wordlist_filter_charclass_include,
    wordlist_filter_length,
    wordlist_optimize,
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
    ctx.wordlist_optimize.return_value = True
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

    def test_submenu_dispatches_to_optimize(self):
        ctx = _make_ctx()
        with patch("hate_crack.attacks.wordlist_optimize") as mock_fn, \
             patch("hate_crack.attacks.interactive_menu", side_effect=["8", "99"]):
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


class TestWordlistOptimize:
    def test_happy_path(self, tmp_path, capsys):
        ctx = _make_ctx()
        wl_a = tmp_path / "a.txt"
        wl_a.write_text("word1\n")
        wl_b = tmp_path / "b.txt"
        wl_b.write_text("word2\n")
        outdir = str(tmp_path / "out")
        ctx.select_file_with_autocomplete.side_effect = [
            f"{wl_a},{wl_b}",
            outdir,
        ]
        with (
            patch("hate_crack.attacks.os.path.isfile", return_value=True),
            patch("hate_crack.attacks.os.path.isdir", return_value=False),
        ):
            wordlist_optimize(ctx)
        ctx.wordlist_optimize.assert_called_once_with(
            [str(wl_a), str(wl_b)], outdir
        )
        out = capsys.readouterr().out
        assert outdir in out

    def test_directory_expansion(self, tmp_path, capsys):
        ctx = _make_ctx()
        wl_dir = str(tmp_path / "wls")
        outdir = str(tmp_path / "out")
        ctx.select_file_with_autocomplete.side_effect = [wl_dir, outdir]
        ctx.list_wordlist_files.return_value = ["a.txt", "b.txt"]
        with (
            patch("hate_crack.attacks.os.path.isfile", return_value=False),
            patch("hate_crack.attacks.os.path.isdir", return_value=True),
        ):
            wordlist_optimize(ctx)
        ctx.wordlist_optimize.assert_called_once_with(
            [os.path.join(wl_dir, "a.txt"), os.path.join(wl_dir, "b.txt")], outdir
        )

    def test_empty_directory_rejection(self, tmp_path, capsys):
        ctx = _make_ctx()
        wl_dir = str(tmp_path / "wls")
        ctx.select_file_with_autocomplete.return_value = wl_dir
        ctx.list_wordlist_files.return_value = []
        with (
            patch("hate_crack.attacks.os.path.isfile", return_value=False),
            patch("hate_crack.attacks.os.path.isdir", return_value=True),
        ):
            wordlist_optimize(ctx)
        out = capsys.readouterr().out
        assert "No wordlist files found" in out
        ctx.wordlist_optimize.assert_not_called()

    def test_empty_input_rejection(self, capsys):
        ctx = _make_ctx()
        ctx.select_file_with_autocomplete.return_value = ","
        wordlist_optimize(ctx)
        out = capsys.readouterr().out
        assert "No input wordlists provided" in out
        ctx.wordlist_optimize.assert_not_called()

    def test_blank_input_rejection(self, capsys):
        ctx = _make_ctx()
        ctx.select_file_with_autocomplete.return_value = ""
        wordlist_optimize(ctx)
        out = capsys.readouterr().out
        assert "No input wordlists provided" in out
        ctx.wordlist_optimize.assert_not_called()

    def test_missing_file_rejection(self, tmp_path, capsys):
        ctx = _make_ctx()
        existing = tmp_path / "a.txt"
        existing.write_text("word\n")
        ctx.select_file_with_autocomplete.return_value = f"{existing},/nonexistent/missing.txt"
        with (
            patch("hate_crack.attacks.os.path.isfile", side_effect=lambda p: p == str(existing)),
            patch("hate_crack.attacks.os.path.isdir", return_value=False),
        ):
            wordlist_optimize(ctx)
        out = capsys.readouterr().out
        assert "Not found" in out
        ctx.wordlist_optimize.assert_not_called()

    def test_empty_outdir_rejection(self, tmp_path, capsys):
        ctx = _make_ctx()
        wl = tmp_path / "a.txt"
        wl.write_text("word\n")
        ctx.select_file_with_autocomplete.side_effect = [str(wl), ""]
        with (
            patch("hate_crack.attacks.os.path.isfile", return_value=True),
            patch("hate_crack.attacks.os.path.isdir", return_value=False),
        ):
            wordlist_optimize(ctx)
        out = capsys.readouterr().out
        assert "Output directory cannot be empty" in out
        ctx.wordlist_optimize.assert_not_called()

    def test_failure_path(self, tmp_path, capsys):
        ctx = _make_ctx()
        ctx.wordlist_optimize.return_value = False
        wl = tmp_path / "a.txt"
        wl.write_text("word\n")
        outdir = str(tmp_path / "out")
        ctx.select_file_with_autocomplete.side_effect = [str(wl), outdir]
        with (
            patch("hate_crack.attacks.os.path.isfile", return_value=True),
            patch("hate_crack.attacks.os.path.isdir", return_value=False),
        ):
            wordlist_optimize(ctx)
        out = capsys.readouterr().out
        assert "Optimization failed" in out


class TestWordlistOptimizeWorker:
    """Tests for the wordlist_optimize worker function in hate_crack.main.

    All binary-calling helpers (wordlist_splitlen, wordlist_subtract_single)
    are mocked so no real binaries are required.
    """

    def _get_worker(self):
        import importlib
        import sys
        # Import the module fresh; SKIP_INIT is already active via conftest.
        mod = sys.modules.get("hate_crack.main")
        if mod is None:
            mod = importlib.import_module("hate_crack.main")
        return mod.wordlist_optimize

    # ------------------------------------------------------------------
    # (a) fast-path: empty outdir → wordlist_splitlen called directly
    # ------------------------------------------------------------------
    def test_fast_path_empty_outdir(self, tmp_path):
        worker = self._get_worker()
        wl = tmp_path / "words.txt"
        wl.write_text("word\n")
        outdir = tmp_path / "out"
        outdir.mkdir()

        with patch("hate_crack.main.wordlist_splitlen", return_value=True) as mock_split, \
             patch("hate_crack.main.wordlist_subtract") as mock_sub:
            result = worker([str(wl)], str(outdir))

        assert result is True
        mock_split.assert_called_once_with(str(wl), str(outdir))
        mock_sub.assert_not_called()

    # ------------------------------------------------------------------
    # (b) merge-path: existing per-length file → wordlist_subtract + append
    # ------------------------------------------------------------------
    def test_merge_path_existing_length_file(self, tmp_path):
        worker = self._get_worker()
        wl_a = tmp_path / "a.txt"
        wl_a.write_text("word1\n")
        wl_b = tmp_path / "b.txt"
        wl_b.write_text("word2\n")
        outdir = tmp_path / "out"
        outdir.mkdir()

        # After the first wordlist, outdir contains "len5.txt"
        len_file = outdir / "len5.txt"
        len_file.write_text("word1\n")

        # The second call goes through the merge path for the tmp subdir.
        # wordlist_splitlen for wl_b produces "len5.txt" in a temp dir.
        # wordlist_subtract produces a non-empty output → append.
        new_words = b"word2\n"

        def fake_splitlen(infile: str, outdir_arg: str) -> bool:
            # Write a len5.txt into wherever we are called to write to
            (Path(outdir_arg) / "len5.txt").write_bytes(b"word2\n")
            return True

        def fake_subtract(src: str, out: str, *remove_files: str) -> bool:
            # Simulate: the diff is "word2\n" — write to outfile (second arg)
            with open(out, "wb") as f:
                f.write(new_words)
            return True

        with patch("hate_crack.main.wordlist_splitlen", side_effect=fake_splitlen), \
             patch("hate_crack.main.wordlist_subtract", side_effect=fake_subtract):
            # outdir is already non-empty (len_file exists), so wl_b goes to merge path
            result = worker([str(wl_b)], str(outdir))

        assert result is True
        # len5.txt should now contain the appended new words
        contents = len_file.read_bytes()
        assert b"word2\n" in contents

    # ------------------------------------------------------------------
    # (c) new length file in subsequent wordlist is just copied
    # ------------------------------------------------------------------
    def test_new_length_file_is_copied(self, tmp_path):
        worker = self._get_worker()
        wl_b = tmp_path / "b.txt"
        wl_b.write_text("verylongword\n")
        outdir = tmp_path / "out"
        outdir.mkdir()

        # Seed outdir with one length file (len5) so it is non-empty
        (outdir / "len5.txt").write_text("hello\n")

        # The second wordlist produces only "len12.txt" (no clash)
        def fake_splitlen(infile: str, outdir_arg: str) -> bool:
            (Path(outdir_arg) / "len12.txt").write_bytes(b"verylongword\n")
            return True

        with patch("hate_crack.main.wordlist_splitlen", side_effect=fake_splitlen), \
             patch("hate_crack.main.wordlist_subtract") as mock_sub:
            result = worker([str(wl_b)], str(outdir))

        assert result is True
        assert (outdir / "len12.txt").exists()
        assert (outdir / "len12.txt").read_bytes() == b"verylongword\n"
        mock_sub.assert_not_called()

    # ------------------------------------------------------------------
    # (d) wordlist_splitlen failure returns False
    # ------------------------------------------------------------------
    def test_splitlen_failure_returns_false(self, tmp_path):
        worker = self._get_worker()
        wl = tmp_path / "words.txt"
        wl.write_text("word\n")
        outdir = tmp_path / "out"
        outdir.mkdir()

        with patch("hate_crack.main.wordlist_splitlen", return_value=False):
            result = worker([str(wl)], str(outdir))

        assert result is False

    # ------------------------------------------------------------------
    # (e) wordlist_subtract failure returns False
    # ------------------------------------------------------------------
    def test_subtract_failure_returns_false(self, tmp_path):
        worker = self._get_worker()
        wl_b = tmp_path / "b.txt"
        wl_b.write_text("word2\n")
        outdir = tmp_path / "out"
        outdir.mkdir()

        # Seed outdir so it's non-empty and has a clashing length file
        (outdir / "len5.txt").write_text("word1\n")

        def fake_splitlen(infile: str, outdir_arg: str) -> bool:
            (Path(outdir_arg) / "len5.txt").write_bytes(b"word2\n")
            return True

        with patch("hate_crack.main.wordlist_splitlen", side_effect=fake_splitlen), \
             patch("hate_crack.main.wordlist_subtract", return_value=False):
            result = worker([str(wl_b)], str(outdir))

        assert result is False

    # ------------------------------------------------------------------
    # (f) missing input file is skipped and processing continues
    # ------------------------------------------------------------------
    def test_missing_input_skipped_processing_continues(self, tmp_path, capsys):
        worker = self._get_worker()
        good_wl = tmp_path / "good.txt"
        good_wl.write_text("word\n")
        missing = str(tmp_path / "nonexistent.txt")
        outdir = tmp_path / "out"
        outdir.mkdir()

        call_count = {"n": 0}

        def fake_splitlen(infile: str, outdir_arg: str) -> bool:
            call_count["n"] += 1
            return True

        with patch("hate_crack.main.wordlist_splitlen", side_effect=fake_splitlen):
            result = worker([missing, str(good_wl)], str(outdir))

        assert result is True
        # Only the good wordlist should have been processed
        assert call_count["n"] == 1
        out = capsys.readouterr().out
        assert "Skipping" in out
