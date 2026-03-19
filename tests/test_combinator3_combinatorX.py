import os
from unittest.mock import MagicMock, patch

import pytest

from hate_crack.attacks import combinator3_crack, combinator_submenu, combinatorX_crack


def _make_ctx(hash_type="1000", hash_file="/tmp/hashes.txt"):
    ctx = MagicMock()
    ctx.hcatHashType = hash_type
    ctx.hcatHashFile = hash_file
    return ctx


class TestCombinator3Crack:
    def test_calls_hcatCombinator3_with_three_wordlists(self, tmp_path):
        ctx = _make_ctx()
        ctx.hcatWordlists = str(tmp_path)
        for name in ["a.txt", "b.txt", "c.txt"]:
            (tmp_path / name).write_text("word\n")
        ctx._resolve_wordlist_path.side_effect = lambda p, base: p
        wl_arg = f"{tmp_path}/a.txt,{tmp_path}/b.txt,{tmp_path}/c.txt"
        with patch("builtins.input", side_effect=["n", wl_arg]):
            combinator3_crack(ctx)
        ctx.hcatCombinator3.assert_called_once()

    def test_aborts_with_fewer_than_3_wordlists(self, tmp_path):
        ctx = _make_ctx()
        ctx.hcatWordlists = str(tmp_path)
        (tmp_path / "a.txt").write_text("word\n")
        ctx._resolve_wordlist_path.side_effect = lambda p, base: p
        wl_arg = f"{tmp_path}/a.txt,{tmp_path}/a.txt"
        with patch("builtins.input", side_effect=["n", wl_arg]):
            combinator3_crack(ctx)
        ctx.hcatCombinator3.assert_not_called()

    def test_aborts_when_no_wordlists_provided(self, tmp_path):
        ctx = _make_ctx()
        ctx.hcatWordlists = str(tmp_path)
        ctx._resolve_wordlist_path.side_effect = lambda p, base: p
        with patch("builtins.input", side_effect=["n", ""]):
            combinator3_crack(ctx)
        ctx.hcatCombinator3.assert_not_called()

    def test_passes_exactly_3_wordlists(self, tmp_path):
        ctx = _make_ctx()
        ctx.hcatWordlists = str(tmp_path)
        for name in ["a.txt", "b.txt", "c.txt"]:
            (tmp_path / name).write_text("word\n")
        ctx._resolve_wordlist_path.side_effect = lambda p, base: p
        wl_arg = f"{tmp_path}/a.txt,{tmp_path}/b.txt,{tmp_path}/c.txt"
        with patch("builtins.input", side_effect=["n", wl_arg]):
            combinator3_crack(ctx)
        call_args = ctx.hcatCombinator3.call_args
        wordlists = call_args[0][2] if len(call_args[0]) >= 3 else call_args[1].get("wordlists")
        assert len(wordlists) == 3


class TestCombinatorXCrack:
    def test_calls_hcatCombinatorX_with_wordlists(self, tmp_path):
        ctx = _make_ctx()
        ctx.hcatWordlists = str(tmp_path)
        for name in ["a.txt", "b.txt"]:
            (tmp_path / name).write_text("word\n")
        ctx._resolve_wordlist_path.side_effect = lambda p, base: p
        wl_arg = f"{tmp_path}/a.txt,{tmp_path}/b.txt"
        with patch("builtins.input", side_effect=["n", wl_arg, ""]):
            combinatorX_crack(ctx)
        ctx.hcatCombinatorX.assert_called_once()

    def test_passes_separator_to_hcatCombinatorX(self, tmp_path):
        ctx = _make_ctx()
        ctx.hcatWordlists = str(tmp_path)
        for name in ["a.txt", "b.txt"]:
            (tmp_path / name).write_text("word\n")
        ctx._resolve_wordlist_path.side_effect = lambda p, base: p
        wl_arg = f"{tmp_path}/a.txt,{tmp_path}/b.txt"
        with patch("builtins.input", side_effect=["n", wl_arg, "-"]):
            combinatorX_crack(ctx)
        call_args = ctx.hcatCombinatorX.call_args
        # separator may be positional or keyword
        positional_has_sep = len(call_args[0]) >= 4 and call_args[0][3] == "-"
        keyword_has_sep = call_args[1].get("separator") == "-"
        assert positional_has_sep or keyword_has_sep

    def test_aborts_with_fewer_than_2_wordlists(self, tmp_path):
        ctx = _make_ctx()
        ctx.hcatWordlists = str(tmp_path)
        (tmp_path / "a.txt").write_text("word\n")
        ctx._resolve_wordlist_path.side_effect = lambda p, base: p
        wl_arg = f"{tmp_path}/a.txt"
        with patch("builtins.input", side_effect=["n", wl_arg, ""]):
            combinatorX_crack(ctx)
        ctx.hcatCombinatorX.assert_not_called()

    def test_no_separator_when_empty_input(self, tmp_path):
        ctx = _make_ctx()
        ctx.hcatWordlists = str(tmp_path)
        for name in ["a.txt", "b.txt"]:
            (tmp_path / name).write_text("word\n")
        ctx._resolve_wordlist_path.side_effect = lambda p, base: p
        wl_arg = f"{tmp_path}/a.txt,{tmp_path}/b.txt"
        with patch("builtins.input", side_effect=["n", wl_arg, ""]):
            combinatorX_crack(ctx)
        call_args = ctx.hcatCombinatorX.call_args
        positional_sep = call_args[0][3] if len(call_args[0]) >= 4 else None
        keyword_sep = call_args[1].get("separator")
        # separator should be None or empty string when nothing entered
        assert positional_sep in (None, "") and keyword_sep in (None, "")


class TestCombinatorSubmenuUpdated:
    def test_submenu_has_combinator3_option(self):
        ctx = _make_ctx()
        with patch("hate_crack.attacks.combinator3_crack") as mock_c3, patch(
            "hate_crack.attacks.interactive_menu", side_effect=["5", "99"]
        ):
            combinator_submenu(ctx)
        mock_c3.assert_called_once_with(ctx)

    def test_submenu_has_combinatorX_option(self):
        ctx = _make_ctx()
        with patch("hate_crack.attacks.combinatorX_crack") as mock_cx, patch(
            "hate_crack.attacks.interactive_menu", side_effect=["6", "99"]
        ):
            combinator_submenu(ctx)
        mock_cx.assert_called_once_with(ctx)

    def test_submenu_items_include_new_attacks(self):
        """Verify the submenu item list advertises options 5 and 6."""
        ctx = _make_ctx()
        captured_items = []

        def capture_menu(items, **kwargs):
            captured_items.extend(items)
            return "99"

        with patch("hate_crack.attacks.interactive_menu", side_effect=capture_menu):
            combinator_submenu(ctx)

        keys = [item[0] for item in captured_items]
        assert "5" in keys
        assert "6" in keys
