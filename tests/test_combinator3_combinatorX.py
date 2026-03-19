from unittest.mock import MagicMock, patch

from hate_crack.attacks import combinator_crack, combinator_submenu


def _make_ctx(hash_type="1000", hash_file="/tmp/hashes.txt"):
    ctx = MagicMock()
    ctx.hcatHashType = hash_type
    ctx.hcatHashFile = hash_file
    return ctx


class TestCombinatorCrackUnified:
    def test_two_wordlists_calls_hcatCombination(self, tmp_path):
        ctx = _make_ctx()
        ctx.hcatWordlists = str(tmp_path)
        for name in ["a.txt", "b.txt"]:
            (tmp_path / name).write_text("word\n")
        ctx._resolve_wordlist_path.side_effect = lambda p, base: p
        inputs = ["n", f"{tmp_path}/a.txt", f"{tmp_path}/b.txt", "", ""]
        with patch("builtins.input", side_effect=inputs):
            combinator_crack(ctx)
        ctx.hcatCombination.assert_called_once()
        ctx.hcatCombinator3.assert_not_called()
        ctx.hcatCombinatorX.assert_not_called()

    def test_three_wordlists_calls_hcatCombinator3(self, tmp_path):
        ctx = _make_ctx()
        ctx.hcatWordlists = str(tmp_path)
        for name in ["a.txt", "b.txt", "c.txt"]:
            (tmp_path / name).write_text("word\n")
        ctx._resolve_wordlist_path.side_effect = lambda p, base: p
        inputs = ["n", f"{tmp_path}/a.txt", f"{tmp_path}/b.txt", f"{tmp_path}/c.txt", "", ""]
        with patch("builtins.input", side_effect=inputs):
            combinator_crack(ctx)
        ctx.hcatCombinator3.assert_called_once()
        ctx.hcatCombination.assert_not_called()
        ctx.hcatCombinatorX.assert_not_called()

    def test_four_wordlists_calls_hcatCombinatorX(self, tmp_path):
        ctx = _make_ctx()
        ctx.hcatWordlists = str(tmp_path)
        for name in ["a.txt", "b.txt", "c.txt", "d.txt"]:
            (tmp_path / name).write_text("word\n")
        ctx._resolve_wordlist_path.side_effect = lambda p, base: p
        inputs = [
            "n",
            f"{tmp_path}/a.txt",
            f"{tmp_path}/b.txt",
            f"{tmp_path}/c.txt",
            f"{tmp_path}/d.txt",
            "",
            "",
        ]
        with patch("builtins.input", side_effect=inputs):
            combinator_crack(ctx)
        ctx.hcatCombinatorX.assert_called_once()
        ctx.hcatCombination.assert_not_called()
        ctx.hcatCombinator3.assert_not_called()

    def test_separator_forces_combinatorX_for_two_wordlists(self, tmp_path):
        ctx = _make_ctx()
        ctx.hcatWordlists = str(tmp_path)
        for name in ["a.txt", "b.txt"]:
            (tmp_path / name).write_text("word\n")
        ctx._resolve_wordlist_path.side_effect = lambda p, base: p
        inputs = ["n", f"{tmp_path}/a.txt", f"{tmp_path}/b.txt", "", "-"]
        with patch("builtins.input", side_effect=inputs):
            combinator_crack(ctx)
        ctx.hcatCombinatorX.assert_called_once()
        ctx.hcatCombination.assert_not_called()

    def test_separator_forces_combinatorX_for_three_wordlists(self, tmp_path):
        ctx = _make_ctx()
        ctx.hcatWordlists = str(tmp_path)
        for name in ["a.txt", "b.txt", "c.txt"]:
            (tmp_path / name).write_text("word\n")
        ctx._resolve_wordlist_path.side_effect = lambda p, base: p
        inputs = ["n", f"{tmp_path}/a.txt", f"{tmp_path}/b.txt", f"{tmp_path}/c.txt", "", "-"]
        with patch("builtins.input", side_effect=inputs):
            combinator_crack(ctx)
        ctx.hcatCombinatorX.assert_called_once()
        ctx.hcatCombinator3.assert_not_called()

    def test_aborts_with_fewer_than_2_wordlists(self, tmp_path):
        ctx = _make_ctx()
        ctx.hcatWordlists = str(tmp_path)
        (tmp_path / "a.txt").write_text("word\n")
        ctx._resolve_wordlist_path.side_effect = lambda p, base: p
        inputs = ["n", f"{tmp_path}/a.txt", ""]
        with patch("builtins.input", side_effect=inputs):
            combinator_crack(ctx)
        ctx.hcatCombination.assert_not_called()
        ctx.hcatCombinator3.assert_not_called()
        ctx.hcatCombinatorX.assert_not_called()

    def test_aborts_when_no_wordlists_provided(self, tmp_path):
        ctx = _make_ctx()
        ctx.hcatWordlists = str(tmp_path)
        ctx._resolve_wordlist_path.side_effect = lambda p, base: p
        with patch("builtins.input", side_effect=["n", ""]):
            combinator_crack(ctx)
        ctx.hcatCombination.assert_not_called()
        ctx.hcatCombinator3.assert_not_called()
        ctx.hcatCombinatorX.assert_not_called()

    def test_no_separator_passes_none_to_combinatorX(self, tmp_path):
        ctx = _make_ctx()
        ctx.hcatWordlists = str(tmp_path)
        for name in ["a.txt", "b.txt", "c.txt", "d.txt"]:
            (tmp_path / name).write_text("word\n")
        ctx._resolve_wordlist_path.side_effect = lambda p, base: p
        inputs = [
            "n",
            f"{tmp_path}/a.txt",
            f"{tmp_path}/b.txt",
            f"{tmp_path}/c.txt",
            f"{tmp_path}/d.txt",
            "",
            "",
        ]
        with patch("builtins.input", side_effect=inputs):
            combinator_crack(ctx)
        call_args = ctx.hcatCombinatorX.call_args
        positional_sep = call_args[0][3] if len(call_args[0]) >= 4 else None
        keyword_sep = call_args[1].get("separator")
        assert positional_sep in (None, "") and keyword_sep in (None, "")


class TestCombinatorSubmenuUpdated:
    def test_submenu_option1_dispatches_to_combinator_crack(self):
        ctx = _make_ctx()
        with patch("hate_crack.attacks.combinator_crack") as mock_c, patch(
            "hate_crack.attacks.interactive_menu", side_effect=["1", "99"]
        ):
            combinator_submenu(ctx)
        mock_c.assert_called_once_with(ctx)

    def test_submenu_has_no_separate_3plus_option(self):
        """Verify option 5 (3+) is removed - combinator is now unified under option 1."""
        ctx = _make_ctx()
        captured_items = []

        def capture_menu(items, **kwargs):
            captured_items.extend(items)
            return "99"

        with patch("hate_crack.attacks.interactive_menu", side_effect=capture_menu):
            combinator_submenu(ctx)

        keys = [item[0] for item in captured_items]
        assert "1" in keys
        assert "5" not in keys
        assert "6" not in keys
