"""Regression tests: custom-path prompts must offer tab autocomplete.

Previously the "p. Enter a custom path" branches (OMEN, Markov) and the
combipow wordlist prompt used a bare ``input()`` with no readline completer,
so TAB did nothing. They now route through ``select_file_with_autocomplete``.
Also covers the canonical selector dropping its completer afterward so later
plain prompts don't inherit stale file-path completion.
"""

import os
import readline
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

os.environ["HATE_CRACK_SKIP_INIT"] = "1"

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _load_attacks():
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    import hate_crack.attacks as attacks  # noqa: PLC0415

    return attacks


def _make_ctx():
    ctx = MagicMock()
    ctx.hcatHashType = "1000"
    ctx.hcatHashFile = "/tmp/hashes.txt"
    ctx.hcatWordlists = "/tmp/wordlists"
    ctx.list_wordlist_files.return_value = []
    return ctx


class TestOmenCustomPath:
    def test_custom_path_uses_autocomplete(self):
        attacks = _load_attacks()
        ctx = _make_ctx()
        ctx.select_file_with_autocomplete.return_value = "/data/custom.txt"
        with patch("builtins.input", side_effect=["p"]):
            result = attacks._omen_pick_training_wordlist(ctx)
        ctx.select_file_with_autocomplete.assert_called_once()
        assert result == "/data/custom.txt"

    def test_custom_path_blank_returns_none(self):
        attacks = _load_attacks()
        ctx = _make_ctx()
        ctx.select_file_with_autocomplete.return_value = None
        with patch("builtins.input", side_effect=["p"]):
            result = attacks._omen_pick_training_wordlist(ctx)
        assert result is None


class TestMarkovCustomPath:
    def test_custom_path_uses_autocomplete(self):
        attacks = _load_attacks()
        ctx = _make_ctx()
        ctx.select_file_with_autocomplete.return_value = "/data/train.txt"
        # out file absent -> "0" option not offered
        with patch("builtins.input", side_effect=["p"]):
            result = attacks._markov_pick_training_source(ctx)
        ctx.select_file_with_autocomplete.assert_called_once()
        assert result == "/data/train.txt"


class TestSelectorResetsCompleter:
    def test_completer_reset_after_selection(self):
        if str(PROJECT_ROOT) not in sys.path:
            sys.path.insert(0, str(PROJECT_ROOT))
        import hate_crack.main as m  # noqa: PLC0415

        sentinel = object()
        readline.set_completer(lambda t, s: None)
        with patch("builtins.input", return_value="/some/path"):
            m.select_file_with_autocomplete("Pick a file")
        assert readline.get_completer() is None
        del sentinel
