"""Tests for cli.prompt_int, the shared numeric-input prompt.

Every one of these covers a way the old ``int(input(...))`` idiom killed the
process: a typo, a stray letter, a negative count. The prompt has to absorb
them and ask again, because the alternative is a traceback that loses whatever
the user had already set up in that attack.
"""

from unittest.mock import patch

from hate_crack.cli import prompt_int


class TestPromptInt:
    def test_returns_parsed_integer(self):
        with patch("builtins.input", side_effect=["42"]):
            assert prompt_int("n: ") == 42

    def test_empty_input_returns_default(self):
        with patch("builtins.input", side_effect=[""]):
            assert prompt_int("n: ", default=7) == 7

    def test_empty_input_reprompts_when_no_default(self, capsys):
        with patch("builtins.input", side_effect=["", "5"]):
            assert prompt_int("n: ") == 5
        assert "[!]" in capsys.readouterr().out

    def test_non_integer_reprompts_instead_of_raising(self, capsys):
        with patch("builtins.input", side_effect=["abc", "100"]):
            assert prompt_int("n: ") == 100
        out = capsys.readouterr().out
        assert "abc" in out
        assert "[!]" in out

    def test_surrounding_whitespace_is_tolerated(self):
        with patch("builtins.input", side_effect=["  12  "]):
            assert prompt_int("n: ") == 12

    def test_value_below_minimum_reprompts(self, capsys):
        with patch("builtins.input", side_effect=["0", "3"]):
            assert prompt_int("n: ", minimum=1) == 3
        assert "[!]" in capsys.readouterr().out

    def test_negative_value_below_minimum_reprompts(self):
        with patch("builtins.input", side_effect=["-5", "1"]):
            assert prompt_int("n: ", minimum=0) == 1

    def test_negative_value_allowed_when_no_minimum(self):
        with patch("builtins.input", side_effect=["-5"]):
            assert prompt_int("n: ") == -5

    def test_q_cancels_and_returns_none(self):
        with patch("builtins.input", side_effect=["q"]):
            assert prompt_int("n: ") is None

    def test_cancel_is_case_insensitive(self):
        with patch("builtins.input", side_effect=["Q"]):
            assert prompt_int("n: ") is None

    def test_eof_cancels_and_returns_none(self):
        """Ctrl-D must not surface as an EOFError traceback from the attack."""
        with patch("builtins.input", side_effect=EOFError):
            assert prompt_int("n: ") is None

    def test_default_is_shown_without_being_retyped(self, capsys):
        """A rejected entry re-asks with the same prompt text, default included."""
        with patch("builtins.input", side_effect=["abc", ""]) as mock_input:
            assert prompt_int("Max candidates (100): ", default=100) == 100
        assert mock_input.call_args_list[-1][0][0] == "Max candidates (100): "
