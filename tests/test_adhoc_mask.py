"""Tests for ad-hoc mask attack, markov brute force, and combinator submenu."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from hate_crack.main import DirEntry


def _make_ctx(hash_type: str = "1000", hash_file: str = "/tmp/hashes.txt") -> MagicMock:
    ctx = MagicMock()
    ctx.hcatHashType = hash_type
    ctx.hcatHashFile = hash_file
    ctx.hcatWordlists = "/tmp/wordlists"
    return ctx


class TestAdHocMaskHandler:
    """Test the adhoc_mask_crack handler for user input and flow."""

    def test_basic_mask(self) -> None:
        """User enters mask, no custom charsets."""
        from hate_crack.attacks import adhoc_mask_crack

        ctx = _make_ctx()
        with patch("builtins.input", side_effect=["1", "?l?l?l?l", ""]):
            adhoc_mask_crack(ctx)

        ctx.hcatAdHocMask.assert_called_once_with(
            "1000",
            "/tmp/hashes.txt",
            "?l?l?l?l",
            "",
            increment=False,
            increment_min="",
            increment_max="",
        )

    def test_default_choice_is_typed_mask(self) -> None:
        """Pressing Enter at the menu falls through to the typed-mask prompt."""
        from hate_crack.attacks import adhoc_mask_crack

        ctx = _make_ctx()
        with patch("builtins.input", side_effect=["", "?d?d?d", ""]):
            adhoc_mask_crack(ctx)

        ctx.hcatAdHocMask.assert_called_once_with(
            "1000",
            "/tmp/hashes.txt",
            "?d?d?d",
            "",
            increment=False,
            increment_min="",
            increment_max="",
        )

    def test_empty_mask_aborts(self) -> None:
        """Empty mask string causes early return."""
        from hate_crack.attacks import adhoc_mask_crack

        ctx = _make_ctx()
        with patch("builtins.input", side_effect=["1", ""]):
            adhoc_mask_crack(ctx)

        ctx.hcatAdHocMask.assert_not_called()

    def test_mask_file_selected(self, tmp_path: Path) -> None:
        """Option 2 passes the chosen .hcmask path straight through to hashcat."""
        from hate_crack.attacks import adhoc_mask_crack

        ctx = _make_ctx()
        ctx.hate_path = str(tmp_path)
        mask_file = tmp_path / "custom.hcmask"
        mask_file.write_text("?u?l?l?l?d?d\n")
        ctx.select_file_with_autocomplete.return_value = str(mask_file)

        with patch("builtins.input", side_effect=["2", ""]):
            adhoc_mask_crack(ctx)

        ctx.hcatAdHocMask.assert_called_once_with(
            "1000",
            "/tmp/hashes.txt",
            str(mask_file),
            "",
            increment=False,
            increment_min="",
            increment_max="",
        )

    def test_missing_mask_file_aborts(self, tmp_path: Path) -> None:
        """A nonexistent mask file path aborts before invoking hashcat."""
        from hate_crack.attacks import adhoc_mask_crack

        ctx = _make_ctx()
        ctx.hate_path = str(tmp_path)
        ctx.select_file_with_autocomplete.return_value = str(tmp_path / "nope.hcmask")

        with patch("builtins.input", side_effect=["2"]):
            adhoc_mask_crack(ctx)

        ctx.hcatAdHocMask.assert_not_called()

    def test_blank_mask_file_aborts(self, tmp_path: Path) -> None:
        """Blank input at the file selector aborts."""
        from hate_crack.attacks import adhoc_mask_crack

        ctx = _make_ctx()
        ctx.hate_path = str(tmp_path)
        ctx.select_file_with_autocomplete.return_value = ""

        with patch("builtins.input", side_effect=["2"]):
            adhoc_mask_crack(ctx)

        ctx.hcatAdHocMask.assert_not_called()

    def test_custom_charset_passed(self) -> None:
        """User enters custom charset -1."""
        from hate_crack.attacks import adhoc_mask_crack

        ctx = _make_ctx()
        with patch("builtins.input", side_effect=["1", "?1?1?1?1", "abc", ""]):
            adhoc_mask_crack(ctx)

        ctx.hcatAdHocMask.assert_called_once()
        call_args = ctx.hcatAdHocMask.call_args
        assert call_args[0][2] == "?1?1?1?1"
        assert "-1" in call_args[0][3]
        assert "abc" in call_args[0][3]


class TestAdHocMaskCharsetPromptsAreConditional:
    """Only the custom slots a mask actually references are asked about."""

    @staticmethod
    def _run(mask: str, answers: list[str]) -> list[str]:
        """Return the prompts shown after the mask was entered."""
        from hate_crack.attacks import adhoc_mask_crack

        ctx = _make_ctx()
        prompts: list[str] = []
        supplied = iter(["1", mask] + answers)

        def _input(prompt: str = "") -> str:
            prompts.append(prompt)
            return next(supplied)

        with patch("builtins.input", _input):
            adhoc_mask_crack(ctx)
        ctx.hcatAdHocMask.assert_called_once()
        return prompts

    def test_mask_without_custom_tokens_asks_nothing(self) -> None:
        prompts = self._run("?u?l?l?d?d", ["n"])
        assert not [p for p in prompts if "Custom charset" in p]

    def test_only_referenced_slots_are_asked(self) -> None:
        prompts = self._run("?1?3?d", ["?u?l", "?d?s", "n"])
        asked = [p for p in prompts if "Custom charset" in p]
        assert len(asked) == 2
        assert "-1" in asked[0]
        assert "-3" in asked[1]

    def test_referenced_slots_reach_hashcat_in_order(self) -> None:
        from hate_crack.attacks import adhoc_mask_crack

        ctx = _make_ctx()
        with patch("builtins.input", side_effect=["1", "?4?2?d", "?d?s", "?u?l", "n"]):
            adhoc_mask_crack(ctx)

        # Prompted low slot first regardless of the order used in the mask.
        assert ctx.hcatAdHocMask.call_args[0][3] == "-2 ?d?s -4 ?u?l"

    def test_escaped_question_mark_is_not_a_custom_slot(self) -> None:
        """`??` is a literal `?` in hashcat, so `??1` does not reference ?1."""
        prompts = self._run("??1?d?d", ["n"])
        assert not [p for p in prompts if "Custom charset" in p]

    def test_literal_digit_after_a_real_token_is_not_a_slot(self) -> None:
        prompts = self._run("?d1?l", ["n"])
        assert not [p for p in prompts if "Custom charset" in p]

    def test_referenced_slot_left_blank_warns(self, capsys) -> None:
        prompts = self._run("?1?l?l", ["", "n"])
        assert len([p for p in prompts if "Custom charset" in p]) == 1
        assert "hashcat will reject the mask" in capsys.readouterr().out


class TestAdHocMaskIncrementPrompt:
    """Option 14 offers --increment, with optional min and max bounds."""

    @staticmethod
    def _typed_mask(answers: list[str]) -> MagicMock:
        from hate_crack.attacks import adhoc_mask_crack

        ctx = _make_ctx()
        # ?l?l?l?l references no custom slot, so no charset prompt intervenes
        # between the mask and the increment question.
        with patch("builtins.input", side_effect=["1", "?l?l?l?l"] + answers):
            adhoc_mask_crack(ctx)
        return ctx

    def test_declining_increment_passes_no_bounds(self) -> None:
        ctx = self._typed_mask(["n"])

        kwargs = ctx.hcatAdHocMask.call_args[1]
        assert kwargs["increment"] is False
        assert kwargs["increment_min"] == ""
        assert kwargs["increment_max"] == ""

    def test_increment_with_both_bounds(self) -> None:
        ctx = self._typed_mask(["y", "4", "8"])

        kwargs = ctx.hcatAdHocMask.call_args[1]
        assert kwargs["increment"] is True
        assert kwargs["increment_min"] == "4"
        assert kwargs["increment_max"] == "8"

    def test_increment_with_both_bounds_blank_is_full_keyspace(self) -> None:
        """Blank min and max mean plain --increment: hashcat picks the bounds."""
        ctx = self._typed_mask(["y", "", ""])

        kwargs = ctx.hcatAdHocMask.call_args[1]
        assert kwargs["increment"] is True
        assert kwargs["increment_min"] == ""
        assert kwargs["increment_max"] == ""

    def test_increment_with_only_min(self) -> None:
        ctx = self._typed_mask(["y", "5", ""])

        kwargs = ctx.hcatAdHocMask.call_args[1]
        assert kwargs["increment"] is True
        assert kwargs["increment_min"] == "5"
        assert kwargs["increment_max"] == ""

    def test_non_numeric_bound_is_reprompted(self) -> None:
        ctx = self._typed_mask(["y", "abc", "5", "9"])

        kwargs = ctx.hcatAdHocMask.call_args[1]
        assert kwargs["increment_min"] == "5"
        assert kwargs["increment_max"] == "9"

    def test_max_below_min_is_reprompted(self) -> None:
        ctx = self._typed_mask(["y", "6", "3", "8"])

        kwargs = ctx.hcatAdHocMask.call_args[1]
        assert kwargs["increment_min"] == "6"
        assert kwargs["increment_max"] == "8"

    def test_mask_file_path_also_offers_increment(self, tmp_path: Path) -> None:
        from hate_crack.attacks import adhoc_mask_crack

        ctx = _make_ctx()
        ctx.hate_path = str(tmp_path)
        mask_file = tmp_path / "custom.hcmask"
        mask_file.write_text("?u?l?l?l?d?d\n")
        ctx.select_file_with_autocomplete.return_value = str(mask_file)

        with patch("builtins.input", side_effect=["2", "y", "6", "10"]):
            adhoc_mask_crack(ctx)

        kwargs = ctx.hcatAdHocMask.call_args[1]
        assert kwargs["increment"] is True
        assert kwargs["increment_min"] == "6"
        assert kwargs["increment_max"] == "10"


class TestMarkovBruteForceHandler:
    """Test markov_brute_force handler logic with table reuse options."""

    def test_use_existing_table(self, tmp_path: Path) -> None:
        """User chooses to use existing .hcstat2 table."""
        from hate_crack.attacks import markov_brute_force

        ctx = _make_ctx()
        hash_file = str(tmp_path / "hashes.txt")
        ctx.hcatHashFile = hash_file
        hcstat2_path = f"{hash_file}.hcstat2"
        Path(hcstat2_path).touch()

        with patch("builtins.input", side_effect=["1", "1", "7"]):
            markov_brute_force(ctx)

        ctx.hcatMarkovTrain.assert_not_called()
        ctx.hcatMarkovBruteForce.assert_called_once()

    def test_no_table_requires_training(self, tmp_path: Path) -> None:
        """No table exists, training is triggered."""
        from hate_crack.attacks import markov_brute_force

        ctx = _make_ctx()
        hash_file = str(tmp_path / "hashes.txt")
        ctx.hcatHashFile = hash_file
        ctx.hcatMarkovTrain.return_value = True
        ctx.list_wordlist_files.return_value = ["test.txt"]
        ctx.list_wordlist_entries.return_value = [DirEntry("test.txt", False)]

        with patch("builtins.input", side_effect=["1", "1", "6"]):
            markov_brute_force(ctx)

        ctx.hcatMarkovTrain.assert_called_once()
        ctx.hcatMarkovBruteForce.assert_called_once()

    def test_training_failure_aborts(self, tmp_path: Path) -> None:
        """Training failure aborts without calling brute force."""
        from hate_crack.attacks import markov_brute_force

        ctx = _make_ctx()
        hash_file = str(tmp_path / "hashes.txt")
        ctx.hcatHashFile = hash_file
        ctx.hcatMarkovTrain.return_value = False
        ctx.list_wordlist_files.return_value = ["test.txt"]
        ctx.list_wordlist_entries.return_value = [DirEntry("test.txt", False)]

        with patch("builtins.input", side_effect=["1", "1"]):
            markov_brute_force(ctx)

        ctx.hcatMarkovTrain.assert_called_once()
        ctx.hcatMarkovBruteForce.assert_not_called()
