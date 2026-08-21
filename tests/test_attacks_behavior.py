import os
from pathlib import Path
from unittest.mock import MagicMock, patch

from hate_crack.attacks import (
    bandrel_method,
    combinator_crack,
    extensive_crack,
    hybrid_crack,
    loopback_attack,
    middle_combinator,
    ollama_attack,
    pathwell_crack,
    prince_attack,
    rosetta_attack,
    thorough_combinator,
    top_mask_crack,
    yolo_combination,
)
from hate_crack.main import DirEntry


def _make_ctx(hash_type: str = "1000", hash_file: str = "/tmp/hashes.txt") -> MagicMock:
    ctx = MagicMock()
    ctx.hcatHashType = hash_type
    ctx.hcatHashFile = hash_file
    # Default backend for every attack that reads ctx.llmBackend (currently
    # only the Rosetta mask path) -- a bare MagicMock attribute would compare
    # unequal to "ollama" and trip the non-ollama refusal in every caller
    # that did not opt into testing that refusal specifically.
    ctx.llmBackend = "ollama"
    return ctx


class TestLoopbackAttack:
    def test_no_rules_proceeds_without_rules(self, tmp_path: Path) -> None:
        ctx = _make_ctx()
        ctx.hcatWordlists = str(tmp_path / "wordlists")
        ctx.rulesDirectory = str(tmp_path / "rules")
        os.makedirs(ctx.rulesDirectory, exist_ok=True)
        ctx.list_rule_files.return_value = []

        # No rule files in directory -> prompts for download -> user says "n"
        # Then rule_choice becomes ["0"] via the "no rules" branch
        with (
            patch("hate_crack.attacks.download_hashmob_rules"),
            patch("builtins.input", side_effect=["n", "0"]),
        ):
            loopback_attack(ctx)

        ctx.hcatQuickDictionary.assert_called_once()
        call_kwargs = ctx.hcatQuickDictionary.call_args
        assert call_kwargs.kwargs.get("loopback") is True

    def test_with_rule_file_calls_with_rule(self, tmp_path: Path) -> None:
        ctx = _make_ctx()
        ctx.hcatWordlists = str(tmp_path / "wordlists")
        ctx.rulesDirectory = str(tmp_path / "rules")
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "best66.rule").write_text("")
        ctx.list_rule_files.return_value = ["best66.rule"]

        with patch("builtins.input", return_value="1"):
            loopback_attack(ctx)

        ctx.hcatQuickDictionary.assert_called_once()
        call_args = ctx.hcatQuickDictionary.call_args
        assert call_args.kwargs.get("loopback") is True
        # Third positional arg is the rule chain string
        assert "best66.rule" in call_args[0][2]

    def test_rule_99_returns_without_calling(self, tmp_path: Path) -> None:
        ctx = _make_ctx()
        ctx.hcatWordlists = str(tmp_path / "wordlists")
        ctx.rulesDirectory = str(tmp_path / "rules")
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "best66.rule").write_text("")

        with patch("builtins.input", return_value="99"):
            loopback_attack(ctx)

        ctx.hcatQuickDictionary.assert_not_called()

    def test_creates_empty_wordlist_if_missing(self, tmp_path: Path) -> None:
        ctx = _make_ctx()
        ctx.hcatWordlists = str(tmp_path / "wordlists")
        ctx.rulesDirectory = str(tmp_path / "rules")
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "best66.rule").write_text("")

        empty_txt = tmp_path / "wordlists" / "empty.txt"
        assert not empty_txt.exists()

        with patch("builtins.input", return_value="1"):
            loopback_attack(ctx)

        assert empty_txt.exists()

    def test_empty_wordlist_passed_to_hcatQuickDictionary(self, tmp_path: Path) -> None:
        ctx = _make_ctx()
        ctx.hcatWordlists = str(tmp_path / "wordlists")
        ctx.rulesDirectory = str(tmp_path / "rules")
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "best66.rule").write_text("")

        with patch("builtins.input", return_value="1"):
            loopback_attack(ctx)

        call_args = ctx.hcatQuickDictionary.call_args
        # Fourth positional arg is the empty wordlist path
        empty_wordlist_arg = call_args[0][3]
        assert empty_wordlist_arg.endswith("empty.txt")


class TestExtensiveCrack:
    def test_calls_all_attack_methods(self) -> None:
        ctx = _make_ctx()

        extensive_crack(ctx)

        ctx.hcatBruteForce.assert_called_once_with(
            ctx.hcatHashType, ctx.hcatHashFile, "1", "7"
        )
        ctx.hcatDictionary.assert_called_once_with(ctx.hcatHashType, ctx.hcatHashFile)
        ctx.hcatTopMask.assert_called_once_with(
            ctx.hcatHashType, ctx.hcatHashFile, 4 * 60 * 60
        )
        ctx.hcatFingerprint.assert_called_once_with(
            ctx.hcatHashType,
            ctx.hcatHashFile,
            max_expander_len=21,
            run_hybrid_on_expanded=False,
        )
        ctx.hcatSmartMask.assert_called_once_with(ctx.hcatHashType, ctx.hcatHashFile)
        ctx.hcatCombination.assert_called_once_with(ctx.hcatHashType, ctx.hcatHashFile)
        ctx.hcatHybrid.assert_called_once_with(ctx.hcatHashType, ctx.hcatHashFile)
        ctx.hcatGoodMeasure.assert_called_once_with(ctx.hcatHashType, ctx.hcatHashFile)

    def test_calls_recycle_after_each_attack(self) -> None:
        ctx = _make_ctx()

        extensive_crack(ctx)

        # extensive_crack calls hcatRecycle after: brute, dictionary, mask,
        # fingerprint, smart mask, combination, hybrid, and once more at the
        # end (hcatExtraCount)
        assert ctx.hcatRecycle.call_count == 8
        ctx.hcatRecycle.assert_any_call(
            ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatBruteCount
        )
        ctx.hcatRecycle.assert_any_call(
            ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatDictionaryCount
        )
        ctx.hcatRecycle.assert_any_call(
            ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatMaskCount
        )
        ctx.hcatRecycle.assert_any_call(
            ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatFingerprintCount
        )
        ctx.hcatRecycle.assert_any_call(
            ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatSmartMaskCount
        )
        ctx.hcatRecycle.assert_any_call(
            ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatCombinationCount
        )
        ctx.hcatRecycle.assert_any_call(
            ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatHybridCount
        )
        ctx.hcatRecycle.assert_any_call(
            ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatExtraCount
        )


class TestTopMaskCrack:
    def test_default_time_uses_four_hours(self) -> None:
        ctx = _make_ctx()

        with patch("builtins.input", return_value=""):
            top_mask_crack(ctx)

        ctx.hcatTopMask.assert_called_once_with(
            ctx.hcatHashType, ctx.hcatHashFile, 4 * 60 * 60
        )

    def test_custom_time_converts_hours_to_seconds(self) -> None:
        ctx = _make_ctx()

        with patch("builtins.input", return_value="2"):
            top_mask_crack(ctx)

        ctx.hcatTopMask.assert_called_once_with(
            ctx.hcatHashType, ctx.hcatHashFile, 2 * 60 * 60
        )

    def test_one_hour_input(self) -> None:
        ctx = _make_ctx()

        with patch("builtins.input", return_value="1"):
            top_mask_crack(ctx)

        ctx.hcatTopMask.assert_called_once_with(
            ctx.hcatHashType, ctx.hcatHashFile, 1 * 60 * 60
        )


class TestCombinatorCrack:
    def test_default_list_wordlist_calls_hcatCombination(self) -> None:
        ctx = _make_ctx()
        ctx.hcatCombinationWordlist = ["/wl/rockyou.txt", "/wl/passwords.txt"]
        ctx._resolve_wordlist_path.side_effect = lambda wl, _: wl

        with patch("builtins.input", return_value=""):
            combinator_crack(ctx)

        ctx.hcatCombination.assert_called_once_with(
            ctx.hcatHashType,
            ctx.hcatHashFile,
            ["/wl/rockyou.txt", "/wl/passwords.txt"],
        )

    def test_default_single_string_wordlist_aborts_gracefully(self, capsys) -> None:
        # When hcatCombinationWordlist is a plain string (one wordlist), the code
        # wraps it in a list giving only 1 item - the handler should abort with a
        # clear message instead of crashing with IndexError.
        ctx = _make_ctx()
        ctx.hcatCombinationWordlist = "/wl/rockyou.txt"
        ctx._resolve_wordlist_path.side_effect = lambda wl, _: wl

        with patch("builtins.input", return_value="y"):
            combinator_crack(ctx)

        ctx.hcatCombination.assert_not_called()
        captured = capsys.readouterr()
        assert "Aborting combinator attack" in captured.out

    def test_resolve_wordlist_path_called_for_each_wordlist(self) -> None:
        ctx = _make_ctx()
        ctx.hcatCombinationWordlist = ["/wl/a.txt", "/wl/b.txt"]
        ctx._resolve_wordlist_path.side_effect = lambda wl, _: wl

        with patch("builtins.input", return_value=""):
            combinator_crack(ctx)

        assert ctx._resolve_wordlist_path.call_count == 2
        ctx._resolve_wordlist_path.assert_any_call("/wl/a.txt", ctx.hcatWordlists)
        ctx._resolve_wordlist_path.assert_any_call("/wl/b.txt", ctx.hcatWordlists)

    def test_three_wordlists_in_config_routes_to_combinator3(self) -> None:
        ctx = _make_ctx()
        ctx.hcatCombinationWordlist = ["/wl/a.txt", "/wl/b.txt", "/wl/c.txt"]
        ctx._resolve_wordlist_path.side_effect = lambda wl, _: wl

        with patch("builtins.input", return_value=""):
            combinator_crack(ctx)

        ctx.hcatCombinator3.assert_called_once()
        ctx.hcatCombination.assert_not_called()
        call_wordlists = ctx.hcatCombinator3.call_args[0][2]
        assert len(call_wordlists) == 3


class TestHybridCrack:
    def test_default_list_wordlist_calls_hcatHybrid(self) -> None:
        ctx = _make_ctx()
        ctx.hcatHybridlist = ["/wl/rockyou.txt"]
        ctx._resolve_wordlist_path.side_effect = lambda wl, _: wl

        with patch("builtins.input", return_value=""):
            hybrid_crack(ctx)

        ctx.hcatHybrid.assert_called_once_with(
            ctx.hcatHashType,
            ctx.hcatHashFile,
            ["/wl/rockyou.txt"],
        )

    def test_default_string_wordlist_wraps_in_list(self) -> None:
        ctx = _make_ctx()
        ctx.hcatHybridlist = "/wl/rockyou.txt"
        ctx._resolve_wordlist_path.side_effect = lambda wl, _: wl

        with patch("builtins.input", return_value=""):
            hybrid_crack(ctx)

        ctx.hcatHybrid.assert_called_once()
        call_wordlists = ctx.hcatHybrid.call_args[0][2]
        assert "/wl/rockyou.txt" in call_wordlists

    def test_decline_default_aborts_when_no_selection(self) -> None:
        ctx = _make_ctx()
        ctx.select_file_with_autocomplete.return_value = None

        with patch("builtins.input", return_value="n"):
            hybrid_crack(ctx)

        ctx.hcatHybrid.assert_not_called()

    def test_spelled_out_no_also_declines_the_default(self) -> None:
        """ "no" is not "n", and answering it must not silently use the default."""
        ctx = _make_ctx()
        ctx.select_file_with_autocomplete.return_value = None

        with patch("builtins.input", return_value="no"):
            hybrid_crack(ctx)

        ctx.hcatHybrid.assert_not_called()

    def test_glob_selection_is_passed_through_unexpanded(self) -> None:
        """hcatHybrid expands the pattern; rejecting it here would make a glob
        usable from config.json but not from this prompt."""
        ctx = _make_ctx()
        ctx.select_file_with_autocomplete.return_value = ["/wl/rock*.txt"]
        ctx._resolve_wordlist_path.side_effect = lambda wl, _: wl

        with patch("builtins.input", return_value="n"):
            hybrid_crack(ctx)

        ctx.hcatHybrid.assert_called_once()
        assert ctx.hcatHybrid.call_args[0][2] == ["/wl/rock*.txt"]

    def test_directory_selection_is_accepted(self, tmp_path) -> None:
        """hcatHybrid expands a directory into the files inside it; rejecting
        it here would make a wordlist collection unusable from this prompt."""
        collection = tmp_path / "collection"
        collection.mkdir()
        (collection / "one.txt").write_text("word\n")
        ctx = _make_ctx()
        ctx.select_file_with_autocomplete.return_value = [str(collection)]
        ctx._resolve_wordlist_path.side_effect = lambda wl, _: wl

        with patch("builtins.input", return_value="n"):
            hybrid_crack(ctx)

        ctx.hcatHybrid.assert_called_once()
        assert ctx.hcatHybrid.call_args[0][2] == [str(collection)]


class TestSimpleAttacks:
    def test_pathwell_crack(self) -> None:
        ctx = _make_ctx()

        pathwell_crack(ctx)

        ctx.hcatPathwellBruteForce.assert_called_once_with(
            ctx.hcatHashType, ctx.hcatHashFile
        )

    def test_prince_attack(self) -> None:
        ctx = _make_ctx()

        prince_attack(ctx)

        ctx.hcatPrince.assert_called_once_with(ctx.hcatHashType, ctx.hcatHashFile)

    def test_yolo_combination(self) -> None:
        ctx = _make_ctx()

        yolo_combination(ctx)

        ctx.hcatYoloCombination.assert_called_once_with(
            ctx.hcatHashType, ctx.hcatHashFile
        )

    def test_thorough_combinator(self) -> None:
        ctx = _make_ctx()

        thorough_combinator(ctx)

        ctx.hcatThoroughCombinator.assert_called_once_with(
            ctx.hcatHashType, ctx.hcatHashFile
        )

    def test_middle_combinator(self) -> None:
        ctx = _make_ctx()

        middle_combinator(ctx)

        ctx.hcatMiddleCombinator.assert_called_once_with(
            ctx.hcatHashType, ctx.hcatHashFile
        )

    def test_bandrel_method(self) -> None:
        ctx = _make_ctx()

        bandrel_method(ctx)

        ctx.hcatBandrel.assert_called_once_with(ctx.hcatHashType, ctx.hcatHashFile)

    def test_pathwell_crack_passes_hash_type_and_file(self) -> None:
        ctx = _make_ctx(hash_type="500", hash_file="/data/hashes.hash")

        pathwell_crack(ctx)

        ctx.hcatPathwellBruteForce.assert_called_once_with("500", "/data/hashes.hash")

    def test_prince_attack_passes_hash_type_and_file(self) -> None:
        ctx = _make_ctx(hash_type="500", hash_file="/data/hashes.hash")

        prince_attack(ctx)

        ctx.hcatPrince.assert_called_once_with("500", "/data/hashes.hash")


class TestOllamaAttack:
    def test_calls_hcatOllama_with_context(self) -> None:
        ctx = _make_ctx()

        with (
            patch("hate_crack.attacks.interactive_menu", return_value="1"),
            patch("builtins.input", side_effect=["ACME", "tech", "NYC", ""]),
        ):
            ollama_attack(ctx)

        ctx.hcatOllama.assert_called_once_with(
            ctx.hcatHashType,
            ctx.hcatHashFile,
            "target",
            {
                "company": "ACME",
                "industry": "tech",
                "location": "NYC",
                "parent_company": "",
            },
        )

    def test_passes_hash_type_and_file(self) -> None:
        ctx = _make_ctx(hash_type="1800", hash_file="/tmp/sha512.txt")

        with (
            patch("hate_crack.attacks.interactive_menu", return_value="1"),
            patch("builtins.input", side_effect=["Corp", "finance", "London", ""]),
        ):
            ollama_attack(ctx)

        call_args = ctx.hcatOllama.call_args[0]
        assert call_args[0] == "1800"
        assert call_args[1] == "/tmp/sha512.txt"

    def test_strips_whitespace_from_inputs(self) -> None:
        ctx = _make_ctx()

        with (
            patch("hate_crack.attacks.interactive_menu", return_value="1"),
            patch(
                "builtins.input",
                side_effect=["  ACME  ", "  tech  ", "  NYC  ", "  parent corp  "],
            ),
        ):
            ollama_attack(ctx)

        target_info = ctx.hcatOllama.call_args[0][3]
        assert target_info["company"] == "ACME"
        assert target_info["industry"] == "tech"
        assert target_info["location"] == "NYC"
        assert target_info["parent_company"] == "parent corp"

    def test_target_string_is_literal_target(self) -> None:
        ctx = _make_ctx()

        with (
            patch("hate_crack.attacks.interactive_menu", return_value="1"),
            patch("builtins.input", side_effect=["X", "Y", "Z", ""]),
        ):
            ollama_attack(ctx)

        assert ctx.hcatOllama.call_args[0][2] == "target"

    def test_wordlist_mode_calls_hcatOllama_with_path(self) -> None:
        ctx = _make_ctx()
        ctx.list_wordlist_files.return_value = ["rockyou.txt"]
        ctx.list_wordlist_entries.return_value = [DirEntry("rockyou.txt", False)]
        ctx.hcatWordlists = "/tmp/wl"

        # mode "2" from interactive_menu, then pick wordlist "1" via input
        with (
            patch("hate_crack.attacks.interactive_menu", return_value="2"),
            patch("builtins.input", side_effect=["1"]),
        ):
            ollama_attack(ctx)

        args = ctx.hcatOllama.call_args[0]
        assert args[2] == "wordlist"
        assert args[3].endswith("rockyou.txt")

    def test_escape_cancels_without_calling_hcatOllama(self) -> None:
        """None from interactive_menu (Escape / 99) cancels the attack."""
        ctx = _make_ctx()
        with patch("hate_crack.attacks.interactive_menu", return_value=None):
            ollama_attack(ctx)
        ctx.hcatOllama.assert_not_called()

    def test_cancel_key_cancels_without_calling_hcatOllama(self) -> None:
        """Selecting '99' (Cancel) cancels the attack."""
        ctx = _make_ctx()
        with patch("hate_crack.attacks.interactive_menu", return_value="99"):
            ollama_attack(ctx)
        ctx.hcatOllama.assert_not_called()

    def test_wordlist_mode_aborts_when_no_wordlist_picked(self) -> None:
        ctx = _make_ctx()
        # mode "2" from interactive_menu, then user cancels the file picker
        ctx.list_wordlist_files.return_value = []
        ctx.list_wordlist_entries.return_value = []
        with (
            patch("hate_crack.attacks.interactive_menu", return_value="2"),
            patch("builtins.input", side_effect=["q"]),
        ):
            ollama_attack(ctx)
        ctx.hcatOllama.assert_not_called()

    def test_cracked_mode_offered_when_out_file_has_content(
        self, tmp_path: Path
    ) -> None:
        hash_file = tmp_path / "hashes.txt"
        hash_file.touch()
        out_file = tmp_path / "hashes.txt.out"
        out_file.write_text("hash:Summer2024!\n")
        ctx = _make_ctx(hash_file=str(hash_file))

        captured_items: list[list[tuple[str, str]]] = []

        def capture_menu(items, **kwargs):
            captured_items.append(list(items))
            return "3"

        with patch("hate_crack.attacks.interactive_menu", side_effect=capture_menu):
            ollama_attack(ctx)

        # Option 3 must be present in the items list when cracked file exists
        keys = [k for k, _ in captured_items[0]]
        assert "3" in keys
        ctx.hcatOllama.assert_called_once_with(
            ctx.hcatHashType, str(hash_file), "cracked", str(out_file)
        )

    def test_cracked_mode_not_offered_when_out_file_missing(
        self, tmp_path: Path
    ) -> None:
        """Option 3 must NOT appear in items when no cracked file exists."""
        hash_file = tmp_path / "hashes.txt"
        hash_file.touch()
        ctx = _make_ctx(hash_file=str(hash_file))

        captured_items: list[list[tuple[str, str]]] = []

        def capture_menu(items, **kwargs):
            captured_items.append(list(items))
            return "99"  # cancel

        with patch("hate_crack.attacks.interactive_menu", side_effect=capture_menu):
            ollama_attack(ctx)

        keys = [k for k, _ in captured_items[0]]
        assert "3" not in keys
        ctx.hcatOllama.assert_not_called()

    def test_cracked_mode_not_offered_when_out_file_empty(self, tmp_path: Path) -> None:
        """Option 3 must NOT appear in items when cracked file exists but is empty."""
        hash_file = tmp_path / "hashes.txt"
        hash_file.touch()
        (tmp_path / "hashes.txt.out").touch()  # exists but zero bytes
        ctx = _make_ctx(hash_file=str(hash_file))

        captured_items: list[list[tuple[str, str]]] = []

        def capture_menu(items, **kwargs):
            captured_items.append(list(items))
            return "99"  # cancel

        with patch("hate_crack.attacks.interactive_menu", side_effect=capture_menu):
            ollama_attack(ctx)

        keys = [k for k, _ in captured_items[0]]
        assert "3" not in keys
        ctx.hcatOllama.assert_not_called()

    def test_target_and_wordlist_modes_unaffected_by_cracked_option(
        self, tmp_path: Path
    ) -> None:
        """Existing modes still work when a cracked file is present."""
        hash_file = tmp_path / "hashes.txt"
        hash_file.touch()
        (tmp_path / "hashes.txt.out").write_text("hash:Summer2024!\n")
        ctx = _make_ctx(hash_file=str(hash_file))

        with (
            patch("hate_crack.attacks.interactive_menu", return_value="1"),
            patch("builtins.input", side_effect=["ACME", "tech", "NYC", ""]),
        ):
            ollama_attack(ctx)

        assert ctx.hcatOllama.call_args[0][2] == "target"

    def test_arrow_menu_env_reaches_ollama_attack(self) -> None:
        """HATE_CRACK_ARROW_MENU=1 routes through interactive_menu in ollama_attack."""

        ctx = _make_ctx()
        calls: list[tuple] = []

        def spy_menu(items, **kwargs):
            calls.append(tuple(items))
            return "99"  # cancel immediately

        with (
            patch("hate_crack.attacks.interactive_menu", side_effect=spy_menu),
        ):
            ollama_attack(ctx)

        # interactive_menu was called — confirms the arrow-menu code path is reachable
        assert len(calls) == 1
        keys = [k for k, _ in calls[0]]
        assert "1" in keys
        assert "2" in keys
        assert "99" in keys


class TestOmenPickTrainingWordlistReprompt:
    """_pick_training_wordlist re-prompts on invalid input instead of aborting."""

    def _make_ctx(self, wordlist_files=None):
        ctx = MagicMock()
        files = wordlist_files or ["rockyou.txt"]
        ctx.list_wordlist_files.return_value = files
        ctx.list_wordlist_entries.return_value = [
            DirEntry(name, False) for name in files
        ]
        ctx.hcatWordlists = "/tmp/wl"
        ctx.hcatHashFile = "/tmp/hashes.txt"
        return ctx

    def test_invalid_input_reprompts_then_valid_pick(self) -> None:
        from hate_crack.attacks import _pick_training_wordlist

        ctx = self._make_ctx(["rockyou.txt"])
        # First input is invalid, second is valid
        with patch("builtins.input", side_effect=["bad", "1"]):
            result = _pick_training_wordlist(ctx)
        assert result is not None
        assert "rockyou.txt" in result

    def test_cancel_with_q_returns_none(self) -> None:
        from hate_crack.attacks import _pick_training_wordlist

        ctx = self._make_ctx(["rockyou.txt"])
        with patch("builtins.input", return_value="q"):
            result = _pick_training_wordlist(ctx)
        assert result is None

    def test_multiple_invalid_inputs_then_cancel(self) -> None:
        from hate_crack.attacks import _pick_training_wordlist

        ctx = self._make_ctx(["rockyou.txt"])
        with patch("builtins.input", side_effect=["99", "abc", "q"]):
            result = _pick_training_wordlist(ctx)
        assert result is None


class TestMarkovPickTrainingSourceReprompt:
    """_markov_pick_training_source re-prompts on invalid input instead of aborting."""

    def _make_ctx(self, tmp_path, has_cracked=False, wordlist_files=None):
        ctx = MagicMock()
        hash_file = str(tmp_path / "hashes.txt")
        ctx.hcatHashFile = hash_file
        files = wordlist_files or ["rockyou.txt"]
        ctx.list_wordlist_files.return_value = files
        ctx.list_wordlist_entries.return_value = [
            DirEntry(name, False) for name in files
        ]
        ctx.hcatWordlists = str(tmp_path / "wordlists")
        if has_cracked:
            (tmp_path / "hashes.txt.out").write_text("cracked_pw\n")
        return ctx

    def test_invalid_input_reprompts_then_valid_pick(self, tmp_path: Path) -> None:
        from hate_crack.attacks import _markov_pick_training_source

        ctx = self._make_ctx(tmp_path, wordlist_files=["rockyou.txt"])
        with patch("builtins.input", side_effect=["bad", "1"]):
            result = _markov_pick_training_source(ctx)
        assert result is not None
        assert "rockyou.txt" in result

    def test_cancel_with_q_returns_none(self, tmp_path: Path) -> None:
        from hate_crack.attacks import _markov_pick_training_source

        ctx = self._make_ctx(tmp_path)
        with patch("builtins.input", return_value="q"):
            result = _markov_pick_training_source(ctx)
        assert result is None

    def test_multiple_invalid_then_cancel(self, tmp_path: Path) -> None:
        from hate_crack.attacks import _markov_pick_training_source

        ctx = self._make_ctx(tmp_path, wordlist_files=["rockyou.txt"])
        with patch("builtins.input", side_effect=["99", "abc", "q"]):
            result = _markov_pick_training_source(ctx)
        assert result is None

    def test_caller_handles_none_correctly(self, tmp_path: Path) -> None:
        """markov_brute_force returns early without crashing when picker returns None."""
        from hate_crack.attacks import markov_brute_force

        ctx = self._make_ctx(tmp_path, wordlist_files=["rockyou.txt"])
        # No .hcstat2 file → goes straight to picker; user cancels
        with patch("builtins.input", return_value="q"):
            markov_brute_force(ctx)
        ctx.hcatMarkovTrain.assert_not_called()
        ctx.hcatMarkovBruteForce.assert_not_called()


class TestAdhocMaskCharsetSkipping:
    """A blank charset answer must skip that slot, not abandon the rest."""

    def test_blank_slot_does_not_abandon_later_slots(self):
        import hate_crack.attacks as hc_attacks
        from hate_crack.attacks import adhoc_mask_crack

        ctx = MagicMock()
        ctx.hcatHashType = "1000"
        ctx.hcatHashFile = "/tmp/hashes.txt"
        # Prompt order: "1" picks the type-a-mask path (option 2 is a mask
        # file), then the mask, then a charset prompt per slot the mask
        # references -- here -1, -2 (blank) and -3 -- then the increment
        # question, declined.
        answers = iter(["1", "?1?2?3?d", "?u?l", "", "?d?s", "n"])
        with (
            patch("builtins.input", lambda _prompt="": next(answers)),
            patch.object(hc_attacks._notify, "prompt_notify_for_attack"),
        ):
            adhoc_mask_crack(ctx)

        ctx.hcatAdHocMask.assert_called_once()
        charset_arg = ctx.hcatAdHocMask.call_args[0][3]
        assert charset_arg == "-1 ?u?l -3 ?d?s", charset_arg


class TestRosettaAttack:
    def test_mask_choice_prompts_description_and_calls_hcatRosettaMask(self) -> None:
        ctx = _make_ctx()

        with (
            patch("hate_crack.attacks.interactive_menu", return_value="4"),
            patch("builtins.input", return_value="8 char passwords with digits"),
        ):
            rosetta_attack(ctx)

        ctx.hcatRosettaMask.assert_called_once_with(
            ctx.hcatHashType, ctx.hcatHashFile, "8 char passwords with digits"
        )

    def test_mask_choice_strips_whitespace_from_description(self) -> None:
        ctx = _make_ctx()

        with (
            patch("hate_crack.attacks.interactive_menu", return_value="4"),
            patch("builtins.input", return_value="  8 char passwords with digits  "),
        ):
            rosetta_attack(ctx)

        ctx.hcatRosettaMask.assert_called_once_with(
            ctx.hcatHashType, ctx.hcatHashFile, "8 char passwords with digits"
        )

    def test_mask_choice_on_vllm_backend_reaches_the_prompt(self) -> None:
        """The pre-flight `ctx.llmBackend != "ollama"` gate is gone (#275) --
        llm.generate_masks() now supports vllm/openai via
        rosetta_backend_kwargs, so rosetta_attack must prompt for a
        description and call hcatRosettaMask instead of short-circuiting."""
        ctx = _make_ctx()
        ctx.llmBackend = "vllm"

        with (
            patch("hate_crack.attacks.interactive_menu", return_value="4"),
            patch("builtins.input", return_value="8 char passwords with digits"),
        ):
            rosetta_attack(ctx)

        ctx.hcatRosettaMask.assert_called_once_with(
            ctx.hcatHashType, ctx.hcatHashFile, "8 char passwords with digits"
        )

    def test_mask_choice_with_blank_description_does_not_call_hcatRosettaMask(
        self,
    ) -> None:
        ctx = _make_ctx()

        with (
            patch("hate_crack.attacks.interactive_menu", return_value="4"),
            patch("builtins.input", return_value="   "),
        ):
            rosetta_attack(ctx)

        ctx.hcatRosettaMask.assert_not_called()

    def test_existing_metric_choice_1_is_unaffected(self) -> None:
        ctx = _make_ctx()
        ctx.rosetta_debug_logs.return_value = ["/tmp/debug1.log"]

        with (
            patch("hate_crack.attacks.interactive_menu", side_effect=["1", "a"]),
            patch("builtins.input", side_effect=["", ""]),
        ):
            rosetta_attack(ctx)

        ctx.hcatRosetta.assert_called_once_with(
            ctx.hcatHashType,
            ctx.hcatHashFile,
            ["/tmp/debug1.log"],
            metric="frequency",
            top_rules=None,
            top_basewords=None,
        )
        ctx.hcatRosettaMask.assert_not_called()

    def test_metric_choice_with_no_debug_logs_returns_without_calling_hcatRosetta(
        self,
    ) -> None:
        ctx = _make_ctx()
        ctx.rosetta_debug_logs.return_value = []

        with (
            patch("hate_crack.attacks.interactive_menu", side_effect=["1", "99"]),
            patch("builtins.input"),
        ):
            rosetta_attack(ctx)

        ctx.hcatRosetta.assert_not_called()
        ctx.hcatRosettaMask.assert_not_called()
