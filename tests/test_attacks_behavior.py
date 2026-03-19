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
    thorough_combinator,
    top_mask_crack,
    yolo_combination,
)


def _make_ctx(hash_type: str = "1000", hash_file: str = "/tmp/hashes.txt") -> MagicMock:
    ctx = MagicMock()
    ctx.hcatHashType = hash_type
    ctx.hcatHashFile = hash_file
    return ctx


class TestLoopbackAttack:
    def test_no_rules_proceeds_without_rules(self, tmp_path: Path) -> None:
        ctx = _make_ctx()
        ctx.hcatWordlists = str(tmp_path / "wordlists")
        ctx.rulesDirectory = str(tmp_path / "rules")
        os.makedirs(ctx.rulesDirectory, exist_ok=True)

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

    def test_empty_wordlist_passed_to_hcatQuickDictionary(
        self, tmp_path: Path
    ) -> None:
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

        ctx.hcatBruteForce.assert_called_once_with(ctx.hcatHashType, ctx.hcatHashFile, "1", "7")
        ctx.hcatDictionary.assert_called_once_with(ctx.hcatHashType, ctx.hcatHashFile)
        ctx.hcatTopMask.assert_called_once_with(ctx.hcatHashType, ctx.hcatHashFile, 4 * 60 * 60)
        ctx.hcatFingerprint.assert_called_once_with(
            ctx.hcatHashType, ctx.hcatHashFile, 7, run_hybrid_on_expanded=False
        )
        ctx.hcatCombination.assert_called_once_with(ctx.hcatHashType, ctx.hcatHashFile)
        ctx.hcatHybrid.assert_called_once_with(ctx.hcatHashType, ctx.hcatHashFile)
        ctx.hcatGoodMeasure.assert_called_once_with(ctx.hcatHashType, ctx.hcatHashFile)

    def test_calls_recycle_after_each_attack(self) -> None:
        ctx = _make_ctx()

        extensive_crack(ctx)

        # extensive_crack calls hcatRecycle after: brute, dictionary, mask,
        # fingerprint, combination, hybrid, and once more at the end (hcatExtraCount)
        assert ctx.hcatRecycle.call_count == 7
        ctx.hcatRecycle.assert_any_call(ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatBruteCount)
        ctx.hcatRecycle.assert_any_call(
            ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatDictionaryCount
        )
        ctx.hcatRecycle.assert_any_call(ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatMaskCount)
        ctx.hcatRecycle.assert_any_call(
            ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatFingerprintCount
        )
        ctx.hcatRecycle.assert_any_call(
            ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatCombinationCount
        )
        ctx.hcatRecycle.assert_any_call(ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatHybridCount)
        ctx.hcatRecycle.assert_any_call(ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatExtraCount)


class TestTopMaskCrack:
    def test_default_time_uses_four_hours(self) -> None:
        ctx = _make_ctx()

        with patch("builtins.input", return_value=""):
            top_mask_crack(ctx)

        ctx.hcatTopMask.assert_called_once_with(ctx.hcatHashType, ctx.hcatHashFile, 4 * 60 * 60)

    def test_custom_time_converts_hours_to_seconds(self) -> None:
        ctx = _make_ctx()

        with patch("builtins.input", return_value="2"):
            top_mask_crack(ctx)

        ctx.hcatTopMask.assert_called_once_with(ctx.hcatHashType, ctx.hcatHashFile, 2 * 60 * 60)

    def test_one_hour_input(self) -> None:
        ctx = _make_ctx()

        with patch("builtins.input", return_value="1"):
            top_mask_crack(ctx)

        ctx.hcatTopMask.assert_called_once_with(ctx.hcatHashType, ctx.hcatHashFile, 1 * 60 * 60)


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


class TestSimpleAttacks:
    def test_pathwell_crack(self) -> None:
        ctx = _make_ctx()

        pathwell_crack(ctx)

        ctx.hcatPathwellBruteForce.assert_called_once_with(ctx.hcatHashType, ctx.hcatHashFile)

    def test_prince_attack(self) -> None:
        ctx = _make_ctx()

        prince_attack(ctx)

        ctx.hcatPrince.assert_called_once_with(ctx.hcatHashType, ctx.hcatHashFile)

    def test_yolo_combination(self) -> None:
        ctx = _make_ctx()

        yolo_combination(ctx)

        ctx.hcatYoloCombination.assert_called_once_with(ctx.hcatHashType, ctx.hcatHashFile)

    def test_thorough_combinator(self) -> None:
        ctx = _make_ctx()

        thorough_combinator(ctx)

        ctx.hcatThoroughCombinator.assert_called_once_with(ctx.hcatHashType, ctx.hcatHashFile)

    def test_middle_combinator(self) -> None:
        ctx = _make_ctx()

        middle_combinator(ctx)

        ctx.hcatMiddleCombinator.assert_called_once_with(ctx.hcatHashType, ctx.hcatHashFile)

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

        with patch("builtins.input", side_effect=["ACME", "tech", "NYC"]):
            ollama_attack(ctx)

        ctx.hcatOllama.assert_called_once_with(
            ctx.hcatHashType,
            ctx.hcatHashFile,
            "target",
            {"company": "ACME", "industry": "tech", "location": "NYC"},
        )

    def test_passes_hash_type_and_file(self) -> None:
        ctx = _make_ctx(hash_type="1800", hash_file="/tmp/sha512.txt")

        with patch("builtins.input", side_effect=["Corp", "finance", "London"]):
            ollama_attack(ctx)

        call_args = ctx.hcatOllama.call_args[0]
        assert call_args[0] == "1800"
        assert call_args[1] == "/tmp/sha512.txt"

    def test_strips_whitespace_from_inputs(self) -> None:
        ctx = _make_ctx()

        with patch("builtins.input", side_effect=["  ACME  ", "  tech  ", "  NYC  "]):
            ollama_attack(ctx)

        target_info = ctx.hcatOllama.call_args[0][3]
        assert target_info["company"] == "ACME"
        assert target_info["industry"] == "tech"
        assert target_info["location"] == "NYC"

    def test_target_string_is_literal_target(self) -> None:
        ctx = _make_ctx()

        with patch("builtins.input", side_effect=["X", "Y", "Z"]):
            ollama_attack(ctx)

        assert ctx.hcatOllama.call_args[0][2] == "target"
