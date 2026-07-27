"""Regression tests for issue #110: pushover notifications were silently
dropped because the name passed to ``prompt_notify_for_attack`` (and
cached in ``_run_consent``) differed from the ``attack_name`` later
passed to ``_run_hcat_cmd``.

Each test below pins the contract: the same string the user consented
to under is the string that ``_run_hcat_cmd`` receives.
"""
import os
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


def _common_patches(main_module):
    return [
        patch.object(main_module, "hcatBin", "hashcat"),
        patch.object(main_module, "hcatTuning", ""),
        patch.object(main_module, "hcatPotfilePath", ""),
        patch.object(main_module, "generate_session_id", return_value="test_session"),
    ]


def _enter_all(stack: ExitStack, ctxmgrs):
    return [stack.enter_context(cm) for cm in ctxmgrs]


class TestQuickDictionaryAttackName:
    """``hcatQuickDictionary`` is shared by Quick Crack and Loopback.
    Both must surface their own prompt name to ``_run_hcat_cmd``.
    """

    def test_default_attack_name_preserved(self, main_module, tmp_path: Path) -> None:
        hash_file = str(tmp_path / "hashes.txt")
        wordlist = str(tmp_path / "words.txt")
        with ExitStack() as stack:
            run = stack.enter_context(patch("hate_crack.main._run_hcat_cmd"))
            stack.enter_context(
                patch("hate_crack.main._add_debug_mode_for_rules", side_effect=lambda c: c)
            )
            stack.enter_context(patch("hate_crack.main._debug_cmd"))
            _enter_all(stack, _common_patches(main_module))
            main_module.hcatQuickDictionary("1000", hash_file, "", wordlist)
        assert run.call_args.kwargs["attack_name"] == "Quick Dictionary"

    def test_quick_crack_override(self, main_module, tmp_path: Path) -> None:
        hash_file = str(tmp_path / "hashes.txt")
        wordlist = str(tmp_path / "words.txt")
        with ExitStack() as stack:
            run = stack.enter_context(patch("hate_crack.main._run_hcat_cmd"))
            stack.enter_context(
                patch("hate_crack.main._add_debug_mode_for_rules", side_effect=lambda c: c)
            )
            stack.enter_context(patch("hate_crack.main._debug_cmd"))
            _enter_all(stack, _common_patches(main_module))
            main_module.hcatQuickDictionary(
                "1000", hash_file, "", wordlist, attack_name="Quick Crack"
            )
        assert run.call_args.kwargs["attack_name"] == "Quick Crack"

    def test_loopback_override(self, main_module, tmp_path: Path) -> None:
        hash_file = str(tmp_path / "hashes.txt")
        wordlist = str(tmp_path / "words.txt")
        with ExitStack() as stack:
            run = stack.enter_context(patch("hate_crack.main._run_hcat_cmd"))
            stack.enter_context(
                patch("hate_crack.main._add_debug_mode_for_rules", side_effect=lambda c: c)
            )
            stack.enter_context(patch("hate_crack.main._debug_cmd"))
            _enter_all(stack, _common_patches(main_module))
            main_module.hcatQuickDictionary(
                "1000",
                hash_file,
                "",
                wordlist,
                loopback=True,
                attack_name="Loopback",
            )
        assert run.call_args.kwargs["attack_name"] == "Loopback"


class TestPrinceAttackName:
    """``hcatPrince`` is shared by PRINCE (direct) and PRINCE-LING
    (delegated via ``hcatPrinceLing``).  Both must surface their own
    name.
    """

    def _stub_prince_env(self, main_module, tmp_path: Path):
        prince_base = tmp_path / "prince_base.txt"
        prince_base.write_text("password\n")
        prince_dir = tmp_path / "princeprocessor"
        prince_dir.mkdir()
        (prince_dir / "pp64.bin").touch()
        return [
            patch.object(main_module, "hate_path", str(tmp_path)),
            patch.object(main_module, "hcatPrinceBaseList", [str(prince_base)]),
        ]

    def test_default_attack_name_is_prince(self, main_module, tmp_path: Path) -> None:
        hash_file = str(tmp_path / "hashes.txt")
        with ExitStack() as stack:
            run = stack.enter_context(patch("hate_crack.main._run_hcat_cmd"))
            popen = stack.enter_context(patch("hate_crack.main.subprocess.Popen"))
            popen.return_value = MagicMock(stdout=MagicMock(), wait=MagicMock())
            _enter_all(stack, _common_patches(main_module))
            _enter_all(stack, self._stub_prince_env(main_module, tmp_path))
            main_module.hcatPrince("1000", hash_file)
        assert run.call_args.kwargs["attack_name"] == "PRINCE"

    def test_prince_ling_override(self, main_module, tmp_path: Path) -> None:
        hash_file = str(tmp_path / "hashes.txt")
        with ExitStack() as stack:
            run = stack.enter_context(patch("hate_crack.main._run_hcat_cmd"))
            popen = stack.enter_context(patch("hate_crack.main.subprocess.Popen"))
            popen.return_value = MagicMock(stdout=MagicMock(), wait=MagicMock())
            _enter_all(stack, _common_patches(main_module))
            _enter_all(stack, self._stub_prince_env(main_module, tmp_path))
            main_module.hcatPrince("1000", hash_file, attack_name="PRINCE-LING")
        assert run.call_args.kwargs["attack_name"] == "PRINCE-LING"


class TestSingleCallerWrapperNames:
    """Wrappers that have a single user-facing handler should pass the
    name the user saw at the prompt, not the internal function-style
    label.
    """

    def test_ngram_x_uses_ngram_label(self, main_module, tmp_path: Path) -> None:
        hash_file = str(tmp_path / "hashes.txt")
        corpus = tmp_path / "corpus.txt"
        corpus.write_text("word\n")
        ngram_dir = tmp_path / "hashcat-utils" / "bin"
        ngram_dir.mkdir(parents=True)
        (ngram_dir / "ngramX.bin").touch()
        with ExitStack() as stack:
            run = stack.enter_context(patch("hate_crack.main._run_hcat_cmd"))
            popen = stack.enter_context(patch("hate_crack.main.subprocess.Popen"))
            popen.return_value = MagicMock(stdout=MagicMock(), wait=MagicMock())
            stack.enter_context(patch.object(main_module, "hate_path", str(tmp_path)))
            _enter_all(stack, _common_patches(main_module))
            main_module.hcatNgramX("1000", hash_file, str(corpus), 3)
        assert run.call_args.kwargs["attack_name"] == "N-gram"

    def test_combination_uses_combinator_label(
        self, main_module, tmp_path: Path
    ) -> None:
        hash_file = str(tmp_path / "hashes.txt")
        wl1 = tmp_path / "w1.txt"
        wl2 = tmp_path / "w2.txt"
        wl1.write_text("a\n")
        wl2.write_text("b\n")
        with ExitStack() as stack:
            run = stack.enter_context(patch("hate_crack.main._run_hcat_cmd"))
            stack.enter_context(patch.object(main_module, "hcatWordlists", str(tmp_path)))
            stack.enter_context(patch.object(main_module, "lineCount", return_value=0))
            stack.enter_context(
                patch.object(main_module, "hcatHashCracked", 0, create=True)
            )
            _enter_all(stack, _common_patches(main_module))
            main_module.hcatCombination(
                "1000", hash_file, wordlists=[str(wl1), str(wl2)]
            )
        assert run.call_args.kwargs["attack_name"] == "Combinator"

    def test_combinator3_uses_combinator_label(
        self, main_module, tmp_path: Path
    ) -> None:
        hash_file = str(tmp_path / "hashes.txt")
        wls = []
        for i in range(3):
            p = tmp_path / f"w{i}.txt"
            p.write_text(f"x{i}\n")
            wls.append(str(p))
        combinator3 = tmp_path / "hashcat-utils" / "bin" / "combinator3.bin"
        combinator3.parent.mkdir(parents=True)
        combinator3.touch()
        with ExitStack() as stack:
            run = stack.enter_context(patch("hate_crack.main._run_hcat_cmd"))
            popen = stack.enter_context(patch("hate_crack.main.subprocess.Popen"))
            popen.return_value = MagicMock(stdout=MagicMock(), wait=MagicMock())
            stack.enter_context(patch.object(main_module, "hate_path", str(tmp_path)))
            stack.enter_context(patch.object(main_module, "lineCount", return_value=0))
            stack.enter_context(
                patch.object(main_module, "hcatHashCracked", 0, create=True)
            )
            _enter_all(stack, _common_patches(main_module))
            main_module.hcatCombinator3("1000", hash_file, wls)
        assert run.call_args.kwargs["attack_name"] == "Combinator"

    def test_combinatorX_uses_combinator_label(
        self, main_module, tmp_path: Path
    ) -> None:
        hash_file = str(tmp_path / "hashes.txt")
        wls = []
        for i in range(2):
            p = tmp_path / f"w{i}.txt"
            p.write_text(f"x{i}\n")
            wls.append(str(p))
        combinatorX = tmp_path / "hashcat-utils" / "bin" / "combinatorX.bin"
        combinatorX.parent.mkdir(parents=True)
        combinatorX.touch()
        with ExitStack() as stack:
            run = stack.enter_context(patch("hate_crack.main._run_hcat_cmd"))
            popen = stack.enter_context(patch("hate_crack.main.subprocess.Popen"))
            popen.return_value = MagicMock(stdout=MagicMock(), wait=MagicMock())
            stack.enter_context(patch.object(main_module, "hate_path", str(tmp_path)))
            stack.enter_context(patch.object(main_module, "lineCount", return_value=0))
            stack.enter_context(
                patch.object(main_module, "hcatHashCracked", 0, create=True)
            )
            _enter_all(stack, _common_patches(main_module))
            main_module.hcatCombinatorX("1000", hash_file, wls)
        assert run.call_args.kwargs["attack_name"] == "Combinator"


class TestHandlersPassThroughPromptName:
    """High-level: the attack-handler functions in ``attacks.py`` must
    pass the same name they prompted with down to the wrapper, so that
    consent set by the prompt aligns with the consent check inside
    ``_should_fire``.
    """

    def _make_ctx(self, tmp_path: Path) -> MagicMock:
        ctx = MagicMock()
        ctx.hcatHashType = "1000"
        ctx.hcatHashFile = str(tmp_path / "hashes.txt")
        ctx.hcatWordlists = str(tmp_path / "wordlists")
        ctx.rulesDirectory = str(tmp_path / "rules")
        return ctx

    def test_quick_crack_handler_passes_quick_crack_label(
        self, tmp_path: Path
    ) -> None:
        from hate_crack.attacks import quick_crack

        ctx = self._make_ctx(tmp_path)
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "best66.rule").write_text("")
        wordlist_dir = tmp_path / "wordlists"
        wordlist_dir.mkdir(parents=True, exist_ok=True)
        wordlist = wordlist_dir / "rockyou.txt"
        wordlist.write_text("password\n")
        ctx.hcatOptimizedWordlists = str(wordlist_dir)
        ctx.list_wordlist_files.return_value = ["rockyou.txt"]
        with patch("builtins.input", side_effect=[str(wordlist), "1"]):
            quick_crack(ctx)
        ctx.hcatQuickDictionary.assert_called_once()
        assert (
            ctx.hcatQuickDictionary.call_args.kwargs.get("attack_name")
            == "Quick Crack"
        )

    def test_loopback_handler_passes_loopback_label(self, tmp_path: Path) -> None:
        from hate_crack.attacks import loopback_attack

        ctx = self._make_ctx(tmp_path)
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "best66.rule").write_text("")
        with patch("builtins.input", return_value="1"):
            loopback_attack(ctx)
        ctx.hcatQuickDictionary.assert_called_once()
        kw = ctx.hcatQuickDictionary.call_args.kwargs
        assert kw.get("attack_name") == "Loopback"
        assert kw.get("loopback") is True

    def test_prince_ling_hcatPrinceLing_passes_prince_ling_label(
        self, main_module, tmp_path: Path
    ) -> None:
        """``hcatPrinceLing`` delegates to ``hcatPrince``. The delegated
        call must carry ``attack_name="PRINCE-LING"`` so per-run consent
        keyed on "PRINCE-LING" actually matches.
        """
        hash_file = str(tmp_path / "hashes.txt")
        pcfg_root = tmp_path / "pcfg_cracker"
        (pcfg_root / "Rules" / "DEFAULT").mkdir(parents=True)
        (pcfg_root / "prince_ling.py").write_text("# stub")
        cache_dir = tmp_path / "optimized"
        cache_dir.mkdir(parents=True)
        cache_path = cache_dir / "pcfg_prince_ling_DEFAULT.txt"
        cache_path.write_text("password\n")
        # Make ruleset_dir older than cache so no regen runs.
        os.utime(pcfg_root / "Rules" / "DEFAULT", (0, 0))
        with ExitStack() as stack:
            stack.enter_context(patch.object(main_module, "hate_path", str(tmp_path)))
            stack.enter_context(
                patch.object(
                    main_module, "hcatOptimizedWordlists", str(cache_dir)
                )
            )
            stack.enter_context(patch.object(main_module, "pcfgRuleset", "DEFAULT"))
            prince = stack.enter_context(patch.object(main_module, "hcatPrince"))
            main_module.hcatPrinceLing("1000", hash_file)
        prince.assert_called_once()
        assert prince.call_args.kwargs.get("attack_name") == "PRINCE-LING"
