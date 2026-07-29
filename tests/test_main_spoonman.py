"""Tests for hcatSpoonman and the Spoonman Attack handler (#169)."""

import os
from unittest.mock import MagicMock, patch

import pytest

from hate_crack import attacks


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


@pytest.fixture
def corpus(tmp_path):
    path = tmp_path / "cracked.txt"
    path.write_text("Password1!\npassword\nSummer2026\n", encoding="latin-1")
    return str(path)


class TestHcatSpoonman:
    def _run(self, main_module, tmp_path, corpus, monkeypatch, **kwargs):
        monkeypatch.setattr(main_module, "hcatOptimizedWordlists", str(tmp_path / "opt"))
        with patch.object(main_module, "hcatQuickDictionary") as quick:
            main_module.hcatSpoonman("1000", "hashes.txt", corpus, **kwargs)
        return quick

    def test_derives_then_delegates_to_quick_dictionary(
        self, main_module, tmp_path, corpus, monkeypatch
    ):
        quick = self._run(main_module, tmp_path, corpus, monkeypatch)

        quick.assert_called_once()
        args, kwargs = quick.call_args
        assert args[0] == "1000"
        assert args[1] == "hashes.txt"
        assert args[2].startswith("-r ")
        assert args[2].endswith("rules.full.rule")
        assert args[3].endswith("basewords.txt")
        assert kwargs["attack_name"] == "Spoonman"
        assert os.path.isfile(args[3])

    def test_coverage_selects_capped_rule_file(
        self, main_module, tmp_path, corpus, monkeypatch
    ):
        quick = self._run(main_module, tmp_path, corpus, monkeypatch, coverage=95)
        assert quick.call_args[0][2].endswith("rules.top95.rule")

    def test_cache_dir_is_namespaced_per_corpus(
        self, main_module, tmp_path, corpus, monkeypatch
    ):
        quick = self._run(main_module, tmp_path, corpus, monkeypatch)
        assert os.path.join("spoonman", "cracked.txt") in quick.call_args[0][3]

    def test_missing_corpus_reports_and_does_not_run_hashcat(
        self, main_module, tmp_path, monkeypatch, capsys
    ):
        quick = self._run(
            main_module, tmp_path, str(tmp_path / "nope.txt"), monkeypatch
        )
        quick.assert_not_called()
        assert "corpus not found" in capsys.readouterr().out

    def test_empty_corpus_reports_and_does_not_run_hashcat(
        self, main_module, tmp_path, monkeypatch, capsys
    ):
        empty = tmp_path / "empty.txt"
        empty.write_text("", encoding="latin-1")
        quick = self._run(main_module, tmp_path, str(empty), monkeypatch)
        quick.assert_not_called()
        assert "Rule derivation failed" in capsys.readouterr().out

    def test_reuses_cache_when_corpus_unchanged(
        self, main_module, tmp_path, corpus, monkeypatch, capsys
    ):
        self._run(main_module, tmp_path, corpus, monkeypatch)
        capsys.readouterr()

        with patch("hate_crack.rulegen.generate") as generate:
            self._run(main_module, tmp_path, corpus, monkeypatch)
        generate.assert_not_called()
        assert "Reusing derived" in capsys.readouterr().out

    def test_regenerates_when_corpus_is_newer_than_cache(
        self, main_module, tmp_path, corpus, monkeypatch, capsys
    ):
        quick = self._run(main_module, tmp_path, corpus, monkeypatch)
        basewords = quick.call_args[0][3]
        # Corpus modified after the cache was written.
        os.utime(corpus, (os.path.getmtime(basewords) + 10,) * 2)
        capsys.readouterr()

        self._run(main_module, tmp_path, corpus, monkeypatch)
        assert "Deriving basewords" in capsys.readouterr().out

    def test_cached_run_still_honours_coverage(
        self, main_module, tmp_path, corpus, monkeypatch
    ):
        self._run(main_module, tmp_path, corpus, monkeypatch)
        quick = self._run(main_module, tmp_path, corpus, monkeypatch, coverage=99)
        assert quick.call_args[0][2].endswith("rules.top99.rule")


class TestSpoonmanAttackHandler:
    def _ctx(self, tmp_path, corpus):
        ctx = MagicMock()
        ctx.hcatWordlists = str(tmp_path)
        ctx.hcatHashType = "1000"
        ctx.hcatHashFile = "hashes.txt"
        ctx.select_file_with_autocomplete.return_value = corpus
        return ctx

    def test_passes_corpus_and_full_coverage(self, tmp_path, corpus):
        ctx = self._ctx(tmp_path, corpus)
        with patch("hate_crack.attacks.interactive_menu", return_value="1"):
            attacks.spoonman_attack(ctx)
        ctx.hcatSpoonman.assert_called_once_with(
            "1000", "hashes.txt", corpus, coverage=None
        )

    @pytest.mark.parametrize(("choice", "expected"), [("2", 99), ("3", 95)])
    def test_passes_capped_coverage(self, tmp_path, corpus, choice, expected):
        ctx = self._ctx(tmp_path, corpus)
        with patch("hate_crack.attacks.interactive_menu", return_value=choice):
            attacks.spoonman_attack(ctx)
        assert ctx.hcatSpoonman.call_args.kwargs["coverage"] == expected

    def test_blank_corpus_aborts(self, tmp_path, corpus, capsys):
        ctx = self._ctx(tmp_path, corpus)
        ctx.select_file_with_autocomplete.return_value = "  "
        attacks.spoonman_attack(ctx)
        ctx.hcatSpoonman.assert_not_called()
        assert "No corpus specified" in capsys.readouterr().out

    def test_nonexistent_corpus_aborts(self, tmp_path, capsys):
        ctx = self._ctx(tmp_path, str(tmp_path / "missing.txt"))
        attacks.spoonman_attack(ctx)
        ctx.hcatSpoonman.assert_not_called()
        assert "Corpus not found" in capsys.readouterr().out

    @pytest.mark.parametrize("choice", ["99", None])
    def test_back_out_of_rule_set_menu(self, tmp_path, corpus, choice):
        ctx = self._ctx(tmp_path, corpus)
        with patch("hate_crack.attacks.interactive_menu", return_value=choice):
            attacks.spoonman_attack(ctx)
        ctx.hcatSpoonman.assert_not_called()
