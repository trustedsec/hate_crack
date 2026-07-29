"""Tests for hcatSpoonman and the Spoonman Attack handler (#169)."""

import os
from unittest.mock import MagicMock, patch

import pytest

from hate_crack import attacks, rulegen


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


@pytest.fixture
def corpus(tmp_path):
    path = tmp_path / "cracked.txt"
    path.write_text("Password1!\npassword\nSummer2026\n", encoding="latin-1")
    return str(path)


class TestHcatSpoonman:
    def _hash_file(self, tmp_path):
        return str(tmp_path / "hashes.txt")

    def _run(self, main_module, tmp_path, corpus, monkeypatch, **kwargs):
        with patch.object(main_module, "hcatQuickDictionary") as quick:
            main_module.hcatSpoonman(
                "1000", self._hash_file(tmp_path), corpus, **kwargs
            )
        return quick

    def test_derives_then_delegates_to_quick_dictionary(
        self, main_module, tmp_path, corpus, monkeypatch
    ):
        quick = self._run(main_module, tmp_path, corpus, monkeypatch)

        quick.assert_called_once()
        args, kwargs = quick.call_args
        assert args[0] == "1000"
        assert args[1] == self._hash_file(tmp_path)
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

    def test_output_lives_beside_the_hash_file(
        self, main_module, tmp_path, corpus, monkeypatch
    ):
        quick = self._run(main_module, tmp_path, corpus, monkeypatch)
        expected_dir = self._hash_file(tmp_path) + ".spoonman"
        assert os.path.dirname(quick.call_args[0][3]) == expected_dir
        assert os.path.isdir(expected_dir)

    def test_cleanup_removes_derived_output(
        self, main_module, tmp_path, corpus, monkeypatch
    ):
        hash_file = self._hash_file(tmp_path)
        self._run(main_module, tmp_path, corpus, monkeypatch)
        assert os.path.isdir(hash_file + ".spoonman")

        monkeypatch.setattr(main_module, "hcatHashFile", hash_file, raising=False)
        monkeypatch.setattr(main_module, "hcatHashFileOrig", hash_file, raising=False)
        monkeypatch.setattr(main_module, "hcatHashType", "1000", raising=False)
        monkeypatch.setattr(main_module, "pwdump_format", False, raising=False)
        main_module.cleanup()
        assert not os.path.exists(hash_file + ".spoonman")

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


# --------------------------------------------------------------------------
# validate_rule — screens rule text this module did not write
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rule",
    [
        ":",
        "l",
        "c$2$0$2$5",
        "$!",
        "^a",
        "T3",
        "TA",
        "sao",
        "i3x",
        "x12",
        "p2",
        "c $2 $0",  # spaces are legal function separators
        "$ ",  # ...and a space is also a legal argument
        "[]",
        "u$1$2$3",
        "d",
        "r",
    ],
)
def test_validate_rule_accepts(rule):
    assert rulegen.validate_rule(rule) is True


@pytest.mark.parametrize(
    "rule",
    [
        "",
        None,
        123,
        "QQQ",  # not a hashcat op
        "$",  # argument runs off the end
        "i3",  # second argument missing
        "M",  # memory op: documented, but this hashcat will not run it
        "<5",  # reject-plain op: same
        "X123",  # memory extract: same
        "# comment",
        "c\t$1",  # non-printable
        "c$é",  # non-ASCII
        "   ",  # separators only, no functions
        "$1" * (rulegen.MAX_RULE_FUNCTIONS + 1),  # over the function ceiling
        "l" * (rulegen.MAX_RULE_LENGTH + 1),  # over the line-length ceiling
    ],
)
def test_validate_rule_rejects(rule):
    assert rulegen.validate_rule(rule) is False


def test_validate_rule_accepts_everything_derive_emits():
    """derive's output must survive the screen it shares a module with."""
    for pw in ["alpha", "Alpha2024!", "!!Delta-99", "sTuVwX", "12345", "a"]:
        _, rule = rulegen.derive(pw)
        assert rulegen.validate_rule(rule) is True, pw


@pytest.mark.parametrize("rule", ["h", "H", "S", "v23", "B23"])
def test_validate_rule_rejects_v7_only_ops(rule):
    """Deliberate: hashcat v7 runs these, v6 does not, and v6 drops them silently."""
    assert rulegen.validate_rule(rule) is False


@pytest.mark.parametrize(
    "rule",
    ["Ta", "T!", "Tz", "z!", "D!", "'!", "i!x", "x!2", "*!2", "y!", "O!2", "p!", "3!x"],
)
def test_validate_rule_rejects_bad_position_arguments(rule):
    """Counting arguments is not enough: a position must come from POS.

    hashcat rejects 'Ta' exactly as silently as it rejects an unknown op, so an
    arity-only check would let this class straight through to the rule file.
    """
    assert rulegen.validate_rule(rule) is False


@pytest.mark.parametrize("rule", ["e!", "@!", "s!x", "i2!", "o2!", "32!", "$!", "^!"])
def test_validate_rule_allows_any_literal_character_argument(rule):
    """The other half of the same rule: literal-argument slots take punctuation."""
    assert rulegen.validate_rule(rule) is True
