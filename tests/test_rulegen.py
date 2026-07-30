"""Tests for hate_crack.rulegen (Spoonman Attack derivation, #169)."""

import pytest

from hate_crack import rulegen

# A spread of shapes the derivation has to handle: casing patterns, leading and
# trailing and interior non-letters, letterless input, and passphrases.
CORPUS = [
    "password",
    "Password1!",
    "PASSWORD",
    "pAsSwOrD",
    "Summer2026",
    "Summer2026!",
    "p@ssw0rd",
    "Company#2026",
    "john.smith",
    "Tr0ub4dor&3",
    "correct horse battery staple",
    "!@#$%^",
    "1234567890",
    "Spring-2026!",
    "aB1cD2eF3",
    "MyD0g$Name!2026",
    "...leading",
    "trailing...",
    "a.b.c.d.e",
    "x",
    "",
]


@pytest.mark.parametrize("pw", CORPUS)
def test_derive_roundtrips(pw):
    base, rule = rulegen.derive(pw)
    assert rulegen.apply_rule(base, rule) == pw


@pytest.mark.parametrize("pw", CORPUS)
def test_derived_rules_respect_hashcat_function_limit(pw):
    _, rule = rulegen.derive(pw)
    assert rulegen.count_ops(rule) <= rulegen.MAX_RULE_FUNCTIONS


class TestHashcatLimits:
    def test_rule_over_function_limit_falls_back_to_literal(self):
        # 32 trailing specials would need 34 ops (c + insert + 32 appends).
        # hashcat drops rules over 31 functions *silently* when other valid
        # rules share the file, so the fallback has to happen at derive time.
        pw = "Passw0rd" + "!" * 32
        base, rule = rulegen.derive(pw)
        assert (base, rule) == (pw, ":")
        assert rulegen.apply_rule(base, rule) == pw

    def test_rule_at_function_limit_is_still_derived(self):
        pw = "password" + "!" * 31
        base, rule = rulegen.derive(pw)
        assert base == "password"
        assert rulegen.count_ops(rule) == rulegen.MAX_RULE_FUNCTIONS
        assert rulegen.apply_rule(base, rule) == pw

    def test_position_past_alphabet_falls_back_to_literal(self):
        # Position 36 is unaddressable in the 0-9A-Z alphabet.
        pw = "a" * 40 + "." + "b"
        base, rule = rulegen.derive(pw)
        assert (base, rule) == (pw, ":")


class TestCountOps:
    @pytest.mark.parametrize(
        ("rule", "expected"),
        [
            (":", 1),
            ("c", 1),
            ("$1$2", 2),
            ("^a^b", 2),
            ("T0T1T2", 3),
            ("i1.i3.", 2),
            ("ci50$!", 3),
        ],
    )
    def test_counts_ops(self, rule, expected):
        assert rulegen.count_ops(rule) == expected

    def test_rejects_unknown_op(self):
        with pytest.raises(ValueError, match="unknown op"):
            rulegen.count_ops("z")


class TestDeriveShapes:
    def test_all_lowercase_needs_no_case_op(self):
        assert rulegen.derive("password") == ("password", ":")

    def test_capitalized_uses_c(self):
        assert rulegen.derive("Password") == ("password", "c")

    def test_all_uppercase_uses_u(self):
        assert rulegen.derive("PASSWORD") == ("password", "u")

    def test_mixed_case_uses_toggles(self):
        base, rule = rulegen.derive("pAsSwOrD")
        assert base == "password"
        assert rule == "T1T3T5T7"

    def test_letterless_password_is_its_own_baseword(self):
        assert rulegen.derive("!@#$%^") == ("!@#$%^", ":")

    def test_interior_non_letters_use_inserts(self):
        base, rule = rulegen.derive("a.b")
        assert base == "ab"
        assert rule == "i1."

    def test_prefix_and_suffix_order(self):
        base, rule = rulegen.derive("12ab!")
        assert base == "ab"
        # Appends come before prepends; prepends are emitted in reverse.
        assert rule == "$!^2^1"
        assert rulegen.apply_rule(base, rule) == "12ab!"


class TestGenerate:
    def _write_corpus(self, tmp_path, passwords):
        path = tmp_path / "corpus.txt"
        path.write_text("\n".join(passwords) + "\n", encoding="latin-1")
        return str(path)

    def test_writes_expected_files(self, tmp_path):
        corpus = self._write_corpus(tmp_path, [p for p in CORPUS if p])
        out = tmp_path / "out"
        result = rulegen.generate(corpus, str(out), print_fn=lambda *a: None)

        assert (out / "basewords.txt").is_file()
        assert (out / "rules.full.rule").is_file()
        assert (out / "rules.top50.rule").is_file()
        assert (out / "rules.top75.rule").is_file()
        assert (out / "rules.top95.rule").is_file()
        assert (out / "rules.top99.rule").is_file()
        assert (out / "coverage.txt").is_file()
        assert result["selfcheck_failures"] == []
        assert result["total"] == len([p for p in CORPUS if p])

    def test_capped_files_default_to_four_tiers_non_decreasing(self, tmp_path):
        corpus = self._write_corpus(tmp_path, [p for p in CORPUS if p])
        out = tmp_path / "out"
        result = rulegen.generate(corpus, str(out), print_fn=lambda *a: None)

        assert set(result["capped_rules"]) == {50, 75, 95, 99}
        counts = {}
        for target, path in result["capped_rules"].items():
            with open(path, encoding="latin-1") as f:
                counts[target] = len(f.read().splitlines())
        assert counts[50] <= counts[75] <= counts[95] <= counts[99]

    def test_full_rule_set_reconstructs_whole_corpus(self, tmp_path):
        passwords = [p for p in CORPUS if p]
        corpus = self._write_corpus(tmp_path, passwords)
        out = tmp_path / "out"
        rulegen.generate(corpus, str(out), print_fn=lambda *a: None)

        basewords = (out / "basewords.txt").read_text(encoding="latin-1").splitlines()
        rules = (out / "rules.full.rule").read_text(encoding="latin-1").splitlines()
        produced = {rulegen.apply_rule(b, r) for b in basewords for r in rules}
        assert set(passwords) <= produced

    def test_rules_sorted_most_productive_first(self, tmp_path):
        # "a" and "b" need no rule (":"); "C" needs "c". So ":" outranks "c".
        corpus = self._write_corpus(tmp_path, ["a", "b", "C"])
        out = tmp_path / "out"
        rulegen.generate(corpus, str(out), print_fn=lambda *a: None)
        rules = (out / "rules.full.rule").read_text(encoding="latin-1").splitlines()
        assert rules[0] == ":"

    def test_capped_file_is_a_prefix_of_the_full_set(self, tmp_path):
        corpus = self._write_corpus(tmp_path, [p for p in CORPUS if p])
        out = tmp_path / "out"
        rulegen.generate(corpus, str(out), print_fn=lambda *a: None)
        full = (out / "rules.full.rule").read_text(encoding="latin-1").splitlines()
        top95 = (out / "rules.top95.rule").read_text(encoding="latin-1").splitlines()
        assert top95 == full[: len(top95)]

    def test_ascii_only_skips_and_counts(self, tmp_path):
        corpus = self._write_corpus(tmp_path, ["password", "pa\x01ssword"])
        out = tmp_path / "out"
        result = rulegen.generate(
            corpus, str(out), ascii_only=True, print_fn=lambda *a: None
        )
        assert result["total"] == 1
        assert result["skipped"] == 1

    def test_blank_lines_are_ignored(self, tmp_path):
        corpus = self._write_corpus(tmp_path, ["password", "", "secret"])
        out = tmp_path / "out"
        result = rulegen.generate(corpus, str(out), print_fn=lambda *a: None)
        assert result["total"] == 2

    def test_empty_corpus_raises(self, tmp_path):
        corpus = self._write_corpus(tmp_path, [])
        out = tmp_path / "out"
        with pytest.raises(ValueError, match="no passwords"):
            rulegen.generate(corpus, str(out), print_fn=lambda *a: None)

    def test_coverage_report_names_the_corpus(self, tmp_path):
        corpus = self._write_corpus(tmp_path, ["password", "Password"])
        out = tmp_path / "out"
        rulegen.generate(corpus, str(out), print_fn=lambda *a: None)
        report = (out / "coverage.txt").read_text(encoding="latin-1")
        assert corpus in report
        assert "self-check failures: 0" in report


class TestCorpusLineParsing:
    """The corpus this attack is built for is a previous engagement's cracked
    output, whose lines carry the hash in front of the password."""

    NTLM = "31d6cfe0d16ae931b73c59d7e0c089c0"
    NTLM_B = "8846f7eaee8fb117ad06bdd830b7586c"
    EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"

    def _write(self, tmp_path, lines, name="corpus.txt"):
        path = tmp_path / name
        path.write_text("\n".join(lines) + "\n", encoding="latin-1")
        return str(path)

    def _run(self, tmp_path, lines):
        corpus = self._write(tmp_path, lines)
        return rulegen.generate(corpus, str(tmp_path / "out"), print_fn=lambda *a: None)

    def _basewords(self, result):
        with open(result["basewords"], encoding="latin-1") as f:
            return f.read().split()

    def test_hash_prefix_does_not_reach_the_baseword(self, tmp_path):
        """Deriving from the whole line prepended the digest's hex digits."""
        result = self._run(tmp_path, [f"{self.NTLM}:Alphabet", f"{self.NTLM_B}:Bravo"])
        assert sorted(self._basewords(result)) == ["alphabet", "bravo"]

    def test_rules_stay_short_without_the_hash_prefix(self, tmp_path):
        """Rebuilding a 32-character prefix consumed most of MAX_RULE_FUNCTIONS."""
        result = self._run(tmp_path, [f"{self.NTLM}:Alphabet1"])
        with open(result["rules"], encoding="latin-1") as f:
            rules = f.read().split()
        assert all(rulegen.count_ops(r) <= 3 for r in rules), rules

    def test_rules_merge_across_passwords_sharing_a_transformation(self, tmp_path):
        """The whole point of the rule file: rank by productivity, then truncate.

        With the hash prefix included every rule was unique, so the ranking
        carried no information and a capped set was no cheaper than the full one.
        """
        result = self._run(
            tmp_path,
            [
                f"{self.NTLM}:Alphabet1",
                f"{self.NTLM_B}:Bravoword1",
                f"{self.NTLM}:Charlieword1",
            ],
        )
        assert result["rules_count"] == 1
        assert result["total"] == 3

    def test_hex_wrapped_plaintext_is_decoded(self, tmp_path):
        result = self._run(tmp_path, ["$HEX[616c706861]", "alpha"])
        assert self._basewords(result) == ["alpha"]
        assert result["basewords_count"] == 1

    def test_plaintext_containing_a_colon_survives(self, tmp_path):
        """A wordlist entry may hold a colon; only real hash fields are dropped."""
        result = self._run(tmp_path, ["12:30", "aabbcc:token"])
        assert result["total"] == 2
        assert "aabbcc" in "".join(self._basewords(result))

    def test_uncracked_dump_is_counted_and_reported(self, tmp_path):
        lines = [
            f"user{i}:{1100 + i}:{self.EMPTY_LM}:{self.NTLM}:::" for i in range(10)
        ]
        messages = []
        corpus = self._write(tmp_path, lines)
        result = rulegen.generate(
            corpus, str(tmp_path / "out"), print_fn=messages.append
        )
        assert result["hash_shaped"] == 10
        assert any("look like hashes" in m for m in messages)
        report = (tmp_path / "out" / "coverage.txt").read_text(encoding="latin-1")
        assert "hash-shaped lines:   10" in report

    def test_cracked_output_triggers_no_warning(self, tmp_path):
        messages = []
        corpus = self._write(tmp_path, [f"{self.NTLM}:Alphabet1", "Bravoword2"])
        result = rulegen.generate(
            corpus, str(tmp_path / "out"), print_fn=messages.append
        )
        assert result["hash_shaped"] == 0
        assert not any("look like hashes" in m for m in messages)
