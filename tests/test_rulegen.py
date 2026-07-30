"""Tests for hate_crack.rulegen (Spoonman Attack derivation, #169)."""

from collections import Counter

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

    def test_gzip_corpus_raises(self, tmp_path):
        """Defensive backstop (#214): generate() must refuse a gzipped path
        outright rather than reading it as latin-1 mojibake."""
        import gzip

        corpus = tmp_path / "corpus.txt.gz"
        with gzip.open(str(corpus), "wt", encoding="latin-1") as f:
            f.write("password\nsecret\n")
        out = tmp_path / "out"
        with pytest.raises(ValueError, match="gzip"):
            rulegen.generate(str(corpus), str(out), print_fn=lambda *a: None)

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


class TestMemoryBound:
    """`generate()` bounds each counter so a huge corpus degrades gracefully."""

    # A frequency skew with an unambiguous winner: three tokens repeated many
    # times each, and a long tail of tokens seen exactly once. Every token is a
    # synthetic phonetic-alphabet word, not a password.
    HOT = ["alphaalpha", "bravobravo", "charliecharlie"]

    def _skewed_corpus(self, tmp_path, tail=40):
        lines = []
        for token in self.HOT:
            lines.extend([token] * 20)
        # Unique in both counters: a distinct letter core (so a distinct
        # baseword) and a distinct digit suffix (so a distinct rule).
        lines.extend(
            f"tail{chr(97 + i // 26)}{chr(97 + i % 26)}zulu{i}" for i in range(tail)
        )
        path = tmp_path / "corpus.txt"
        path.write_text("\n".join(lines) + "\n", encoding="latin-1")
        return str(path)

    def _read(self, path):
        with open(path, encoding="latin-1") as f:
            return f.read()

    def _outputs(self, outdir):
        names = ("basewords.txt", "rules.full.rule", "coverage.txt")
        return {n: self._read(str(outdir / n)) for n in names}

    def test_default_bound_is_the_documented_constant(self):
        assert rulegen.MAX_UNIQUE_KEYS == 20_000_000

    # A corpus whose every derived artefact is short enough to write down.
    # 5x a bare lowercase token, 3x a capitalised token with a digit, 2x a
    # token with a trailing punctuation mark. All synthetic.
    LITERAL_CORPUS = ["alpha"] * 5 + ["Bravo1"] * 3 + ["delta!"] * 2
    LITERAL_BASEWORDS = "alpha\nbravo\ndelta\n"
    LITERAL_RULES = ":\nc$1\n$!\n"
    LITERAL_MILESTONES = {50: 1, 75: 2, 80: 2, 90: 3, 95: 3, 99: 3, 100: 3}
    LITERAL_CAPPED = {
        50: ":\n",
        75: ":\nc$1\n",
        95: ":\nc$1\n$!\n",
        99: ":\nc$1\n$!\n",
    }

    @pytest.mark.parametrize("max_unique", [None, rulegen.MAX_UNIQUE_KEYS])
    def test_unpruned_output_matches_pinned_literal_values(self, tmp_path, max_unique):
        """The bound must not change results for a corpus that never reaches it.

        Pinned against values captured from the pre-bound implementation.
        Comparing a bounded run to an unbounded one would be vacuous: both take
        the unpruned path, so a regression in the coverage denominator would
        move both arms identically and the assertion could never fail. Literal
        expectations are the only form that catches it.
        """
        path = tmp_path / "corpus.txt"
        path.write_text("\n".join(self.LITERAL_CORPUS) + "\n", encoding="latin-1")
        out = tmp_path / "out"
        result = rulegen.generate(
            str(path), str(out), print_fn=lambda *a: None, max_unique=max_unique
        )

        assert self._read(result["basewords"]) == self.LITERAL_BASEWORDS
        assert self._read(result["rules"]) == self.LITERAL_RULES
        assert result["milestones"] == self.LITERAL_MILESTONES
        for target, expected in self.LITERAL_CAPPED.items():
            assert self._read(result["capped_rules"][target]) == expected, target
        assert result["total"] == 10
        assert result["basewords_count"] == 3
        assert result["rules_count"] == 3
        assert result["pruned"] is False
        assert result["reconstructable_min"] == 10
        assert result["reconstructable_max"] == 10

        report = self._read(result["coverage"])
        assert "passwords:           10\n" in report
        assert "unique basewords:    3\n" in report
        # Substring, not `"pruned" not in report`: the corpus path is in there.
        assert "pruned (max_unique" not in report
        assert report.endswith(
            "rules needed for coverage:\n"
            "   50%: 1 rules\n"
            "   75%: 2 rules\n"
            "   80%: 2 rules\n"
            "   90%: 3 rules\n"
            "   95%: 3 rules\n"
            "   99%: 3 rules\n"
            "  100%: 3 rules\n"
        )

    def test_pruned_milestones_use_the_retained_denominator(
        self, tmp_path, monkeypatch
    ):
        """The denominator change only bites when pruning fires, so pin it there.

        6 repeats of one token plus 6 singletons, each singleton unique in both
        counters. Pruning leaves 7 of the 12 passwords covered by the surviving
        rules; against the old `total` denominator the top rule would reach
        only 50% and the 90/95/99/100 milestones would never be recorded.
        """
        monkeypatch.setattr(rulegen, "_PRUNE_CHECK_INTERVAL", 4)
        lines = ["alpha"] * 6 + [f"bravo{chr(97 + i)}{i}" for i in range(6)]
        path = tmp_path / "corpus.txt"
        path.write_text("\n".join(lines) + "\n", encoding="latin-1")
        result = rulegen.generate(
            str(path), str(tmp_path / "out"), print_fn=lambda *a: None, max_unique=2
        )

        assert result["total"] == 12
        assert result["pruned_rule_hits"] == 5
        assert result["milestones"] == {
            50: 1,
            75: 1,
            80: 1,
            90: 2,
            95: 2,
            99: 2,
            100: 2,
        }
        report = self._read(result["coverage"])
        assert "(percentages are of the 7 passwords the retained" in report

    def test_small_corpus_reports_no_pruning(self, tmp_path):
        corpus = self._skewed_corpus(tmp_path)
        result = rulegen.generate(
            corpus, str(tmp_path / "out"), print_fn=lambda *a: None
        )
        assert result["pruned"] is False
        assert result["pruned_basewords"] == 0
        assert result["pruned_rules"] == 0
        report = self._read(result["coverage"])
        assert "pruned (max_unique" not in report

    def test_tiny_bound_prunes_the_low_frequency_tail(self, tmp_path, monkeypatch):
        # The real check interval is a million lines; shrink it so a corpus
        # small enough for a test can trip the bound.
        monkeypatch.setattr(rulegen, "_PRUNE_CHECK_INTERVAL", 10)
        corpus = self._skewed_corpus(tmp_path)
        messages = []
        result = rulegen.generate(
            corpus,
            str(tmp_path / "out"),
            print_fn=messages.append,
            max_unique=5,
        )

        assert result["pruned"] is True
        assert result["pruned_basewords"] > 0
        assert result["pruned_baseword_hits"] > 0
        assert result["pruned_rules"] > 0
        assert result["pruned_rule_hits"] > 0
        # The repeated tokens survive; the once-seen tail is discarded, bar the
        # few lines read after the final size check.
        basewords = self._read(result["basewords"]).split()
        for token in self.HOT:
            assert token in basewords
        assert len([w for w in basewords if w.startswith("tail")]) <= 2
        assert result["basewords_count"] <= 5

        report = self._read(result["coverage"])
        assert "pruned (max_unique=5)" in report
        assert f"basewords discarded: {result['pruned_basewords']}" in report
        assert "retained" in report
        assert any("Memory bound reached" in m for m in messages)
        assert any("max_unique=5" in m for m in messages)
        assert any("sample" in m for m in messages)

    def test_baseword_only_pruning_is_reported_honestly(self, tmp_path, monkeypatch):
        """Only the baseword counter overflows, so rule coverage is intact.

        The rule denominator alone would then claim full coverage while most of
        the corpus has no surviving baseword to apply those rules to. The report
        has to say so, and must not print a "not of all N read" note against a
        denominator that is still N.
        """
        monkeypatch.setattr(rulegen, "_PRUNE_CHECK_INTERVAL", 5)
        # 60 distinct letter cores sharing one rule shape, plus a hot token.
        tail = [f"tail{chr(97 + i // 26)}{chr(97 + i % 26)}zulu" for i in range(60)]
        lines = tail + ["alphaalpha"] * 20
        path = tmp_path / "corpus.txt"
        path.write_text("\n".join(lines) + "\n", encoding="latin-1")
        messages = []
        result = rulegen.generate(
            str(path), str(tmp_path / "out"), print_fn=messages.append, max_unique=5
        )

        assert result["pruned"] is True
        assert result["pruned_basewords"] > 0
        assert result["pruned_baseword_hits"] > 0
        assert result["pruned_rules"] == 0
        assert result["pruned_rule_hits"] == 0
        # Rule coverage is untouched, so the reconstructable count is driven
        # entirely by the baseword losses and is exact rather than a range.
        assert result["reconstructable_max"] == 80 - result["pruned_baseword_hits"]
        assert result["reconstructable_min"] == result["reconstructable_max"]

        report = self._read(result["coverage"])
        assert "not of all" not in report
        assert "basewords were pruned" in report
        assert (
            f"still reconstructable: {result['reconstructable_max']} of 80 passwords"
            in report
        )

        warning = next(m for m in messages if "Memory bound reached" in m)
        assert f"{result['pruned_baseword_hits']} of 80 passwords" in warning
        assert "0 on the rule side" in warning

    def test_pruning_does_not_cause_selfcheck_failures(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rulegen, "_PRUNE_CHECK_INTERVAL", 10)
        corpus = self._skewed_corpus(tmp_path)
        result = rulegen.generate(
            corpus,
            str(tmp_path / "out"),
            print_fn=lambda *a: None,
            max_unique=2,
            verify=True,
        )
        assert result["pruned"] is True
        assert result["selfcheck_failures"] == []

    def test_total_still_counts_every_password(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rulegen, "_PRUNE_CHECK_INTERVAL", 10)
        corpus = self._skewed_corpus(tmp_path)
        result = rulegen.generate(
            corpus, str(tmp_path / "out"), print_fn=lambda *a: None, max_unique=5
        )
        assert result["total"] == 3 * 20 + 40


class TestPruneCounter:
    def test_no_op_when_already_within_the_bound(self):
        counter = Counter({"alpha": 3, "bravo": 1})
        assert rulegen._prune_counter(counter, 5) == (0, 0)
        assert counter == Counter({"alpha": 3, "bravo": 1})

    def test_none_disables_the_bound(self):
        counter = Counter({"alpha": 1, "bravo": 1})
        assert rulegen._prune_counter(counter, None) == (0, 0)
        assert len(counter) == 2

    def test_removes_whole_frequency_tiers_from_the_bottom(self):
        counter = Counter({"alpha": 9, "bravo": 5, "charlie": 2, "delta": 1, "echo": 1})
        keys, hits = rulegen._prune_counter(counter, 3)
        assert (keys, hits) == (2, 2)
        assert counter == Counter({"alpha": 9, "bravo": 5, "charlie": 2})

    def test_raises_the_threshold_until_the_bound_is_met(self):
        counter = Counter({"alpha": 9, "bravo": 2, "charlie": 2, "delta": 1})
        keys, hits = rulegen._prune_counter(counter, 1)
        assert (keys, hits) == (3, 5)
        assert counter == Counter({"alpha": 9})

    def test_all_keys_tied_still_honours_the_bound(self):
        """A single tier that overflows is cut partway, not left in place.

        Giving up here would return a counter still over the bound and let it
        grow unchecked for the rest of the read.
        """
        counter = Counter({f"token{i:03d}": 1 for i in range(100)})
        keys, hits = rulegen._prune_counter(counter, 10)
        assert (keys, hits) == (90, 90)
        assert len(counter) == 10

    def test_partial_cut_applies_after_whole_tiers_are_cleared(self):
        """Lower tiers go first; only the leftover tie is cut arbitrarily."""
        counter = Counter({"alpha": 1, "bravo": 1})
        counter.update({f"token{i:02d}": 5 for i in range(4)})
        keys, hits = rulegen._prune_counter(counter, 2)
        assert len(counter) == 2
        # Both frequency-1 keys, then two of the four tied 5s.
        assert (keys, hits) == (4, 1 + 1 + 5 + 5)
        assert set(counter.values()) == {5}

    def test_overshooting_the_bound_is_allowed(self):
        """Clearing a whole tier may leave far fewer keys than the bound."""
        counter = Counter({"alpha": 4, "bravo": 1, "charlie": 1, "delta": 1})
        keys, _ = rulegen._prune_counter(counter, 3)
        assert keys == 3
        assert len(counter) == 1
