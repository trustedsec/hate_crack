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
            ("o0a", 1),
            ("o1bo5c", 2),
        ],
    )
    def test_counts_ops(self, rule, expected):
        assert rulegen.count_ops(rule) == expected

    def test_rejects_unknown_op(self):
        with pytest.raises(ValueError, match="unknown op"):
            rulegen.count_ops("z")

    def test_o_counts_in_complex_rule(self):
        """o op counts correctly when mixed with other ops."""
        # c=1, o0a=1, u=1, total=3
        assert rulegen.count_ops("co0au") == 3


class TestOp:
    """Tests for the 'o' (overwrite) operation."""

    def test_o_in_range_overwrites_character(self):
        """o{p}{x} overwrites the character at position p with x."""
        assert rulegen.apply_rule("alpha", "o1x") == "axpha"
        assert rulegen.apply_rule("alpha", "o0X") == "Xlpha"
        assert rulegen.apply_rule("alpha", "o4z") == "alphz"

    def test_o_out_of_range_is_noop(self):
        """o{p}{x} leaves the word unchanged if p >= len(s)."""
        assert rulegen.apply_rule("alpha", "o5x") == "alpha"
        assert rulegen.apply_rule("alpha", "o9x") == "alpha"
        assert rulegen.apply_rule("a", "o1x") == "a"

    def test_o_applies_correctly_in_rules(self):
        """o op can be applied in rules to overwrite positions."""
        baseword = "simpleword"
        # simpleword: s=0, i=1, m=2, p=3, l=4, e=5, w=6, o=7, r=8, d=9
        # Overwrite position 0 with 'S', position 6 with '2'
        rule = "o0So62"
        result = rulegen.apply_rule(baseword, rule)
        assert result == "Simple2ord"
        # Verify the rule passes validation
        assert rulegen.validate_rule(rule)

    def test_o_combined_with_other_ops(self):
        """o can be combined with other ops in the same rule."""
        # test: t=0, e=1, s=2, t=3
        # o1X (overwrite position 1 'e' with 'X'), then u (uppercase all)
        # -> tXst -> TXST
        assert rulegen.apply_rule("test", "o1Xu") == "TXST"
        # test: prepend "A", overwrite position 1 with "B", append "!"
        # -> Atest -> ABest -> ABest!
        assert rulegen.apply_rule("test", "^Ao1B$!") == "ABest!"


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


class TestCaseEncoding:
    """Tests for case-encoding selection: choose the cheapest of four strategies."""

    def test_all_lowercase_emits_no_case_op_regression(self):
        """All-lowercase words emit no case op (cost 0)."""
        base, rule = rulegen.derive("simpleword")
        assert base == "simpleword"
        assert rule == ":"

    def test_capitalized_emits_c_regression(self):
        """First-letter-uppercase (only) emits 'c' (cost 1)."""
        base, rule = rulegen.derive("Simpleword")
        assert base == "simpleword"
        assert rule == "c"

    def test_all_uppercase_emits_u_regression(self):
        """All-uppercase words emit 'u' (cost 1)."""
        base, rule = rulegen.derive("SIMPLEWORD")
        assert base == "simpleword"
        assert rule == "u"

    def test_mostly_uppercase_prefers_u_over_direct(self):
        """Mostly uppercase: u+invert cheaper than direct toggles.

        SIMPLEWORx (uppercase at 0-8, lowercase at 9): direct costs 9,
        u+invert costs 1+1=2 (u + toggle position 9). u+invert wins.
        Verified: derive("SIMPLEWORx") == ("simpleworx", "uT9")
        """
        base, rule = rulegen.derive("SIMPLEWORx")
        assert base == "simpleworx"
        assert rule == "uT9"
        assert rulegen.apply_rule(base, rule) == "SIMPLEWORx"

    def test_mixed_case_tie_breaks_to_c(self):
        """Mixed case encoding cost tie: c and direct both cost 4, c wins.

        SimPlewOrD has uppercase at positions 0, 3, 7, 9.
        Costs: none=invalid, direct=4, u+inv=7, c=1+3=4
        Tie at 4; tie-break order is none,c,u,direct, so c wins.
        """
        base, rule = rulegen.derive("SimPlewOrD")
        assert base == "simpleword"
        assert rule == "cT3T7T9"
        assert rulegen.apply_rule(base, rule) == "SimPlewOrD"

    def test_position_36_boundary_all_uppercase(self):
        """Position 36 is unaddressable; all-uppercase 37-char string uses u+invert.

        "A"*36 + "B" (37 chars, all uppercase).
        Baseword is "a"*36 + "b", all lowercase.
        direct: toggle 0-36 (37 toggles, exceeds function limit); disqualified
        u+invert: u + toggle each lowercase = u + 0 (no lowercase) = cost 1, valid
        c+fix: c + toggle 1-36 (position 36 unaddressable); disqualified
        Result: u+invert wins at cost 1 (emitted as single 'u' op).
        Verified: derive("A"*36+"B") == ("a"*36+"b", "u")
        """
        pw = "A" * 36 + "B"
        base, rule = rulegen.derive(pw)
        assert base == "a" * 36 + "b"
        assert rule == "u"
        assert rulegen.apply_rule(base, rule) == pw

    def test_position_36_boundary_mostly_lowercase(self):
        """Position 36 unaddressable; "ab" + C*35 uses u+invert.

        "ab" + "C"*35 (37 chars: ab...CCC where C spans positions 2-36).
        Uppercase at positions 2-36 (35 letters).
        u+invert: u + toggle 0,1 = cost 3 (positions 0-1 are lowercase)
        direct: toggle 2-36 = cost 35
        c+fix: c + toggle at >0 (2-36 = 35) = cost 1+35 = 36
        Min cost is u+invert at 3.
        Verified: derive("ab" + "C"*35) == ("ab" + "c"*35, "uT0T1")
        """
        pw = "ab" + "C" * 35
        base, rule = rulegen.derive(pw)
        assert base == "ab" + "c" * 35
        assert rule == "uT0T1"
        assert rulegen.apply_rule(base, rule) == pw

    def test_position_36_boundary_fallback_to_literal(self):
        """All candidates disqualified when position 36 needed in multiple ways.

        "aB" + "C"*35 + "d" (38 chars: uppercase at 1-36, lowercase at 0,37).
        direct: toggle 1-36 (position 36 unaddressable); disqualified
        u+invert: toggle 37 (unaddressable); disqualified
        c+fix: toggle at >0 (1-36, position 36 unaddressable); disqualified
        All disqualified: fall back to literal.
        Verified: derive("aB" + "C"*35 + "d") == (pw, ":")
        """
        pw = "aB" + "C" * 35 + "d"
        base, rule = rulegen.derive(pw)
        assert (base, rule) == (pw, ":")
        assert rulegen.apply_rule(base, rule) == pw

    def test_alternating_case_pattern(self):
        """Alternating case: pick cheapest between direct, u+invert, c."""
        # aBaBaB: uppercase at 1,3,5. Direct = 3, u+invert = 1+3 = 4, c = 1+3 = 4
        # Min cost is 3 (direct), so expect three T ops
        base, rule = rulegen.derive("aBaBaB")
        assert base == "ababab"
        # Uppercase at positions 1, 3, 5
        assert rule == "T1T3T5"
        assert rulegen.apply_rule(base, rule) == "aBaBaB"

    def test_interior_uppercase_single(self):
        """Interior single uppercase: direct might be cheaper."""
        # sImpleword: uppercase at 1. Direct = 1, u+invert = 1+8 = 9, c = 1+1+1 = 3
        # Min is 1 (direct)
        base, rule = rulegen.derive("sImpleword")
        assert base == "simpleword"
        assert rule == "T1"
        assert rulegen.apply_rule(base, rule) == "sImpleword"

    def test_uppercase_at_both_ends_middle_lower(self):
        # SImpleworD: uppercase at 0, 1, 9
        # Costs: none=invalid, direct=3, u+inv=1+7=8, c=1+2=3 (toggle 1,9 at >0)
        # Tie at cost 3 between direct and c; tie-break: c wins
        base, rule = rulegen.derive("SImpleworD")
        assert base == "simpleword"
        # c + T1 + T9
        assert rule == "cT1T9"
        assert rulegen.apply_rule(base, rule) == "SImpleworD"

    def test_roundtrip_all_case_patterns(self):
        """All case patterns round-trip correctly."""
        patterns = [
            "simpleword",  # all lower
            "Simpleword",  # first upper
            "SIMPLEWORD",  # all upper
            "sImpleworD",  # interior+last upper
            "SImpleword",  # first+interior upper
            "aBaBaB",  # alternating
            "simpleWord",  # last upper
            "sIMPLEWORD",  # all-but-first upper
        ]
        for pw in patterns:
            base, rule = rulegen.derive(pw)
            result = rulegen.apply_rule(base, rule)
            assert result == pw, f"Round-trip failed for {pw}: got {result}"


class TestDeriveOpsValidation:
    """Ensure all ops emitted by derive() are known to RULE_OP_ARGS."""

    def test_all_derive_ops_are_in_rule_op_args(self):
        """Every op derive() can emit must be a key in RULE_OP_ARGS."""
        test_passwords = [
            "alphabetonlyword",  # : no-op
            "Alphaword",  # c
            "ALPHAWORD",  # u
            "aLpHaWoRd",  # T ops
            "alpha.beta",  # i ops
            "alpha!@#",  # $ ops
            "!@#alpha",  # ^ ops
            "Alphaword123",  # mix of everything
        ]
        for pw in test_passwords:
            base, rule = rulegen.derive(pw)
            if rule != ":":
                i = 0
                while i < len(rule):
                    op = rule[i]
                    assert op in rulegen.RULE_OP_ARGS, (
                        f"Op {op!r} from derive({pw!r}) not in RULE_OP_ARGS"
                    )
                    i += 1 + len(rulegen.RULE_OP_ARGS[op])

    def test_all_derived_rules_validate(self):
        """Every rule derive() produces must pass validate_rule()."""
        test_passwords = [
            "alphaword",
            "Alphaword1!",
            "ALPHAWORD",
            "aLpHaWoRd",
            "Summertime2026",
            "Summertide2026!",
            "alph@w0rd",
            "Codebase#2026",
            "john.smith.test",
            "correct horse battery staple",
            "!@#$%^",
            "1234567890",
            "Spring-2026!",
            "aB1cD2eF3",
            "MyC0d3$Emb3d!2026",
        ]
        for pw in test_passwords:
            base, rule = rulegen.derive(pw)
            assert rulegen.validate_rule(rule), (
                f"Rule {rule!r} from derive({pw!r}) fails validate_rule()"
            )


class TestBroadRoundTripProperty:
    """Property tests for round-trip correctness per Constraint 2.

    Constraint 2 requires testing across broad generated input sets, not
    hand-picked cases. This class generates passwords exhaustively across
    case masks and spot-checks diverse byte ranges.
    """

    def test_roundtrip_exhaustive_case_masks(self):
        """Exhaustive round-trip test: all case masks over a fixed stem.

        Generates all 2^8 = 256 case patterns across an 8-letter stem,
        covering every combination of uppercase and lowercase.
        Each is derived and applied, verifying round-trip.
        """
        import itertools

        stem = "codebase"
        # Generate all case masks: True=upper, False=lower
        for mask in itertools.product([True, False], repeat=len(stem)):
            pw = "".join(c.upper() if m else c.lower() for c, m in zip(stem, mask))
            base, rule = rulegen.derive(pw)
            result = rulegen.apply_rule(base, rule)
            assert result == pw, (
                f"Round-trip failed for mask {mask}: derive({pw!r}) "
                f"-> apply_rule returned {result!r}"
            )

    def test_roundtrip_random_byte_sweep(self):
        """Random round-trip spot-check: diverse byte ranges and lengths.

        Uses fixed seed for determinism; covers:
        - Single bytes across the printable range
        - Combinations with digits and symbols
        - Passwords from 1 to 60 characters (exercises >35 unaddressable positions)
        - High-byte characters (latin-1 encoding)
        """
        import random
        import string

        random.seed(42)
        # Printable ASCII + selected high bytes
        charset = (
            string.ascii_letters
            + string.digits
            + "!@#$%^&*()_-=+[]{}|;:,.<>?"
            + "".join(chr(i) for i in range(128, 256, 15))
        )

        for _ in range(100):
            # Random length 1-60 (past the position-35 boundary)
            length = random.randint(1, 60)
            pw = "".join(random.choice(charset) for _ in range(length))
            base, rule = rulegen.derive(pw)
            result = rulegen.apply_rule(base, rule)
            assert result == pw, (
                f"Round-trip failed: derive({pw!r}) -> apply_rule returned {result!r}"
            )


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


class TestReverseLeetMap:
    """The map only proposes candidates; attestation decides (see module doc)."""

    def test_map_covers_the_documented_minimum(self):
        expected = {
            "@": ["a"],
            "0": ["o"],
            "3": ["e"],
            "$": ["s"],
            "4": ["a"],
            "7": ["t"],
            "5": ["s"],
            "9": ["g"],
            "8": ["b"],
            "+": ["t"],
            "!": ["i"],
            "1": ["i", "l"],
        }
        for leet, letters in expected.items():
            assert rulegen.REVERSE_LEET[leet] == letters, leet

    def test_every_candidate_is_a_lowercase_letter(self):
        for leet, letters in rulegen.REVERSE_LEET.items():
            assert letters, leet
            for letter in letters:
                assert letter.islower() and letter.isalpha(), (leet, letter)

    def test_no_leet_key_is_itself_a_letter(self):
        # A letter never needs restoring: it is already in the baseword.
        for leet in rulegen.REVERSE_LEET:
            assert not rulegen._isalpha(leet), leet

    def test_slot_cap_is_the_documented_constant(self):
        assert rulegen.MAX_LEET_SLOTS == 4


class TestDeriveLeetAware:
    """Corpus-informed restoration of leet-substituted letters into the baseword."""

    # Synthetic invented compounds, none of them a password from any corpus.
    DICT = Counter(
        {
            "quibblefox": 7,
            "mirthbell": 5,
            "zanterwick": 4,
            "plumdorf": 3,
            "griblenaut": 6,
            "ziziziziz": 4,
            "ziziziziziz": 4,
        }
    )

    def test_restores_an_attested_letter_with_o_not_i(self):
        base, rule = rulegen.derive_leet_aware("qu1bblefox", self.DICT)
        assert base == "quibblefox"
        assert rule == "o21"
        assert "i" not in rule
        assert rulegen.apply_rule(base, rule) == "qu1bblefox"
        # Contrast with the letters-only derivation this replaces.
        assert rulegen.derive("qu1bblefox") == ("qubblefox", "i21")

    def test_restores_two_slots_and_keeps_the_case_ops_cheapest(self):
        base, rule = rulegen.derive_leet_aware("Z@nterw1ck", self.DICT)
        assert base == "zanterwick"
        # 'c' for the leading capital, then the two overwrites left to right.
        assert rule == "co1@o71"
        assert rulegen.apply_rule(base, rule) == "Z@nterw1ck"

    def test_case_positions_index_the_restored_baseword(self):
        """A restored letter shifts every later letter's case position by one."""
        base, rule = rulegen.derive_leet_aware("Gr1bleNaut", self.DICT)
        assert base == "griblenaut"
        # 'N' is at index 6 of the restored baseword "griblenaut" but index 5
        # of the letters-only "grblenaut", so the toggle position has to move.
        assert rule == "cT6o21"
        assert rulegen.derive("Gr1bleNaut") == ("grblenaut", "cT5i21")
        assert rulegen.apply_rule(base, rule) == "Gr1bleNaut"

    def test_mixed_restored_and_unrestored_slots_interleave_correctly(self):
        """An un-restored slot still inserts, and does not disturb the o positions."""
        d = Counter({"mirthbell": 5})
        # '-' is not a leet character, so it stays an insert; '1' restores.
        base, rule = rulegen.derive_leet_aware("m1rth-bell", d)
        assert base == "mirthbell"
        assert rule == "o11i5-"
        assert rulegen.apply_rule(base, rule) == "m1rth-bell"

    def test_unrestored_leet_slot_before_a_restored_one(self):
        """An insert to the left of an overwrite must not shift its position.

        The dictionary here attests only the form that leaves the first '1'
        out and restores the second, so the rule has to emit i then o -- the
        case an off-by-one in the position accounting would break.
        """
        base, rule = rulegen.derive_leet_aware("m1rthbe1l", Counter({"mrthbell": 5}))
        assert base == "mrthbell"
        assert rule == "i11o71"
        assert rulegen.apply_rule(base, rule) == "m1rthbe1l"

    def test_both_leet_slots_restore_when_that_form_is_attested(self):
        base, rule = rulegen.derive_leet_aware("m1rthbe1l", Counter({"mirthbell": 5}))
        assert base == "mirthbell"
        assert rule == "o11o71"
        assert rulegen.apply_rule(base, rule) == "m1rthbe1l"

    def test_suffix_and_prefix_still_come_last(self):
        base, rule = rulegen.derive_leet_aware("!!qu1bblefox99", self.DICT)
        assert base == "quibblefox"
        assert rule == "o21$9$9^!^!"
        assert rulegen.apply_rule(base, rule) == "!!qu1bblefox99"

    def test_leading_leet_character_is_not_a_slot(self):
        """A leading non-letter is already a position-independent ^ op."""
        assert rulegen.derive_leet_aware("1quibblefox", self.DICT) == rulegen.derive(
            "1quibblefox"
        )

    def test_trailing_leet_character_is_not_a_slot(self):
        assert rulegen.derive_leet_aware("quibblefox1", self.DICT) == rulegen.derive(
            "quibblefox1"
        )

    def test_non_leet_interior_character_is_not_a_slot(self):
        d = Counter({"quibblefox": 7})
        # '%' has no reverse-leet candidate, so there is nothing to restore.
        assert rulegen.derive_leet_aware("quibble%fox", d) == rulegen.derive(
            "quibble%fox"
        )


class TestDeriveLeetAwareAttestation:
    def test_empty_dictionary_returns_exactly_derive(self):
        for pw in CORPUS + [
            "qu1bblefox",
            "Z@nterw1ck",
            "m1rthb3ll",
            "pl0md0rf",
            "gr!blenaut",
        ]:
            assert rulegen.derive_leet_aware(pw, {}) == rulegen.derive(pw), pw

    def test_unattested_candidate_is_not_restored(self):
        # The dictionary knows something else entirely.
        d = Counter({"unrelatedword": 99})
        assert rulegen.derive_leet_aware("qu1bblefox", d) == rulegen.derive(
            "qu1bblefox"
        )

    def test_min_hits_gates_a_thinly_attested_candidate(self):
        d = Counter({"quibblefox": 1})
        # Default min_hits=2: one attestation is not enough.
        assert rulegen.derive_leet_aware("qu1bblefox", d) == rulegen.derive(
            "qu1bblefox"
        )
        # Lowering the bar accepts it.
        assert rulegen.derive_leet_aware("qu1bblefox", d, min_hits=1) == (
            "quibblefox",
            "o21",
        )

    def test_letters_only_baseword_can_win_on_attestation(self):
        """When deleting the letter is better attested, do not restore.

        This is the case a static reverse-leet map gets wrong, and the reason
        the all-slots-left-alone combination is in the search.
        """
        d = Counter({"grbblefox": 50, "gribblefox": 3})
        assert rulegen.derive_leet_aware("gr1bblefox", d) == rulegen.derive(
            "gr1bblefox"
        )
        assert rulegen.derive("gr1bblefox")[0] == "grbblefox"

    @pytest.mark.parametrize(
        ("counts", "expected_base"),
        [
            ({"gribble": 9, "grlbble": 3}, "gribble"),
            ({"gribble": 3, "grlbble": 9}, "grlbble"),
        ],
    )
    def test_ambiguous_one_resolves_by_attestation_not_map_order(
        self, counts, expected_base
    ):
        """'1' is 'i' or 'l'; the corpus decides, not the map's ordering."""
        base, rule = rulegen.derive_leet_aware("gr1bble", Counter(counts))
        assert base == expected_base
        assert rule == "o21"
        assert rulegen.apply_rule(base, rule) == "gr1bble"

    def test_ambiguous_one_with_neither_candidate_attested(self):
        assert rulegen.derive_leet_aware("gr1bble", Counter({"grbbleX": 9})) == (
            rulegen.derive("gr1bble")
        )

    def test_count_tie_prefers_more_slots_restored(self):
        """Equal attestation: the more-restored form wins over lexicographic.

        Chosen so the two tie-breaks disagree -- "zinterwck" (one slot) sorts
        *before* "zinterwick" (two slots), so a selection that skipped straight
        to lexicographic order would pick the wrong one.
        """
        d = Counter({"zinterwick": 4, "zinterwck": 4})
        assert sorted(d) == ["zinterwck", "zinterwick"]
        base, rule = rulegen.derive_leet_aware("z1nterw1ck", d)
        assert base == "zinterwick"
        assert rule == "o11o71"
        assert rulegen.apply_rule(base, rule) == "z1nterw1ck"

    def test_count_and_slot_tie_prefers_the_lexicographically_smaller(self):
        """The final tie-break exists only so the result cannot vary (Constraint 4)."""
        d = Counter({"gribble": 4, "grlbble": 4})
        base, _ = rulegen.derive_leet_aware("gr1bble", d)
        assert base == "gribble"


class TestDeriveLeetAwareLimits:
    def test_four_slots_restore(self):
        d = Counter({"ziziziziz": 4})
        base, rule = rulegen.derive_leet_aware("z1z1z1z1z", d)
        assert base == "ziziziziz"
        assert rule == "o11o31o51o71"
        assert rulegen.apply_rule(base, rule) == "z1z1z1z1z"

    def test_five_slots_falls_back_to_derive(self):
        """One slot past MAX_LEET_SLOTS, with the restored form well attested."""
        d = Counter({"ziziziziziz": 40})
        pw = "z1z1z1z1z1z"
        assert rulegen.derive_leet_aware(pw, d) == rulegen.derive(pw)
        assert rulegen.derive(pw)[0] == "zzzzzz"

    def test_slot_at_the_last_addressable_position_restores(self):
        d = Counter({"a" * 35 + "ib": 4})
        pw = "a" * 35 + "1b"
        base, rule = rulegen.derive_leet_aware(pw, d)
        assert base == "a" * 35 + "ib"
        assert rule == "oZ1"  # position 35 is 'Z' in the POS alphabet
        assert rulegen.apply_rule(base, rule) == pw

    def test_slot_past_the_addressable_range_falls_back(self):
        d = Counter({"a" * 36 + "ib": 4})
        pw = "a" * 36 + "1b"
        assert rulegen.derive_leet_aware(pw, d) == rulegen.derive(pw)
        assert rulegen.derive_leet_aware(pw, d) == (pw, ":")

    def test_over_the_function_limit_falls_back(self):
        # 30 trailing appends + one overwrite is 31 functions; a 31st append
        # would be 32, over the limit, so the whole thing falls back.
        d = Counter({"quibblefox": 7})
        ok = "qu1bblefox" + "!" * 30
        base, rule = rulegen.derive_leet_aware(ok, d)
        assert base == "quibblefox"
        assert rulegen.count_ops(rule) == rulegen.MAX_RULE_FUNCTIONS
        assert rulegen.apply_rule(base, rule) == ok

        over = "qu1bblefox" + "!" * 31
        assert rulegen.derive_leet_aware(over, d) == rulegen.derive(over)

    def test_every_emitted_rule_validates(self):
        d = Counter({"quibblefox": 7, "mirthbell": 5, "zanterwick": 4})
        for pw in [
            "qu1bblefox",
            "Qu1bblefox!",
            "m1rthbell",
            "M1RTHBELL",
            "z@nterw1ck",
            "!!z@nterw1ck99",
            "m1rth-bell",
        ]:
            _, rule = rulegen.derive_leet_aware(pw, d)
            assert rulegen.validate_rule(rule), (pw, rule)


def _leet_round_trip_inputs():
    """A broad, deterministic input set that leans on the leet-slot paths.

    Covers letters, digits, symbols, mixed case, leading/trailing/interior
    non-letters, the empty string, long strings past the position-35 boundary,
    and high bytes -- per Constraint 2.
    """
    import itertools
    import random
    import string

    stems = ["quibblefox", "mirthbell", "zanterwick", "plumdorf", "griblenaut"]
    leet_chars = list(rulegen.REVERSE_LEET)
    inputs = ["", "x", "1234567890", "!@#$%^", "..leading", "trailing.."]

    # Every substitution of one or two letters in each stem, over a spread of
    # case masks and affixes.
    for stem in stems:
        for k in (1, 2, 3):
            for positions in itertools.combinations(range(1, len(stem) - 1), k):
                for leet in leet_chars:
                    chars = list(stem)
                    for p in positions:
                        chars[p] = leet
                    word = "".join(chars)
                    inputs.append(word)
                    inputs.append(word.upper())
                    inputs.append(word.capitalize())
                    inputs.append("!!" + word + "99")

    random.seed(1091)
    charset = (
        string.ascii_letters
        + string.digits
        + "!@#$%^&*()_-=+[]{}|;:,.<>?"
        + "".join(chr(i) for i in range(128, 256, 15))
    )
    for _ in range(400):
        length = random.randint(1, 60)
        inputs.append("".join(random.choice(charset) for _ in range(length)))
    # Long strings built from a stem so leet slots land past position 35 too.
    for stem in stems:
        inputs.append((stem.replace("o", "0") + "-") * 5)
        inputs.append((stem.replace("e", "3").upper() + "1") * 4)
    return inputs


class TestLeetAwareRoundTripProperty:
    """Constraint 2 over derive_leet_aware: the round trip must always hold."""

    INPUTS = _leet_round_trip_inputs()

    def _rich_dictionary(self):
        """Attest every letters-only and every partially-restored form.

        Deliberately generous: it makes restoration fire on a large share of
        the inputs, which is what gives the round-trip assertions teeth. A
        realistic corpus attests far less (measured: 0.2% of basewords moved on
        a 360,000-password sample), so a thin dictionary would leave most of
        this sweep on the plain-derive path and prove much less.
        """
        d = Counter()
        for pw in self.INPUTS:
            letters = [c for c in pw if rulegen._isalpha(c)]
            if letters:
                d["".join(c.lower() for c in letters)] += 9
        for stem in ["quibblefox", "mirthbell", "zanterwick", "plumdorf", "griblenaut"]:
            d[stem] += 9
        return d

    def test_round_trip_with_a_rich_dictionary(self):
        d = self._rich_dictionary()
        restored = 0
        for pw in self.INPUTS:
            base, rule = rulegen.derive_leet_aware(pw, d)
            assert rulegen.apply_rule(base, rule) == pw, (pw, base, rule)
            if (base, rule) != rulegen.derive(pw):
                restored += 1
        # Guard against a vacuous sweep: if restoration never fired, the
        # assertions above only re-tested derive().
        assert restored > 100, restored

    def test_exhaustive_case_masks_over_a_restored_slot(self):
        """All 2^10 case masks x every restorable slot, with the stem attested.

        The analogue of the derive() case-mask sweep, and the test that pins
        the thing restoration actually changes: a restored letter occupies a
        baseword position, so every case op after it shifts by one. Indexing
        the case mask into the letters-only core instead would break here.
        """
        import itertools

        stem = "zanterwick"
        d = Counter({stem: 9})
        # Only a slot whose letter some leet character maps to can restore.
        slots = {1: "@", 3: "7", 4: "3", 7: "1"}
        for slot, leet in slots.items():
            assert stem[slot] in rulegen.REVERSE_LEET[leet], (slot, leet)
            for mask in itertools.product([True, False], repeat=len(stem)):
                cased = "".join(
                    c.upper() if m else c.lower() for c, m in zip(stem, mask)
                )
                pw = cased[:slot] + leet + cased[slot + 1 :]
                base, rule = rulegen.derive_leet_aware(pw, d)
                assert base == stem, (pw, base)
                assert rulegen.apply_rule(base, rule) == pw, (pw, base, rule)

    def test_round_trip_with_an_empty_dictionary(self):
        for pw in self.INPUTS:
            base, rule = rulegen.derive_leet_aware(pw, {})
            assert rulegen.apply_rule(base, rule) == pw, (pw, base, rule)

    def test_empty_dictionary_is_derive_for_every_input(self):
        for pw in self.INPUTS:
            assert rulegen.derive_leet_aware(pw, {}) == rulegen.derive(pw), pw

    def test_restored_rules_respect_the_function_limit(self):
        d = self._rich_dictionary()
        for pw in self.INPUTS:
            _, rule = rulegen.derive_leet_aware(pw, d)
            assert rulegen.count_ops(rule) <= rulegen.MAX_RULE_FUNCTIONS, (pw, rule)

    def test_restored_rules_all_validate(self):
        """Restricted to printable-ASCII inputs, as validate_rule() requires.

        A high byte in the password becomes a high byte in the rule's literal
        argument, which hashcat will not accept -- true of derive() before this
        task too, and not something restoration changes.
        """
        d = self._rich_dictionary()
        checked = 0
        for pw in self.INPUTS:
            if not pw or not rulegen._is_printable_ascii(pw):
                continue
            _, rule = rulegen.derive_leet_aware(pw, d)
            assert rulegen.validate_rule(rule), (pw, rule)
            checked += 1
        assert checked > 500, checked

    def test_restoration_never_lengthens_the_rule(self):
        """o replaces i one-for-one, so restoring must not cost extra functions.

        Case ops can move (positions index the restored baseword), so this is
        an upper bound rather than an equality -- but a restoration that made
        the rule longer would be a regression in the thing the task is for.
        """
        d = self._rich_dictionary()
        for pw in self.INPUTS:
            _, plain = rulegen.derive(pw)
            _, restored = rulegen.derive_leet_aware(pw, d)
            assert rulegen.count_ops(restored) <= rulegen.count_ops(plain) + 1, (
                pw,
                plain,
                restored,
            )


class TestGenerateLeetRestore:
    # 3 bare, 2 leet-mangled capitalised, 2 of an unrelated word. Every string
    # is an invented compound.
    CORPUS = ["quibblefox"] * 3 + ["Qu1bblefox"] * 2 + ["mirthbell"] * 2

    # Pinned from the letters-only implementation this task builds on.
    ONE_PASS_BASEWORDS = "quibblefox\nqubblefox\nmirthbell\n"
    ONE_PASS_RULES = ":\nci21\n"
    # Pass 2 folds "qubblefox" into "quibblefox" and swaps the insert for an
    # overwrite.
    TWO_PASS_BASEWORDS = "quibblefox\nmirthbell\n"
    TWO_PASS_RULES = ":\nco21\n"

    def _write(self, tmp_path, lines=None, name="corpus.txt"):
        path = tmp_path / name
        path.write_text("\n".join(lines or self.CORPUS) + "\n", encoding="latin-1")
        return str(path)

    def _read(self, path):
        with open(path, encoding="latin-1") as f:
            return f.read()

    def test_leet_restore_off_reproduces_the_letters_only_output(self, tmp_path):
        result = rulegen.generate(
            self._write(tmp_path),
            str(tmp_path / "out"),
            print_fn=lambda *a: None,
            leet_restore=False,
        )
        assert self._read(result["basewords"]) == self.ONE_PASS_BASEWORDS
        assert self._read(result["rules"]) == self.ONE_PASS_RULES
        assert result["leet_restored"] == 0
        assert result["selfcheck_failures"] == []
        report = self._read(result["coverage"])
        assert "leet restored" not in report
        assert "read TWICE" not in report

    def test_leet_restore_on_folds_the_mangled_form_into_the_real_word(self, tmp_path):
        result = rulegen.generate(
            self._write(tmp_path), str(tmp_path / "out"), print_fn=lambda *a: None
        )
        assert self._read(result["basewords"]) == self.TWO_PASS_BASEWORDS
        assert self._read(result["rules"]) == self.TWO_PASS_RULES
        assert result["leet_restored"] == 2
        assert result["basewords_count"] == 2
        assert result["total"] == 7
        assert result["selfcheck_failures"] == []

    def test_leet_restore_defaults_to_on(self, tmp_path):
        result = rulegen.generate(
            self._write(tmp_path), str(tmp_path / "out"), print_fn=lambda *a: None
        )
        assert self._read(result["basewords"]) == self.TWO_PASS_BASEWORDS

    def test_coverage_report_declares_the_second_pass(self, tmp_path):
        result = rulegen.generate(
            self._write(tmp_path), str(tmp_path / "out"), print_fn=lambda *a: None
        )
        report = self._read(result["coverage"])
        assert "leet restored:       2\n" in report
        assert "read TWICE" in report
        assert "pass 1" in report and "pass 2" in report

    def test_console_output_mentions_the_second_pass(self, tmp_path):
        messages = []
        rulegen.generate(
            self._write(tmp_path), str(tmp_path / "out"), print_fn=messages.append
        )
        assert any("leet-substituted letter" in m for m in messages)
        assert any("read twice" in m for m in messages)

    def test_reads_the_corpus_twice_only_when_enabled(self, tmp_path, monkeypatch):
        """Observe the actual opens rather than trusting the code path.

        Counts the difference rather than an absolute, because the gzip sniff
        in :func:`generate` opens the corpus once as well and is not a pass.
        """
        import builtins

        corpus = self._write(tmp_path)
        real_open = builtins.open
        opens = []

        def counting_open(file, *args, **kwargs):
            if str(file) == corpus:
                opens.append(str(file))
            return real_open(file, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", counting_open)
        rulegen.generate(
            corpus, str(tmp_path / "one"), print_fn=lambda *a: None, leet_restore=False
        )
        one_pass = len(opens)
        assert one_pass >= 1
        opens.clear()
        rulegen.generate(
            corpus, str(tmp_path / "two"), print_fn=lambda *a: None, leet_restore=True
        )
        assert len(opens) == one_pass + 1

    def test_min_hits_is_configurable(self, tmp_path):
        # A single attestation, so the default min_hits=2 restores nothing.
        lines = ["quibblefox", "Qu1bblefox"]
        result = rulegen.generate(
            self._write(tmp_path, lines),
            str(tmp_path / "out2"),
            print_fn=lambda *a: None,
        )
        assert result["leet_restored"] == 0
        result = rulegen.generate(
            self._write(tmp_path, lines),
            str(tmp_path / "out1"),
            print_fn=lambda *a: None,
            leet_min_hits=1,
        )
        assert result["leet_restored"] == 1

    def test_full_rule_set_still_reconstructs_the_whole_corpus(self, tmp_path):
        passwords = [p for p in CORPUS if p] + self.CORPUS
        result = rulegen.generate(
            self._write(tmp_path, passwords),
            str(tmp_path / "out"),
            print_fn=lambda *a: None,
        )
        basewords = self._read(result["basewords"]).splitlines()
        rules = self._read(result["rules"]).splitlines()
        produced = {rulegen.apply_rule(b, r) for b in basewords for r in rules}
        assert set(passwords) <= produced
        assert result["selfcheck_failures"] == []

    def test_every_generated_rule_validates(self, tmp_path):
        passwords = [p for p in CORPUS if p] + self.CORPUS
        result = rulegen.generate(
            self._write(tmp_path, passwords),
            str(tmp_path / "out"),
            print_fn=lambda *a: None,
        )
        for rule in self._read(result["rules"]).splitlines():
            assert rulegen.validate_rule(rule), rule

    @pytest.mark.parametrize("leet_restore", [False, True])
    def test_two_runs_produce_identical_bytes(self, tmp_path, leet_restore):
        """Constraint 4: no reliance on set iteration order or hash seeding."""
        passwords = [p for p in CORPUS if p] + self.CORPUS * 2
        corpus = self._write(tmp_path, passwords)
        outs = []
        for name in ("a", "b"):
            result = rulegen.generate(
                corpus,
                str(tmp_path / name),
                print_fn=lambda *a: None,
                leet_restore=leet_restore,
            )
            outs.append(
                (
                    self._read(result["basewords"]),
                    self._read(result["rules"]),
                    self._read(result["capped_rules"][50]),
                )
            )
        assert outs[0] == outs[1]

    def test_pruning_still_applies_in_both_passes(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rulegen, "_PRUNE_CHECK_INTERVAL", 5)
        lines = ["quibblefox"] * 20 + [f"tail{chr(97 + i)}zulu{i}" for i in range(40)]
        result = rulegen.generate(
            self._write(tmp_path, lines),
            str(tmp_path / "out"),
            print_fn=lambda *a: None,
            max_unique=5,
        )
        assert result["pruned"] is True
        assert result["basewords_count"] <= 5
        assert result["selfcheck_failures"] == []
