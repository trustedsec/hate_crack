"""Unit tests for hate_crack.corpus_stats (pure aggregation, no LLM involved)."""

import gzip
import os

import pytest

os.environ["HATE_CRACK_SKIP_INIT"] = "1"
from hate_crack import corpus_stats  # noqa: E402
from hate_crack import main as hc_main  # noqa: E402

# A 32-character digest: hash fields are recognized by length, so a short
# stand-in like "aabbcc" is correctly treated as part of a password.
NTLM = "31d6cfe0d16ae931b73c59d7e0c089c0"


# --------------------------------------------------------------------------
# usable_plaintext / decode_hex_wrapper
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("token2\n", "token2"),
        ("", ""),
        ("   \t ", ""),
        (f"{NTLM}:token2", "token2"),
        (f"{NTLM}:", ""),
        # A plaintext may itself contain colons; only the hash field is dropped.
        (f"{NTLM}:frag:ment", "frag:ment"),
        # No recognizable hash field, so the line is a password in full. A
        # wordlist entry holding a colon (URL, ratio, time) must survive.
        ("aabbcc:token2", "aabbcc:token2"),
        ("12:30", "12:30"),
    ],
)
def test_usable_plaintext(raw, expected):
    assert corpus_stats.usable_plaintext(raw) == expected


def test_hex_wrapper_is_decoded():
    # "vwxyz!!" as UTF-8 bytes, which is how hashcat would emit it.
    assert corpus_stats.usable_plaintext("$HEX[70c3a4737377c3b672642121]") == (
        "p\xc3\xa4ssw\xc3\xb6rd!!"
    )


def test_hex_wrapper_decoded_after_hash_split():
    line = f"{NTLM}:$HEX[68656c6c6f]"
    assert corpus_stats.usable_plaintext(line) == "hello"


@pytest.mark.parametrize(
    "value",
    [
        "$HEX[nothex]",  # not hex digits
        "$HEX[abc]",  # odd length
        "$HEX[6865",  # unterminated
        "notawrapper",
        "$HEXX[6865]",
    ],
)
def test_malformed_hex_wrapper_passes_through(value):
    assert corpus_stats.decode_hex_wrapper(value) == value


def test_main_delegates_to_shared_plaintext_helper():
    """The sampler, the aggregator, and rulegen must agree on what a password is."""
    assert hc_main._usable_plaintext(f"{NTLM}:$HEX[68656c6c6f]") == "hello"


# --------------------------------------------------------------------------
# summarize
# --------------------------------------------------------------------------


def _corpus(tmp_path, passwords, name="corpus.txt"):
    path = tmp_path / name
    path.write_text("\n".join(passwords) + "\n", encoding="latin-1")
    return str(path)


def test_digit_only_basewords_excluded(tmp_path):
    """A PIN-heavy corpus must not fill the baseword list with digit strings."""
    path = _corpus(tmp_path, ["1234", "5678", "9012", "alpha"])
    words = dict(corpus_stats.summarize(path)["basewords"])
    assert set(words) == {"alpha"}
    # The digit-only share is still reported, just not as basewords.
    text = corpus_stats.format_summary(corpus_stats.summarize(path))
    assert "no letters" in text


def test_summarize_counts_whole_corpus(tmp_path):
    path = _corpus(tmp_path, ["Alpha2024!", "alpha1", "Bravo2024", "alpha1"])
    stats = corpus_stats.summarize(path)

    assert stats["total"] == 4
    assert stats["unique"] == 3
    basewords = dict(stats["basewords"])
    assert basewords["alpha"] == 3
    assert basewords["bravo"] == 1


def test_summarize_reports_shapes_masks_and_years(tmp_path):
    path = _corpus(tmp_path, ["Alpha2024!", "alpha1", "BRAVO", "aLpHa"])
    stats = corpus_stats.summarize(path)

    shapes = dict(stats["shapes"])
    assert shapes["Capitalized"] == 1
    assert shapes["all lowercase"] == 1
    assert shapes["ALL UPPERCASE"] == 1
    assert shapes["mIxEd case"] == 1

    assert dict(stats["years"])["2024"] == 1
    assert dict(stats["digit_suffixes"])["1"] == 1
    assert dict(stats["special_suffixes"])["!"] == 1
    assert dict(stats["specials"])["!"] == 1
    assert ("?u?l?l?l?l?d?d?d?d?s", 1) in stats["masks"]


def test_summarize_lengths(tmp_path):
    path = _corpus(tmp_path, ["abc", "abcd", "wxyz"])
    assert dict(corpus_stats.summarize(path)["lengths"]) == {3: 1, 4: 2}


def test_summarize_splits_hash_prefixed_lines(tmp_path):
    """A .out file is the corpus operators reach for most; its lines carry hashes."""
    path = _corpus(
        tmp_path,
        [
            "31d6cfe0d16ae931b73c59d7e0c089c0:Alpha2024!",
            "8846f7eaee8fb117ad06bdd830b7586c:Alpha2025!",
        ],
    )
    stats = corpus_stats.summarize(path)
    assert dict(stats["basewords"])["alpha"] == 2
    assert stats["baseword_total"] == 1


def test_summarize_decodes_hex_before_aggregating(tmp_path):
    path = _corpus(tmp_path, ["$HEX[616c706861]", "alpha"])
    stats = corpus_stats.summarize(path)
    assert dict(stats["basewords"])["alpha"] == 2
    assert stats["baseword_total"] == 1


@pytest.mark.parametrize(
    "line",
    [
        "500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
        "31d6cfe0d16ae931b73c59d7e0c089c0",
        "aad3b435b51404eeaad3b435b51404ee:x",
    ],
)
def test_looks_like_hash_line_detects_dump_lines(line):
    assert corpus_stats.looks_like_hash_line(line)


@pytest.mark.parametrize(
    "line",
    [
        "Alpha2024!",
        "frag:ment",
        "correct horse battery staple",
        "deadbeef",  # hex but far too short to be a hash
    ],
)
def test_looks_like_hash_line_leaves_plaintexts_alone(line):
    assert not corpus_stats.looks_like_hash_line(line)


def test_summarize_counts_hash_shaped_lines(tmp_path):
    """An uncracked NTDS dump must be countable so callers can warn about it."""
    dump = [
        f"user{i}:{i}:aad3b435b51404eeaad3b435b51404ee:"
        "31d6cfe0d16ae931b73c59d7e0c089c0:::"
        for i in range(10)
    ]
    stats = corpus_stats.summarize(_corpus(tmp_path, dump))
    assert stats["hash_shaped"] == 10

    clean = corpus_stats.summarize(_corpus(tmp_path, ["Alpha1"], name="clean.txt"))
    assert clean["hash_shaped"] == 0


def test_corpus_context_warns_on_a_hash_dump(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(hc_main, "ollamaMaxSampleLines", 500)
    dump = [
        f"user{i}:{i}:aad3b435b51404eeaad3b435b51404ee:"
        "31d6cfe0d16ae931b73c59d7e0c089c0:::"
        for i in range(10)
    ]
    hc_main._corpus_context(_corpus(tmp_path, dump))
    assert "look like hashes, not plaintexts" in capsys.readouterr().out


def test_corpus_context_does_not_warn_on_plaintexts(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(hc_main, "ollamaMaxSampleLines", 500)
    path = _corpus(tmp_path, ["Alpha2024!", "Bravo2025!"])
    hc_main._corpus_context(path)
    assert "look like hashes" not in capsys.readouterr().out


def test_summarize_skips_blank_lines(tmp_path):
    path = tmp_path / "blanks.txt"
    path.write_text("\nalpha\n\n   \nbeta\n")
    assert corpus_stats.summarize(str(path))["total"] == 2


def test_summarize_empty_corpus_raises(tmp_path):
    path = tmp_path / "empty.txt"
    path.write_text("\n\n   \n")
    with pytest.raises(ValueError, match="no passwords"):
        corpus_stats.summarize(str(path))


def test_summarize_missing_file_raises_oserror(tmp_path):
    with pytest.raises(OSError):
        corpus_stats.summarize(str(tmp_path / "nope.txt"))


def test_output_is_bounded_regardless_of_corpus_size(tmp_path):
    """Summary size must not scale with the corpus, or it defeats the purpose."""
    path = _corpus(tmp_path, [f"word{i:05d}" for i in range(5000)])
    stats = corpus_stats.summarize(path)

    assert stats["total"] == 5000
    assert len(stats["basewords"]) <= corpus_stats.TOP_BASEWORDS
    assert len(stats["masks"]) <= corpus_stats.TOP_MASKS
    assert len(stats["digit_suffixes"]) <= corpus_stats.TOP_SUFFIXES
    assert len(stats["years"]) <= corpus_stats.TOP_YEARS


def test_singleton_basewords_dropped_on_large_corpus(tmp_path):
    """Above the floor threshold, seen-once basewords are noise."""
    passwords = ["alpha"] * 600 + ["zetauniquetoken"]
    path = _corpus(tmp_path, passwords)
    stats = corpus_stats.summarize(path)
    words = dict(stats["basewords"])
    assert words["alpha"] == 600
    assert "zetauniquetoken" not in words


def test_singletons_kept_on_small_corpus(tmp_path):
    """Below the threshold the floor would empty the list, so it is not applied."""
    path = _corpus(tmp_path, ["alpha", "beta", "gamma"])
    words = dict(corpus_stats.summarize(path)["basewords"])
    assert set(words) == {"alpha", "beta", "gamma"}


# --------------------------------------------------------------------------
# Unicode digits (#229) — str.isdigit() is True for Unicode digits that
# int() rejects (e.g. the superscript "²"), which used to crash
# summarize() outright. The fix is a single ASCII-only digit predicate used
# by _mask, _years, and the trailing-digit-suffix run.
# --------------------------------------------------------------------------


def test_summarize_survives_unicode_digit_and_returns_usable_stats(tmp_path):
    """The crash from #229: a superscript digit must not raise, and the rest
    of the corpus must still be summarized normally."""
    path = _corpus(tmp_path, ["password1", "summer2019", "²123"])
    stats = corpus_stats.summarize(path)
    assert stats["total"] == 3
    assert dict(stats["years"])["2019"] == 1


def test_years_excludes_unicode_digit_chunk_but_finds_ascii_year():
    assert list(corpus_stats._years("²123")) == []
    assert list(corpus_stats._years("summer2019")) == ["2019"]


def test_mask_does_not_classify_unicode_digit_as_d():
    mask = corpus_stats._mask("²123")
    # The superscript falls through to the symbol class, not ?d: hashcat's
    # ?d charset is ASCII 0-9 and cannot generate this character.
    assert mask == "?s?d?d?d"


def test_trailing_digit_suffix_does_not_count_unicode_digit(tmp_path):
    path = _corpus(tmp_path, ["abc²123"])
    stats = corpus_stats.summarize(path)
    # Only the ASCII run "123" counts as the trailing digit suffix; the
    # superscript breaks the run rather than extending it.
    assert dict(stats["digit_suffixes"])["123"] == 1
    assert "²123" not in dict(stats["digit_suffixes"])


def test_arabic_indic_decimals_do_not_crash_and_are_not_ascii_digits():
    """Arabic-Indic digits (e.g. '123' in ٠-prefixed form) are Unicode
    *decimal* digits: str.isdecimal() is True and int() succeeds on them, so
    isdecimal() alone would not be a sufficient fix here. hashcat's ?d mask
    charset is ASCII 0-9 only, so this module classifies them as NOT ASCII
    digits -- consistent with _mask and the digit-suffix run, which both
    exist to describe what hashcat can actually generate.
    """
    arabic_123 = "١٢٣"
    assert arabic_123.isdecimal()
    assert int(arabic_123) == 123
    assert not corpus_stats._is_ascii_digit(arabic_123[0])
    assert corpus_stats._mask(arabic_123) == "?s?s?s"
    assert list(corpus_stats._years("a" + arabic_123)) == []


def test_ascii_digit_behaviour_unchanged_years_masks_suffixes(tmp_path):
    """Regression guard: ordinary ASCII passwords must analyze exactly as
    before this change."""
    path = _corpus(tmp_path, ["Alpha2024!", "alpha1"])
    stats = corpus_stats.summarize(path)
    assert dict(stats["years"])["2024"] == 1
    assert dict(stats["digit_suffixes"])["1"] == 1
    assert ("?u?l?l?l?l?d?d?d?d?s", 1) in stats["masks"]
    assert list(corpus_stats._years("summer2019")) == ["2019"]
    assert corpus_stats._mask("abc123") == "?l?l?l?d?d?d"


# --------------------------------------------------------------------------
# Non-ASCII passwords carry no mask (#230). Every hashcat built-in charset is
# ASCII-only and hashcat masks are byte-oriented while _mask is
# character-oriented, so a mask for a non-ASCII password is unusable in two
# independent ways. Such passwords are excluded from the mask counters and the
# exclusion is reported; every other statistic is unaffected.
# --------------------------------------------------------------------------

# Non-ASCII samples, deliberately not password-like: a superscript (#229's
# character), an accented letter, and a CJK character.
SUPERSCRIPT = "ab²x"
ACCENTED = "abéx"
CJK = "ab中x"


def _corpus_utf8(tmp_path, passwords, name="corpus_utf8.txt"):
    """Write a corpus as UTF-8 bytes, which is how hashcat emits plaintexts.

    summarize() reads latin-1, so a multi-byte character arrives as several
    non-ASCII characters -- exactly the byte/character mismatch #230 is about.
    """
    path = tmp_path / name
    path.write_bytes(("\n".join(passwords) + "\n").encode("utf-8"))
    return str(path)


def test_non_ascii_passwords_contribute_no_mask_but_count_everywhere_else(tmp_path):
    path = _corpus_utf8(tmp_path, ["abcx", SUPERSCRIPT, ACCENTED, CJK])
    stats = corpus_stats.summarize(path)

    assert stats["total"] == 4
    assert stats["mask_total"] == 1
    assert stats["mask_excluded_non_ascii"] == 3
    # The only mask reported is the ASCII password's, once.
    assert stats["masks"] == [("?l?l?l?l", 1)]
    # Lengths still cover all four (byte lengths, since the file is read as
    # latin-1), and the non-ASCII passwords still produce basewords.
    assert sum(count for _n, count in stats["lengths"]) == 4
    assert dict(stats["basewords"])
    assert sum(dict(stats["basewords"]).values()) == 4


def test_mask_shares_use_the_mask_eligible_denominator(tmp_path):
    """A wrong denominator (total) would render 30%, not 50%."""
    ascii_pws = ["abcx", "defx", "ghix"]
    non_ascii = [SUPERSCRIPT, ACCENTED, CJK, "zé", "y中", "x²", "wé"]
    path = _corpus_utf8(tmp_path, ascii_pws + non_ascii)
    stats = corpus_stats.summarize(path)

    assert stats["total"] == 10
    assert stats["mask_total"] == 3
    assert stats["masks"] == [("?l?l?l?l", 3)]

    text = corpus_stats.format_summary(stats)
    mask_line = next(line for line in text.splitlines() if line.startswith("Masks"))
    assert "?l?l?l?l (3x, 100%)" in mask_line
    # 3/10 would be the whole-corpus share and is the bug this guards.
    assert "30%" not in mask_line


def test_format_summary_names_the_exclusion_counts(tmp_path):
    path = _corpus_utf8(tmp_path, ["abcx", "defx", SUPERSCRIPT, CJK])
    text = corpus_stats.format_summary(corpus_stats.summarize(path))
    assert "Masks (over 2 of 4; 2 excluded as non-ASCII):" in text


def test_format_summary_reports_exclusion_when_no_masks_survive(tmp_path):
    path = _corpus_utf8(tmp_path, [SUPERSCRIPT, ACCENTED, CJK])
    stats = corpus_stats.summarize(path)
    assert stats["masks"] == []
    text = corpus_stats.format_summary(stats)
    assert "Masks (over 0 of 3; 3 excluded as non-ASCII): none" in text


def test_format_summary_is_byte_identical_for_an_all_ascii_corpus(tmp_path):
    """The regression guard that matters most: this text goes into an LLM
    prompt, so its shape must not change for the all-ASCII corpora every
    existing user has. Expected value written out in full, not derived.
    """
    path = _corpus(tmp_path, ["Alpha2024!", "alpha1", "alpha1", "BRAVO"])
    text = corpus_stats.format_summary(corpus_stats.summarize(path))
    assert text == (
        "Corpus: 4 passwords (3 distinct, 2 distinct basewords). "
        "These figures cover the ENTIRE corpus, not a sample.\n"
        "Lengths: 5 chars (1x, 25%), 6 chars (2x, 50%), 10 chars (1x, 25%)\n"
        "Casing: all lowercase (2x, 50%), Capitalized (1x, 25%), "
        "ALL UPPERCASE (1x, 25%)\n"
        "Masks: ?l?l?l?l?l?d (2x, 50%), ?u?l?l?l?l?d?d?d?d?s (1x, 25%), "
        "?u?u?u?u?u (1x, 25%)\n"
        "Trailing digits: 1 (2x, 50%)\n"
        "Trailing symbols: ! (1x, 25%)\n"
        "Symbols used: ! (1x, 25%)\n"
        "Years: 2024 (1x, 25%)\n"
        "\nTop basewords by share of corpus (of 2 distinct):\n"
        "  alpha (3x, 75%)\n"
        "  bravo (1x, 25%)\n"
    )
    # "Masks:" with no parenthetical is the pre-#230 rendering.
    assert "excluded as non-ASCII" not in text


# --------------------------------------------------------------------------
# format_summary
# --------------------------------------------------------------------------


def test_format_summary_mentions_whole_corpus_and_top_baseword(tmp_path):
    path = _corpus(tmp_path, ["Alpha2024!", "alpha1", "Bravo2024"])
    text = corpus_stats.format_summary(corpus_stats.summarize(path))

    assert "ENTIRE corpus" in text
    assert "3 passwords" in text
    assert "alpha" in text
    assert "Casing" in text and "Masks" in text


def test_format_summary_reports_counts_and_shares(tmp_path):
    path = _corpus(tmp_path, ["alpha"] * 3 + ["bravo"])
    text = corpus_stats.format_summary(corpus_stats.summarize(path))
    assert "alpha (3x, 75%)" in text
    assert "bravo (1x, 25%)" in text


def test_share_precision_adapts_to_small_shares():
    """Whole-percent precision would render an entire diverse corpus as "0%"."""
    assert corpus_stats._share(5000, 10000) == "5,000x, 50%"
    assert corpus_stats._share(30, 10000) == "30x, 0.3%"
    assert corpus_stats._share(3, 10000) == "3x, 0.03%"
    # Never collapses to a bare "0%", which would read as "this rank is noise".
    assert "0.0%" not in corpus_stats._share(1, 100000)


def test_share_handles_zero_total():
    assert corpus_stats._share(4, 0) == "4x"


def test_format_summary_size_is_bounded(tmp_path):
    path = _corpus(tmp_path, [f"word{i:05d}x" for i in range(5000)])
    text = corpus_stats.format_summary(corpus_stats.summarize(path))
    # Comfortably inside the 8192-token default context window; a 5,000-line
    # raw dump would not be.
    assert len(text) < 8000


def test_format_summary_handles_empty_sections(tmp_path):
    """A corpus with no symbols, digits, or years must not emit dangling labels."""
    path = _corpus(tmp_path, ["alpha", "beta"])
    text = corpus_stats.format_summary(corpus_stats.summarize(path))
    assert "Trailing digits" not in text
    assert "Years" not in text
    assert "\n\n\n" not in text


# --------------------------------------------------------------------------
# main._corpus_context — chooses stats-only vs stats+plaintexts
# --------------------------------------------------------------------------


def test_corpus_context_includes_plaintexts_when_all_fit(tmp_path, monkeypatch):
    monkeypatch.setattr(hc_main, "ollamaMaxSampleLines", 500)
    path = _corpus(tmp_path, ["Alpha2024!", "Bravo2024"])

    context = hc_main._corpus_context(path)
    assert "Alpha2024!" in context["sample"]
    assert "ENTIRE corpus" in context["summary"]


def test_corpus_context_drops_plaintexts_above_the_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(hc_main, "ollamaMaxSampleLines", 10)
    path = _corpus(tmp_path, [f"Alpha{i:04d}!" for i in range(100)])

    context = hc_main._corpus_context(path)
    assert "sample" not in context
    assert "100 passwords" in context["summary"]
    assert "alpha" in context["summary"]


def test_corpus_context_invalid_cap_falls_back_to_500(tmp_path, monkeypatch):
    monkeypatch.setattr(hc_main, "ollamaMaxSampleLines", 0)
    path = _corpus(tmp_path, ["alpha", "beta"])
    assert "sample" in hc_main._corpus_context(path)


def test_corpus_context_returns_none_for_missing_file(tmp_path, capsys):
    assert hc_main._corpus_context(str(tmp_path / "nope.txt")) is None
    assert "Error" in capsys.readouterr().out


def test_corpus_context_returns_none_for_empty_corpus(tmp_path, capsys):
    path = tmp_path / "empty.txt"
    path.write_text("\n  \n")
    assert hc_main._corpus_context(str(path)) is None
    assert "no passwords read" in capsys.readouterr().out


# --------------------------------------------------------------------------
# llm._corpus_block — labelling
# --------------------------------------------------------------------------


def test_corpus_block_labels_both_sections():
    from hate_crack import llm

    block = llm._corpus_block({"summary": "STATS", "sample": "pw1\npw2"})
    assert "CORPUS STATISTICS" in block and "STATS" in block
    assert "PASSWORDS" in block and "pw1" in block
    # Statistics first: the model should read the distribution before the list.
    assert block.index("STATS") < block.index("pw1")


def test_corpus_block_omits_absent_sections():
    from hate_crack import llm

    assert "PASSWORDS" not in llm._corpus_block({"summary": "STATS"})
    assert "CORPUS STATISTICS" not in llm._corpus_block({"sample": "pw1"})
    assert llm._corpus_block({}) == ""


# --------------------------------------------------------------------------
# gzip handling (#214) — a gzipped corpus must be decompressed before
# summarize() ever sees it, not read as latin-1 mojibake.
# --------------------------------------------------------------------------


def _gzip_corpus(tmp_path, lines, name="corpus.txt.gz"):
    """Write *lines* of "hash:plaintext" as a gzip-compressed corpus."""
    path = tmp_path / name
    with gzip.open(str(path), "wt", encoding="latin-1") as f:
        f.write("\n".join(lines) + "\n")
    return str(path)


def test_summarize_rejects_gzip_input_directly(tmp_path):
    """The defensive backstop: summarize() must refuse a gzipped path outright."""
    path = _gzip_corpus(tmp_path, [f"{NTLM}:Spring2026", f"{NTLM}:Summer2026"])
    with pytest.raises(ValueError):
        corpus_stats.summarize(path)


def test_corpus_stats_summarize_on_decompressed_gzip_has_ascii_basewords(tmp_path):
    """Direct summarize() call on the decompressed temp file behind gzip input."""
    lines = [f"{NTLM}:Spring2026", f"{NTLM}:Summer2026"]
    path = _gzip_corpus(tmp_path, lines)

    with hc_main._wordlist_path(path) as resolved:
        stats = corpus_stats.summarize(resolved)

    basewords = set(dict(stats["basewords"]))
    assert basewords == {"spring", "summer"}
    for word in basewords:
        assert all(0x20 <= ord(c) <= 0x7E for c in word), word


def test_corpus_context_end_to_end_gzip_yields_real_basewords(tmp_path, capsys):
    """_corpus_context on a gzip path must summarize real plaintexts, not mojibake."""
    lines = [f"{NTLM}:Spring2026", f"{NTLM}:Summer2026"]
    path = _gzip_corpus(tmp_path, lines)

    context = hc_main._corpus_context(path)

    assert context is not None
    summary_text = context["summary"]
    assert "spring" in summary_text.lower()
    assert "summer" in summary_text.lower()
    # The aggregate summary must describe real ASCII basewords, not mojibake
    # bytes from the raw gzip stream.
    assert all(0x20 <= ord(c) <= 0x7E or c == "\n" for c in summary_text)


def test_corpus_context_gzip_sample_branch_yields_real_plaintexts(tmp_path):
    """A small gzipped corpus (line count <= ollamaMaxSampleLines) takes the
    literal-sample branch in _corpus_context, at main.py's
    ``_sample_plaintext_file(path, cap, ...)`` call. That call used to read
    the *original*, still-gzipped path directly -- outside the
    ``_wordlist_path`` decompression the summarize() call already went
    through -- so ``context["sample"]`` carried raw gzip bytes straight into
    the LLM prompt even after the summary was fixed. This is squarely inside
    issue #214's title ("...read a gzipped corpus as binary garbage"), so the
    sample field must be checked independently of the summary field.
    """
    lines = [f"{NTLM}:Spring2026", f"{NTLM}:Summer2026"]
    path = _gzip_corpus(tmp_path, lines)
    # Well under the default 500-line cap, so the sample branch fires.
    assert len(lines) <= 500

    context = hc_main._corpus_context(path)

    assert context is not None
    assert "sample" in context
    sample_text = context["sample"]
    assert "Spring2026" in sample_text
    assert "Summer2026" in sample_text
    # The discriminating assertion: no byte outside printable ASCII. A raw
    # gzip stream decodes cleanly under latin-1, so this is the one check
    # that would have caught the original bug in the sample path.
    assert all(0x20 <= ord(c) <= 0x7E or c == "\n" for c in sample_text)
