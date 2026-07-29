"""Unit tests for hate_crack.corpus_stats (pure aggregation, no LLM involved)."""

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
    monkeypatch.setattr(hc_main, "ollamaMaxSampleLines", 500, raising=False)
    dump = [
        f"user{i}:{i}:aad3b435b51404eeaad3b435b51404ee:"
        "31d6cfe0d16ae931b73c59d7e0c089c0:::"
        for i in range(10)
    ]
    hc_main._corpus_context(_corpus(tmp_path, dump))
    assert "look like hashes, not plaintexts" in capsys.readouterr().out


def test_corpus_context_does_not_warn_on_plaintexts(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(hc_main, "ollamaMaxSampleLines", 500, raising=False)
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
    monkeypatch.setattr(hc_main, "ollamaMaxSampleLines", 500, raising=False)
    path = _corpus(tmp_path, ["Alpha2024!", "Bravo2024"])

    context = hc_main._corpus_context(path)
    assert "Alpha2024!" in context["sample"]
    assert "ENTIRE corpus" in context["summary"]


def test_corpus_context_drops_plaintexts_above_the_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(hc_main, "ollamaMaxSampleLines", 10, raising=False)
    path = _corpus(tmp_path, [f"Alpha{i:04d}!" for i in range(100)])

    context = hc_main._corpus_context(path)
    assert "sample" not in context
    assert "100 passwords" in context["summary"]
    assert "alpha" in context["summary"]


def test_corpus_context_invalid_cap_falls_back_to_500(tmp_path, monkeypatch):
    monkeypatch.setattr(hc_main, "ollamaMaxSampleLines", 0, raising=False)
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
