"""Tests for the per-target attack coverage store."""

import os


from hate_crack import attack_coverage as ac


def _write(path, text):
    path.write_text(text, encoding="utf-8")
    return str(path)


# --- target identity -------------------------------------------------------


def test_target_id_is_content_addressed(tmp_path):
    a = _write(tmp_path / "a.txt", "aad3b435b51404ee\n")
    b = _write(tmp_path / "renamed.txt", "aad3b435b51404ee\n")
    assert ac.target_id(a) == ac.target_id(b)


def test_target_id_changes_with_content(tmp_path):
    a = _write(tmp_path / "a.txt", "hash1\n")
    b = _write(tmp_path / "b.txt", "hash2\n")
    assert ac.target_id(a) != ac.target_id(b)


def test_target_id_missing_file_returns_none(tmp_path):
    assert ac.target_id(str(tmp_path / "nope.txt")) is None


# --- rule / mask entry parsing --------------------------------------------


def test_read_entries_skips_comments_and_blanks(tmp_path):
    # A whitespace-only line is a no-op rule, so it is dropped. `$ ` is not
    # whitespace-only and is preserved -- see the test below.
    path = _write(tmp_path / "r.rule", "# header\n\nc\n$1\n\n  \n")
    assert ac.read_entries(path) == ["c", "$1"]


def test_read_entries_preserves_significant_trailing_space(tmp_path):
    """`$ ` appends a space. Stripping it would silently change the rule."""
    path = _write(tmp_path / "r.rule", "$ \n$1\n")
    assert ac.read_entries(path) == ["$ ", "$1"]


def test_read_entries_handles_crlf(tmp_path):
    path = _write(tmp_path / "r.rule", "c\r\n$1\r\n")
    assert ac.read_entries(path) == ["c", "$1"]


def test_read_entries_deduplicates_preserving_order(tmp_path):
    path = _write(tmp_path / "r.rule", "c\n$1\nc\n")
    assert ac.read_entries(path) == ["c", "$1"]


def test_read_entries_missing_file_returns_empty(tmp_path):
    assert ac.read_entries(str(tmp_path / "nope.rule")) == []


# --- lossless round trip ---------------------------------------------------


def test_read_entries_preserves_non_utf8_bytes(tmp_path):
    """rulegen.py writes latin-1, so undecodable bytes must survive verbatim."""
    path = tmp_path / "latin1.rule"
    path.write_bytes(b"$\xe9\nc\n")
    entries = ac.read_entries(str(path))
    assert len(entries) == 2
    assert entries[0].encode("utf-8", errors="surrogateescape") == b"$\xe9"


def test_read_entries_does_not_split_on_exotic_line_breaks(tmp_path):
    r"""str.splitlines() breaks on \x0b, \x0c, \x1c-\x1e and U+2028 -- all of
    which a rule can legitimately append. Only \n and \r\n are terminators."""
    path = tmp_path / "vt.rule"
    path.write_bytes("$\x0b\n$\x0c\n$ \n".encode())
    assert ac.read_entries(str(path)) == ["$\x0b", "$\x0c", "$ "]


def test_read_entries_handles_a_missing_final_newline(tmp_path):
    path = tmp_path / "r.rule"
    path.write_bytes(b"c\n$1")
    assert ac.read_entries(str(path)) == ["c", "$1"]


# --- target memo -----------------------------------------------------------


def test_target_id_is_memoized(tmp_path, monkeypatch):
    """hcatCorporateMasks asks once per mask length; a large NTLM dump would
    otherwise be re-read eight times."""
    ac.clear_target_memo()
    path = _write(tmp_path / "t.hash", "aad3b435b51404ee\n")
    first = ac.target_id(path)
    calls = []
    monkeypatch.setattr(ac, "_sha256_file", lambda p: calls.append(p) or "x" * 64)
    assert ac.target_id(path) == first
    assert calls == []
    ac.clear_target_memo()


def test_target_id_memo_notices_a_changed_file(tmp_path):
    ac.clear_target_memo()
    path = tmp_path / "t.hash"
    _write(path, "one\n")
    first = ac.target_id(str(path))
    os.utime(path, (0, 0))
    _write(path, "two\n")
    assert ac.target_id(str(path)) != first
    ac.clear_target_memo()


# --- mask canonicalization -------------------------------------------------


class TestCanonicalMaskEntry:
    """Two hcmask lines that enumerate the same candidates must key alike;
    two that do not must not."""

    def test_charset_token_and_literal_spelling_agree(self):
        # ?d and 0123456789 expand to the same charset.
        assert ac.canonical_mask_entry("?d,?1?1") == ac.canonical_mask_entry(
            "0123456789,?1?1"
        )

    def test_duplicate_chars_collapse(self):
        # hashcat deduplicates a custom charset, so "aa" is the charset "a".
        assert ac.canonical_mask_entry("aa,?1?1") == ac.canonical_mask_entry("a,?1?1")

    def test_charset_order_is_irrelevant(self):
        # Order changes enumeration order, not the candidate set.
        assert ac.canonical_mask_entry("ab,?1?1") == ac.canonical_mask_entry("ba,?1?1")

    def test_slot_order_is_relevant(self):
        # ?1 and ?2 are not interchangeable: "a" then "b" differs from "b" then "a".
        assert ac.canonical_mask_entry("a,b,?1?2") != ac.canonical_mask_entry(
            "b,a,?1?2"
        )

    def test_different_masks_stay_distinct(self):
        assert ac.canonical_mask_entry("abc,?1?1") != ac.canonical_mask_entry(
            "abc,?1?1?1"
        )

    def test_trailing_space_is_significant(self):
        # A mask is whitespace-significant: the space is a literal position.
        assert ac.canonical_mask_entry("abc,?1?1 ") != ac.canonical_mask_entry(
            "abc,?1?1"
        )

    def test_plain_mask_is_returned_verbatim(self):
        # Keeps pre-existing keys for charset-less masks bit-identical.
        for entry in ("?d?d?d?d", "Summer?d?d", "?a?a ", ""):
            assert ac.canonical_mask_entry(entry) == entry

    def test_unparseable_mask_keys_on_raw_text(self):
        # Invalid is hashcat's to report; this must still be stable, not raise.
        assert ac.canonical_mask_entry("abc,?z?z") == "abc,?z?z"
        assert ac.canonical_mask_entry("a,b,c,d,e,f,g,h,i,?1") == (
            "a,b,c,d,e,f,g,h,i,?1"
        )

    def test_stable_across_calls(self):
        assert ac.canonical_mask_entry("?d,?1?1") == ac.canonical_mask_entry("?d,?1?1")


# --- entry hashing ---------------------------------------------------------


def test_entry_hash_is_a_signed_64_bit_int():
    value = ac.entry_hash("rule", "c $1")
    assert isinstance(value, int)
    assert -(2**63) <= value < 2**63
    assert value == ac.entry_hash("rule", "c $1")
    assert value != ac.entry_hash("rule", "c $2")


def test_entry_hash_distinguishes_rules_with_undecodable_bytes(tmp_path):
    """Non-UTF-8 rules must not share a hash.

    ``read_entries`` decodes with surrogateescape, so ``$\\xa1`` and ``$\\xa9``
    survive as distinct strings. Encoding with ``errors="replace"`` mapped both
    bytes to U+FFFD and collapsed them, so running one rule marked the other
    covered -- 154 rules of Bandrel's Spoonman file, in the wild.
    """
    path = tmp_path / "latin1.rule"
    path.write_bytes(b"$\xc3$\xa1\n$\xc3$\xa9\n$\xc3$\xb3\n")

    entries = ac.read_entries(str(path))
    assert len(entries) == 3

    assert len({ac.entry_hash("rule", entry) for entry in entries}) == 3


def test_equivalent_masks_share_a_hash():
    assert ac.entry_hash("mask", "?d,?1?1") == ac.entry_hash("mask", "0123456789,?1?1")


def test_rule_entries_are_not_canonicalized():
    # A rule has no such normalization and its text is significant.
    assert ac.entry_hash("rule", "?d,?1?1") != ac.entry_hash("rule", "0123456789,?1?1")


def test_plain_mask_hash_is_the_blake2b_of_the_raw_text():
    # A charset-less mask is hashed exactly as written.
    import hashlib

    digest = hashlib.blake2b(b"?d?d?d?d", digest_size=8).digest()
    assert ac.entry_hash("mask", "?d?d?d?d") == int.from_bytes(
        digest, "big", signed=True
    )


def test_equivalent_masks_recorded_once(tmp_path):
    # End to end through a real store: the second spelling reads as covered.
    store = ac.CoverageStore(tmp_path / "cov.sqlite3")
    try:
        first = ac.entry_hash("mask", "aa,?1?1")
        store.record(
            target="t",
            kind="mask",
            variant="",
            attack="Smart Mask",
            wordlist_ids=(),
            rows=((ac.NO_WORDLIST, first),),
        )
        second = ac.entry_hash("mask", "a,?1?1")
        assert store.covered("t", ac.NO_WORDLIST, "", "mask", [second]) == {second}
    finally:
        store.close()


def test_concurrent_writers_on_one_store_file_do_not_error(tmp_path):
    """Two hate_crack instances in one engagement must not lock each other out."""
    path = tmp_path / "shared.sqlite3"
    one = ac.CoverageStore(path)
    other = ac.CoverageStore(path)
    try:
        h1 = ac.entry_hash("mask", "?d?d")
        h2 = ac.entry_hash("mask", "?l?l")
        for store, entry_h, attack in ((one, h1, "one"), (other, h2, "other")):
            store.record(
                target="t",
                kind="mask",
                variant="",
                attack=attack,
                wordlist_ids=(),
                rows=((ac.NO_WORDLIST, entry_h),),
            )
        assert one.covered("t", ac.NO_WORDLIST, "", "mask", [h1, h2]) == {h1, h2}
    finally:
        one.close()
        other.close()
