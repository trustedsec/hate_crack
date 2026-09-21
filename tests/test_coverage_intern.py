"""Tests for coverage dictionary interning."""

import pytest

from hate_crack import attack_coverage as ac


@pytest.fixture
def store(tmp_path):
    s = ac.CoverageStore(tmp_path / "cov.sqlite3")
    yield s
    s.close()


def test_intern_entries_is_stable_and_distinct(store):
    first = store.intern_entries("rule", ["$1", "c", "sa@"])
    again = store.intern_entries("rule", ["$1", "c", "sa@"])
    assert first == again
    assert len(set(first)) == 3


def test_intern_entries_separates_kinds(store):
    rule = store.intern_entries("rule", ["c"])
    mask = store.intern_entries("mask", ["c"])
    assert rule != mask


def test_intern_entries_canonicalizes_mask_charsets(store):
    # Canonicalization collapses masks that enumerate the same candidates but
    # differ in charset spelling. Test three mechanisms:
    # (1) Charset order: 'abc,?1?1' and 'cba,?1?1' both normalize to 'abc\x00?1?1'
    # (2) Charset dedup: 'aa,?1?1' and 'a,?1?1' both normalize to 'a\x00?1?1'
    # (3) Token vs literal: '0123456789,?1?1' and '?d,?1?1' both normalize to '0123456789\x00?1?1'
    mask1a, mask1b = "abc,?1?1", "cba,?1?1"  # Different order, same charset
    mask2a, mask2b = "aa,?1?1", "a,?1?1"  # Dedup
    mask3a, mask3b = "0123456789,?1?1", "?d,?1?1"  # Token vs literal

    # Intern pairs in single call; mask kind canonicalizes, rule kind does not
    mask_ids = store.intern_entries(
        "mask", [mask1a, mask1b, mask2a, mask2b, mask3a, mask3b]
    )
    assert len(set(mask_ids)) == 3, (
        "Canonical forms should collapse 6 spellings to 3 ids"
    )
    assert mask_ids[0] == mask_ids[1], "Charset order should not matter"
    assert mask_ids[2] == mask_ids[3], "Charset dedup should not matter"
    assert mask_ids[4] == mask_ids[5], "Token vs literal should not matter"

    # Rule kind stays verbatim; same inputs should produce different ids
    rule_ids = store.intern_entries(
        "rule", [mask1a, mask1b, mask2a, mask2b, mask3a, mask3b]
    )
    assert len(set(rule_ids)) == 6, "Rule kind should not canonicalize"


def test_intern_entries_round_trips_undecodable_bytes(store, tmp_path):
    # rulegen.py writes latin-1, so read_entries yields surrogates. When a str
    # with a surrogate is bound to the database, sqlite3 raises UnicodeEncodeError
    # trying to encode it as UTF-8. _entry_blob prevents this by encoding with
    # surrogatepass first, converting to bytes before binding.
    path = tmp_path / "latin1.rule"
    path.write_bytes(b"$\xc3\n$\xa9\n")
    entries = ac.read_entries(str(path))
    assert entries == ["$\udcc3", "$\udca9"]
    ids = store.intern_entries("rule", entries)
    assert ids is not None
    assert len(set(ids)) == 2
    assert store.entry_text(ids[0]) == "$\udcc3"
    # Verify the schema declares entry as BLOB, not TEXT.
    # PRAGMA table_info reports the declared column type, whereas typeof() reports
    # the storage class of the bound value. This assertion catches a regression if
    # the schema is changed to TEXT.
    conn = store._connect()
    assert conn is not None
    schema_info = conn.execute("PRAGMA table_info(entries)").fetchall()
    entry_column = [col for col in schema_info if col[1] == "entry"]
    assert len(entry_column) == 1
    assert entry_column[0][2] == "BLOB", "entry column must be declared as BLOB"


def test_intern_entries_preserves_significant_trailing_space(store):
    ids = store.intern_entries("rule", ["$ ", "$"])
    assert len(set(ids)) == 2


def test_intern_helpers_return_none_when_store_unusable(tmp_path, monkeypatch):
    s = ac.CoverageStore(tmp_path / "cov.sqlite3")
    monkeypatch.setattr(s, "_connect", lambda: None)
    assert s.intern_entries("rule", ["c"]) is None
    assert s.intern_target("a" * 64) is None
    assert s.intern_wordlist("b" * 64) is None
    assert s.intern_variant("inc:1-8") is None


def test_intern_entries_empty_returns_empty(store):
    assert store.intern_entries("rule", []) == []


def test_intern_target_and_wordlist_and_variant_are_stable(store):
    assert store.intern_target("a" * 64) == store.intern_target("a" * 64)
    assert store.intern_wordlist("b" * 64) == store.intern_wordlist("b" * 64)
    assert store.intern_variant("inc:1-8") == store.intern_variant("inc:1-8")
    assert store.intern_variant("") != store.intern_variant("inc:1-8")
