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


def test_intern_entries_round_trips_undecodable_bytes(store, tmp_path):
    # rulegen.py writes latin-1, so read_entries yields surrogates. A TEXT
    # column raises UnicodeEncodeError on these; a BLOB column must not.
    path = tmp_path / "latin1.rule"
    path.write_bytes(b"$\xc3\n$\xa9\n")
    entries = ac.read_entries(str(path))
    assert entries == ["$\udcc3", "$\udca9"]
    ids = store.intern_entries("rule", entries)
    assert ids is not None
    assert len(set(ids)) == 2
    assert store.entry_text(ids[0]) == "$\udcc3"


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
