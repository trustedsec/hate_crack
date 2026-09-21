"""Tests for the content-addressed rule and mask file manifest cache."""

import os

import pytest

from hate_crack import attack_coverage as ac


@pytest.fixture
def store(tmp_path):
    s = ac.CoverageStore(tmp_path / "cov.sqlite3")
    yield s
    s.close()


def _rule(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_manifest_returns_entries_and_ids(store, tmp_path):
    path = _rule(tmp_path, "a.rule", "$1\nc\n")
    entries, ids = store.file_entry_ids(path, "rule")
    assert entries == ["$1", "c"]
    assert len(ids) == 2


def test_manifest_hit_skips_interning_not_reading(store, tmp_path, monkeypatch):
    """Cache hit skips the expensive interning, but still reads the file.

    The file read is cheap (0.22s for large files). The expensive part is
    per-line hashing and mask canonicalization via Rosetta (0.55s+), which
    intern_entries performs. A manifest hit skips that.
    """
    path = _rule(tmp_path, "a.rule", "$1\nc\n")
    store.file_entry_ids(path, "rule")

    # Instrument intern_entries to count calls.
    calls = []
    real = store.intern_entries

    def track(*args, **kwargs):
        calls.append((args, kwargs))
        return real(*args, **kwargs)

    monkeypatch.setattr(store, "intern_entries", track)

    # Second call with cache hit.
    store.file_entry_ids(path, "rule")

    # intern_entries must not be called on a cache hit. The file is still
    # read to verify its content hasn't changed (and is cheap).
    assert calls == []


def test_manifest_detects_edit_that_preserves_size_and_mtime(store, tmp_path):
    """The case a (size, mtime) stat memo would miss.

    A stale manifest here drops the new lines from the filtered file handed
    to hashcat, so they are never run. Content addressing makes it
    impossible by construction.
    """
    path = _rule(tmp_path, "a.rule", "$1\nc\n")
    before = os.stat(path)
    entries_before, _ = store.file_entry_ids(path, "rule")
    # Same byte count, same mtime, different content.
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("$2\nd\n")
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert os.stat(path).st_size == before.st_size
    assert os.stat(path).st_mtime_ns == before.st_mtime_ns
    entries_after, _ = store.file_entry_ids(path, "rule")
    assert entries_before == ["$1", "c"]
    assert entries_after == ["$2", "d"]


def test_manifest_is_reused_across_paths_with_identical_content(store, tmp_path):
    a = _rule(tmp_path, "a.rule", "$1\nc\n")
    b = _rule(tmp_path, "copy.rule", "$1\nc\n")
    _, ids_a = store.file_entry_ids(a, "rule")
    _, ids_b = store.file_entry_ids(b, "rule")
    assert ids_a == ids_b


def test_manifest_separates_one_path_used_as_rule_and_mask(store, tmp_path):
    path = _rule(tmp_path, "shared.txt", "?d?d\n")
    _, as_rule = store.file_entry_ids(path, "rule")
    _, as_mask = store.file_entry_ids(path, "mask")
    assert as_rule != as_mask


def test_manifest_missing_file_returns_none(store, tmp_path):
    assert store.file_entry_ids(str(tmp_path / "nope.rule"), "rule") is None


def test_manifest_unusable_store_returns_none(tmp_path, monkeypatch):
    s = ac.CoverageStore(tmp_path / "cov.sqlite3")
    path = tmp_path / "a.rule"
    path.write_text("$1\n", encoding="utf-8")
    monkeypatch.setattr(s, "_connect", lambda: None)
    assert s.file_entry_ids(str(path), "rule") is None


def test_manifest_entries_from_file_not_dictionary(store, tmp_path, monkeypatch):
    """Entries come from the file, never from dictionary lookups.

    On a cache hit, making the dictionary unreadable must not affect the
    returned entries -- they come from the file that was parsed for the hash,
    not from dictionary lookups. This is essential because the dictionary
    holds canonicalized forms (with NUL separators), not the author's literal
    lines, and filtering must output exactly what was in the file.
    """
    path = _rule(tmp_path, "a.rule", "$1\nc\n")
    entries_first, ids_first = store.file_entry_ids(path, "rule")

    # Break the dictionary by dropping the entries table.
    def break_entry_text(self, entry_id):
        raise RuntimeError("Dictionary is unavailable")

    monkeypatch.setattr(ac.CoverageStore, "entry_text", break_entry_text)

    # Second call with cache hit and broken dictionary.
    entries_second, ids_second = store.file_entry_ids(path, "rule")

    # Entries must still be correct (from file, not dictionary).
    assert entries_second == ["$1", "c"]
    assert entries_second == entries_first
    assert ids_second == ids_first


def test_manifest_mask_entries_never_corrupted_on_cache_hit(store, tmp_path):
    """Mask entries with custom charsets are never corrupted on cache hit.

    intern_entries canonicalizes mask entries, producing forms with NUL
    separators ('abc\\x00?1?1'). These are used only for dictionary keys.
    On a cache hit, the entries returned must be the literal file lines
    ('abc,?1?1'), never the canonical forms. Two identical charsets with
    different orders must remain distinct lines.
    """
    # Two hcmask lines that differ only in custom charset order.
    path = _rule(tmp_path, "masks.hcmask", "abc,?1?1\ncba,?1?1\n?d?d?l\n")

    # First call: cache miss, entries interned.
    entries_first, ids_first = store.file_entry_ids(path, "mask")

    # Verify the literal entries on the first call.
    assert entries_first == ["abc,?1?1", "cba,?1?1", "?d?d?l"]
    # All three must have ids (no collapse).
    assert len(ids_first) == 3

    # Second call: cache hit, entries reconstructed.
    entries_second, ids_second = store.file_entry_ids(path, "mask")

    # Entries must still be the literal lines, byte-for-byte.
    # This catches the corruption case where reconstruction from the
    # dictionary would yield NUL-separated forms or collapsed duplicates.
    assert entries_second == ["abc,?1?1", "cba,?1?1", "?d?d?l"]
    assert entries_second == entries_first
    assert ids_second == ids_first

    # No NUL bytes anywhere (the corruption symptom).
    for entry in entries_second:
        assert "\x00" not in entry
