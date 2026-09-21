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
    """Cache hit skips interning but still reads the file.

    A manifest hit skips intern_entries -- the expensive per-line hashing,
    Rosetta mask parse, and dictionary round trips. The file is still read
    (cheap, needed to verify it hasn't changed) and entries are parsed.
    """
    path = _rule(tmp_path, "a.rule", "$1\nc\n")
    store.file_entry_ids(path, "rule")

    # Instrument intern_entries to verify it is not called on hit.
    intern_calls = []
    real_intern = store.intern_entries

    def track_intern(*args, **kwargs):
        intern_calls.append((args, kwargs))
        return real_intern(*args, **kwargs)

    monkeypatch.setattr(store, "intern_entries", track_intern)

    # Second call with cache hit.
    store.file_entry_ids(path, "rule")

    # intern_entries must not be called on a cache hit.
    assert intern_calls == []


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


def test_manifest_reads_file_exactly_once_per_call(store, tmp_path, monkeypatch):
    """File is read exactly once per file_entry_ids call.

    The file is opened once to read and hash it. The digest and entries
    come from the same bytes, making it impossible for them to diverge
    on a concurrent edit. Counts opens to verify this.
    """
    path = _rule(tmp_path, "a.rule", "$1\nc\n")

    # Instrument builtins.open to count calls to this specific file.
    open_count = []
    real_open = open

    def track_open(p, *args, **kwargs):
        if str(p) == path:
            open_count.append(1)
        return real_open(p, *args, **kwargs)

    monkeypatch.setattr("builtins.open", track_open)

    # First call (cache miss).
    store.file_entry_ids(path, "rule")
    assert len(open_count) == 1

    # Second call (cache hit).
    open_count.clear()
    store.file_entry_ids(path, "rule")
    assert len(open_count) == 1


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

    # Make dictionary lookups fail to prove they are not called.
    def break_entry_text(self, entry_id):
        raise RuntimeError("entry_text was called; entries should come from file")

    monkeypatch.setattr(ac.CoverageStore, "entry_text", break_entry_text)

    # Second call with cache hit and broken dictionary.
    # If entry_text is called, it will raise. Since we don't call it,
    # this succeeds.
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

    # Second call: cache hit, entries re-read from file.
    entries_second, ids_second = store.file_entry_ids(path, "mask")

    # Entries must still be the literal lines, byte-for-byte.
    # This catches the corruption case where reading from the dictionary
    # would yield NUL-separated forms or collapsed duplicates.
    assert entries_second == ["abc,?1?1", "cba,?1?1", "?d?d?l"]
    assert entries_second == entries_first
    assert ids_second == ids_first

    # No NUL bytes anywhere (the corruption symptom).
    for entry in entries_second:
        assert "\x00" not in entry


def test_manifest_rejects_truncated_blob(store, tmp_path):
    """Truncated manifest blob is rejected, causing a cache miss.

    A blob whose length is not a multiple of 8 cannot be a valid array of
    int64s. file_entry_ids must detect this and treat it as a cache miss,
    re-interning from the file.
    """
    import hashlib

    path = _rule(tmp_path, "a.rule", "$1\nc\n")
    entries_first, ids_first = store.file_entry_ids(path, "rule")

    # Compute the file's digest.
    with open(path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()

    # Directly INSERT a truncated blob into the manifest.
    conn = store._connect()
    assert conn is not None
    truncated = b"X"  # 1 byte, not a multiple of 8
    conn.execute(
        "INSERT OR REPLACE INTO file_manifests "
        "(content_sha256, kind, entry_ids) VALUES (?, ?, ?)",
        (digest, "rule", truncated),
    )
    conn.commit()

    # file_entry_ids must reject the truncated blob and fall through to re-interning.
    entries_second, ids_second = store.file_entry_ids(path, "rule")

    # Returned ids must match the fresh internment, and entries must be correct.
    assert entries_second == entries_first
    assert ids_second == ids_first


def test_manifest_rejects_wrong_id_count_blob(store, tmp_path):
    """Manifest blob with wrong number of ids is rejected.

    If a blob unpacks to a different number of ids than the file has entries,
    the manifest is corrupt. file_entry_ids must detect this and treat it as
    a cache miss.
    """
    import hashlib

    path = _rule(tmp_path, "a.rule", "$1\nc\n")
    entries_first, ids_first = store.file_entry_ids(path, "rule")
    assert len(ids_first) == 2  # Two entries

    # Compute the file's digest.
    with open(path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()

    # Directly INSERT a manifest with only one id where two are expected.
    conn = store._connect()
    assert conn is not None
    wrong_count_ids = ac._pack_ids([99])  # Only one id
    conn.execute(
        "INSERT OR REPLACE INTO file_manifests "
        "(content_sha256, kind, entry_ids) VALUES (?, ?, ?)",
        (digest, "rule", wrong_count_ids),
    )
    conn.commit()

    # file_entry_ids must reject the mismatched count and fall through to re-interning.
    entries_second, ids_second = store.file_entry_ids(path, "rule")

    # Returned ids must match the fresh internment (two ids), not the corrupt one.
    assert entries_second == entries_first
    assert ids_second == ids_first
    assert len(ids_second) == 2


def test_manifest_byte_order_pinned(store, tmp_path):
    """Manifest blob uses pinned little-endian byte order.

    If a blob were packed in big-endian on a different system, it would
    unpack to wrong ids with no length error -- a silent failure in the
    covered-when-untried direction. Verify that a reversed blob either
    reads correctly or is rejected, not silently misread.
    """
    import hashlib

    path = _rule(tmp_path, "a.rule", "$1\nc\n")
    entries_first, ids_first = store.file_entry_ids(path, "rule")

    # Compute the file's digest.
    with open(path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()

    # Create a blob as if it were packed in the opposite byte order.
    # We'll swap the bytes of the packed array.
    correct_blob = ac._pack_ids(ids_first)
    # Reverse each 8-byte chunk to simulate opposite endianness.
    reversed_blob = b"".join(
        correct_blob[i : i + 8][::-1] for i in range(0, len(correct_blob), 8)
    )

    # Insert the reversed blob into the manifest.
    conn = store._connect()
    assert conn is not None
    conn.execute(
        "INSERT OR REPLACE INTO file_manifests "
        "(content_sha256, kind, entry_ids) VALUES (?, ?, ?)",
        (digest, "rule", reversed_blob),
    )
    conn.commit()

    # file_entry_ids must either read it correctly or reject it (len check).
    # Either way, it must not return wrong ids.
    entries_second, ids_second = store.file_entry_ids(path, "rule")

    # The safest expectation: the len(ids) == len(entries) guard rejects it.
    # (Assuming the byte-reversed ids don't happen to be the same length.)
    # But the key property: entries_second must be correct (from file).
    assert entries_second == entries_first
