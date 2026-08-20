"""Tests for the per-target attack coverage store."""

import os
import sqlite3

import pytest

from hate_crack import attack_coverage as ac


@pytest.fixture
def store(tmp_path, monkeypatch):
    s = ac.CoverageStore(tmp_path / "coverage" / "cov.sqlite3")
    monkeypatch.setattr(ac, "get_store", lambda: s)
    yield s
    s.close()


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


# --- wordlist fingerprints -------------------------------------------------


def test_wordlist_fingerprint_is_content_addressed(store, tmp_path):
    a = _write(tmp_path / "wl1.txt", "alpha\nbravo\n")
    b = _write(tmp_path / "wl2.txt", "alpha\nbravo\n")
    assert store.wordlist_fingerprint(a) == store.wordlist_fingerprint(b)


def test_wordlist_fingerprint_memo_avoids_rehash(store, tmp_path, monkeypatch):
    path = _write(tmp_path / "wl.txt", "alpha\n")
    first = store.wordlist_fingerprint(path)

    calls = []
    monkeypatch.setattr(ac, "_sha256_file", lambda p: calls.append(p) or "x" * 64)
    store.clear_fingerprint_memo()  # drop in-process memo, keep the persisted one

    assert store.wordlist_fingerprint(path) == first
    assert calls == [], "unchanged wordlist should be served from the persisted memo"


def test_wordlist_fingerprint_rehashes_when_content_changes(store, tmp_path):
    path = tmp_path / "wl.txt"
    _write(path, "alpha\n")
    first = store.wordlist_fingerprint(str(path))
    os.utime(path, (0, 0))
    _write(path, "alpha\nbravo\n")
    assert store.wordlist_fingerprint(str(path)) != first


def test_wordlist_fingerprint_missing_file_returns_none(store, tmp_path):
    assert store.wordlist_fingerprint(str(tmp_path / "nope.txt")) is None


def test_unwritable_store_degrades_instead_of_raising(tmp_path, monkeypatch):
    """A read-only home must not take an attack down."""
    s = ac.CoverageStore(tmp_path / "nodir" / "cov.sqlite3")
    monkeypatch.setattr(
        s, "_connect", lambda: None
    )  # simulate a connection that cannot be made
    path = _write(tmp_path / "wl.txt", "alpha\n")
    assert s.wordlist_fingerprint(path) is not None  # still hashes
    assert s.covered(["k"]) == set()
    assert s.record(["k"]) == 0
    assert s.history("t") == []
    assert s.forget_target("t") == 0
    assert s.log_run("t", "Dictionary") is None


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


# --- keys ------------------------------------------------------------------


def test_entry_key_is_stable_and_distinct():
    k1 = ac.entry_key("target", "rule", "wlfp", "c", "")
    assert k1 == ac.entry_key("target", "rule", "wlfp", "c", "")
    assert k1 != ac.entry_key("target2", "rule", "wlfp", "c", "")
    assert k1 != ac.entry_key("target", "mask", "wlfp", "c", "")
    assert k1 != ac.entry_key("target", "rule", "wlfp2", "c", "")
    assert k1 != ac.entry_key("target", "rule", "wlfp", "$1", "")
    assert k1 != ac.entry_key("target", "rule", "wlfp", "c", "inc:1-8")


def test_entry_key_fields_cannot_bleed_into_each_other():
    """A NUL separator stops "ab"+"c" colliding with "a"+"bc"."""
    assert ac.entry_key("t", "rule", "ab", "c") != ac.entry_key("t", "rule", "a", "bc")


# --- store round trip ------------------------------------------------------


def test_store_round_trip(store):
    assert store.covered(["k1"]) == set()
    store.record(["k1", "k2"], target="t", kind="rule", attack="Dictionary")
    store.record(["k2", "k3"], target="t", kind="rule", attack="Dictionary")
    assert store.covered(["k1", "k2", "k3", "k4"]) == {"k1", "k2", "k3"}


def test_record_is_idempotent_and_does_not_grow_on_repeats(store):
    assert store.record(["k1", "k2"], target="t") == 2
    assert store.record(["k1", "k2"], target="t") == 0, "repeat must insert nothing"


def test_record_keeps_a_key_linked_to_the_run_that_first_covered_it(store):
    store.record(["k1"], target="t", attack="Dictionary")
    first = store._connect().execute("SELECT run_id FROM covered").fetchone()[0]
    store.record(["k1"], target="t", attack="Recycle")
    again = store._connect().execute("SELECT run_id FROM covered").fetchone()[0]
    assert first == again, "a repeat must not re-attribute an already-covered key"


def test_record_ignores_empty(store):
    assert store.record([]) == 0
    assert store.covered(["anything"]) == set()


def test_covered_table_stores_no_per_key_metadata(store):
    """Metadata lives once per run, not once per key -- 27.5 MB vs 39.6 MB."""
    cols = {
        row[1]
        for row in store._connect().execute("PRAGMA table_info(covered)").fetchall()
    }
    assert cols == {"key", "run_id"}


def test_covered_handles_more_keys_than_the_sqlite_parameter_limit(store):
    """The 999-parameter limit is why the query binds one JSON value, not N."""
    keys = [f"k{i}" for i in range(2500)]
    store.record(keys, target="t")
    assert store.covered(keys) == set(keys)


def test_covered_query_interpolates_nothing(store):
    """Static SQL with a single bound parameter -- no placeholder building."""
    assert "?" == ac._COVERED_IN_JSON[ac._COVERED_IN_JSON.index("json_each(") + 10]
    assert ac._COVERED_IN_JSON.count("?") == 1


def test_covered_falls_back_when_json1_is_missing(store, monkeypatch):
    """A SQLite built without JSON1 must still answer correctly."""
    keys = [f"k{i}" for i in range(1200)]
    store.record(keys, target="t")
    # sqlite3.Connection is immutable, so stand in a statement that fails the
    # same way a missing json_each would.
    monkeypatch.setattr(
        ac, "_COVERED_IN_JSON", "SELECT key FROM covered WHERE key IN (nope(?))"
    )
    assert store.covered(keys + ["absent"]) == set(keys)


# --- history ---------------------------------------------------------------


def test_history_records_dynamic_attacks(store):
    store.log_run("t", "PRINCE", detail="baselist=corp.txt")
    store.log_run("t", "PCFG")
    assert [row[0] for row in store.history("t")] == ["PRINCE", "PCFG"]
    assert store.history("other") == []


# --- forgetting ------------------------------------------------------------


def test_forget_target_clears_only_that_target(store):
    store.record(["a1", "a2"], target="A")
    store.record(["b1"], target="B")
    store.log_run("A", "Dictionary")
    assert store.forget_target("A") == 2
    assert store.covered(["a1", "a2", "b1"]) == {"b1"}
    assert store.history("A") == []


# --- indexing --------------------------------------------------------------


def test_covered_table_is_without_rowid(store):
    """Sound only because `covered` is narrow -- see the schema note. A wide
    WITHOUT ROWID table measured slower to insert with no size win."""
    sql = (
        store._connect()
        .execute("SELECT sql FROM sqlite_master WHERE name = 'covered'")
        .fetchone()[0]
    )
    assert "WITHOUT ROWID" in sql.upper()


def test_membership_lookup_uses_the_primary_key_index(store):
    store.record(["k1"], target="t")
    plan = (
        store._connect()
        .execute(
            "EXPLAIN QUERY PLAN SELECT key FROM covered WHERE key IN (?, ?)", ("a", "b")
        )
        .fetchall()
    )
    detail = " ".join(row[3] for row in plan)
    assert "SCAN" not in detail.upper(), (
        f"membership query degraded to a scan: {detail}"
    )


def test_forget_target_uses_the_run_index(store):
    store.record(["k1"], target="t")
    plan = (
        store._connect()
        .execute(
            "EXPLAIN QUERY PLAN DELETE FROM covered WHERE run_id IN "
            "(SELECT id FROM runs WHERE target = ?)",
            ("t",),
        )
        .fetchall()
    )
    detail = " ".join(row[3] for row in plan)
    assert "covered_run" in detail, f"forget_target degraded to a scan: {detail}"
    assert "runs_target" in detail, f"target lookup degraded to a scan: {detail}"


def test_fingerprint_lookup_uses_the_primary_key(store):
    plan = (
        store._connect()
        .execute(
            "EXPLAIN QUERY PLAN SELECT sha256 FROM wordlist_fingerprints WHERE path = ?",
            ("/x",),
        )
        .fetchall()
    )
    detail = " ".join(row[3] for row in plan)
    assert "SCAN" not in detail.upper(), detail


def test_wal_mode_is_enabled(store):
    mode = store._connect().execute("PRAGMA journal_mode").fetchone()[0]
    assert mode.lower() == "wal"


def test_concurrent_writer_does_not_error(store, tmp_path):
    """Two hate_crack instances in one engagement must not lock each other out."""
    store.record(["k1"], target="t")
    other = sqlite3.connect(str(store._path), timeout=30.0)
    try:
        other.execute("PRAGMA busy_timeout=5000")
        other.execute(
            "INSERT INTO runs (target, kind, attack, ran_at) VALUES (?,?,?,?)",
            ("t", "rule", "other-instance", "now"),
        )
        rid = other.execute("SELECT last_insert_rowid()").fetchone()[0]
        other.execute(
            "INSERT OR IGNORE INTO covered (key, run_id) VALUES (?,?)", ("k2", rid)
        )
        other.commit()
    finally:
        other.close()
    assert store.covered(["k1", "k2"]) == {"k1", "k2"}
