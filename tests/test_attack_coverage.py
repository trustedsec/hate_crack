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


def test_entry_key_distinguishes_rules_with_undecodable_bytes(tmp_path):
    """Non-UTF-8 rules must not share a key.

    ``read_entries`` decodes with surrogateescape, so ``$\\xa1`` and ``$\\xa9``
    survive as distinct strings. Keying them with ``errors="replace"`` mapped
    both bytes to U+FFFD and collapsed them, so running one rule marked the
    other covered -- 154 rules of Bandrel's Spoonman file, in the wild.
    """
    path = tmp_path / "latin1.rule"
    path.write_bytes(b"$\xc3$\xa1\n$\xc3$\xa9\n$\xc3$\xb3\n")

    entries = ac.read_entries(str(path))
    assert len(entries) == 3

    keys = {ac.entry_key("t", "rule", "wlfp", entry) for entry in entries}
    assert len(keys) == 3


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


def test_covered_falls_back_when_the_json_payload_exceeds_sqlite_bind_limit(
    store, monkeypatch
):
    """A rule file x wordlist-count key set can serialize past 2 GiB.

    CPython's sqlite3 module raises OverflowError -- not sqlite3.Error -- when
    a single bound parameter exceeds INT_MAX bytes, which a huge rule file run
    against many large wordlists can reach (see the real crash this regresses:
    an uncaught OverflowError out of _apply_coverage). The fallback path this
    should take already exists and is already covered above for a missing
    JSON1 extension; it must also fire for this exception type.
    """
    keys = [f"k{i}" for i in range(1200)]
    store.record(keys, target="t")
    real_conn = store._connect()

    class _OverflowingConnection:
        """Proxies to the real connection, except for the covered-lookup query.

        sqlite3.Connection is a C type -- its bound methods are read-only, so
        the only way to make one call raise is to stand in for the connection
        itself.
        """

        def execute(self, sql, *args, **kwargs):
            if sql is ac._COVERED_IN_JSON:
                raise OverflowError("string longer than INT_MAX bytes")
            return real_conn.execute(sql, *args, **kwargs)

        def __getattr__(self, name):
            return getattr(real_conn, name)

    monkeypatch.setattr(store, "_conn", _OverflowingConnection())
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


# --- summary ---------------------------------------------------------------


def test_summary_of_an_unknown_target_is_empty(store):
    summary = store.summary("nope")
    assert summary["entries"] == 0
    assert summary["runs"] == 0
    assert summary["by_attack"] == []
    assert summary["last_run"] is None


def test_summary_counts_entries_and_runs_per_attack(store):
    store.record(["a", "b", "c"], target="T", kind="rule", attack="Dictionary")
    store.record(["d"], target="T", kind="mask", attack="Top Mask")
    store.log_run("T", attack="PRINCE", kind="history")
    store.record(["z"], target="OTHER", kind="rule", attack="Dictionary")

    summary = store.summary("T")
    assert summary["entries"] == 4, "only this target's keys"
    assert summary["runs"] == 3, "including the unfiltered PRINCE run"
    assert dict((a, n) for a, n, _ in summary["by_attack"]) == {
        "Dictionary": 3,
        "Top Mask": 1,
        "PRINCE": 0,
    }
    assert summary["last_run"] is not None


def test_summary_does_not_double_count_a_repeated_run(store):
    store.record(["a", "b"], target="T", kind="rule", attack="Dictionary")
    store.record(["a", "b"], target="T", kind="rule", attack="Dictionary")
    summary = store.summary("T")
    assert summary["entries"] == 2, "the repeat added no keys"
    assert summary["runs"] == 2, "but it is still a run that happened"


def test_summary_survives_a_broken_store(tmp_path, monkeypatch):
    s = ac.CoverageStore(tmp_path / "cov.sqlite3")
    monkeypatch.setattr(s, "_connect", lambda: None)
    assert s.summary("T")["entries"] == 0


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


class TestEntryKeyMaskCanonicalization:
    def test_equivalent_masks_share_a_key(self):
        assert ac.entry_key("t", "mask", "", "?d,?1?1") == ac.entry_key(
            "t", "mask", "", "0123456789,?1?1"
        )

    def test_rule_entries_are_not_canonicalized(self):
        # A rule has no such normalization and its text is significant.
        assert ac.entry_key("t", "rule", "", "?d,?1?1") != ac.entry_key(
            "t", "rule", "", "0123456789,?1?1"
        )

    def test_plain_mask_key_unchanged_by_canonicalization(self):
        # Guards the migration property: charset-less mask keys are exactly
        # what they were before canonical_mask_entry existed.
        import hashlib

        payload = "t\x00mask\x00wl\x00\x00?d?d?d?d"
        expected = hashlib.sha256(
            payload.encode("utf-8", errors="surrogatepass")
        ).hexdigest()
        assert ac.entry_key("t", "mask", "wl", "?d?d?d?d", "") == expected

    def test_equivalent_masks_recorded_once(self, store, tmp_path):
        # End-to-end through the store: the second spelling reads as covered.
        k = ac.entry_key("t", "mask", "", "aa,?1?1")
        store.record([k], target="t", kind="mask", attack="Smart Mask")
        assert store.covered([ac.entry_key("t", "mask", "", "a,?1?1")]) == {k}
