"""Incremental conversion of legacy coverage into the interned schema."""

import sqlite3

import pytest

from hate_crack import attack_coverage as ac
from tests.test_coverage_migration import _old_store


@pytest.fixture
def store(tmp_path):
    s = ac.CoverageStore(tmp_path / "cov.sqlite3")
    yield s
    s.close()


def test_convert_writes_rows_then_marker(store):
    run_id = store.log_run("t" * 64, kind="rule")
    tid = store.intern_target("t" * 64)
    ok = store.convert_scope(
        "t" * 64, "sha-a", "rule", "w", "", [(1, 0, 10)], run_id, tid
    )
    assert ok is True
    assert store.is_converted("t" * 64, "sha-a", "rule", "w", "") is True
    assert store.covered_ids(tid, [(1, 0, 10)]) == {(1, 0, 10)}


class _BoomOnConvertedInsert:
    """Proxy around a real sqlite3.Connection that raises on the marker insert.

    Python 3.13's ``sqlite3.Connection`` no longer allows an instance-level
    ``execute`` override (it is a read-only slot on the C type), so the
    brief's direct ``monkeypatch.setattr(conn, "execute", boom)`` cannot run
    here. This proxy achieves the same fault injection by standing in for
    ``store._conn`` instead: everything delegates to the real connection via
    ``__getattr__`` except ``execute``, which raises exactly for the marker
    insert, and ``__enter__``/``__exit__``, which are forwarded explicitly so
    ``with conn:`` still drives the real connection's transaction (and rolls
    it back when the injected error propagates).
    """

    def __init__(self, real):
        self._real = real

    def __getattr__(self, name):
        return getattr(self._real, name)

    def __enter__(self):
        return self._real.__enter__()

    def __exit__(self, exc_type, exc, tb):
        return self._real.__exit__(exc_type, exc, tb)

    def execute(self, sql, *args):
        if "INTO converted" in sql:
            raise sqlite3.OperationalError("disk I/O error")
        return self._real.execute(sql, *args)


def test_convert_is_atomic_when_the_marker_insert_fails(store, monkeypatch):
    """A crash between the rows and the marker must roll back both.

    The reverse order loses coverage permanently: the combination reads as
    converted while its rows were never carried over, and the old table is
    never consulted for it again.
    """
    run_id = store.log_run("t" * 64, kind="rule")
    tid = store.intern_target("t" * 64)
    real_conn = store._connect()

    monkeypatch.setattr(store, "_conn", _BoomOnConvertedInsert(real_conn))
    ok = store.convert_scope(
        "t" * 64, "sha-a", "rule", "w", "", [(1, 0, 10)], run_id, tid
    )
    monkeypatch.undo()
    assert ok is False
    assert store.is_converted("t" * 64, "sha-a", "rule", "w", "") is False
    assert store.covered_ids(tid, [(1, 0, 10)]) == set()


def test_converted_is_keyed_by_kind(store):
    run_id = store.log_run("t" * 64)
    tid = store.intern_target("t" * 64)
    store.convert_scope("t" * 64, "p", "rule", "w", "", [(1, 0, 10)], run_id, tid)
    # One path can serve as both a rule file and a mask file; a marker for
    # one must not suppress conversion of the other.
    assert store.is_converted("t" * 64, "p", "mask", "w", "") is False


def test_converted_distinguishes_wordlist_and_variant(store):
    run_id = store.log_run("t" * 64)
    tid = store.intern_target("t" * 64)
    store.convert_scope("t" * 64, "p", "rule", "w1", "", [(1, 0, 10)], run_id, tid)
    assert store.is_converted("t" * 64, "p", "rule", "w2", "") is False
    assert store.is_converted("t" * 64, "p", "rule", "w1", "inc:1-8") is False


# --- wiring into plan_run ---------------------------------------------------


def _f(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_plan_run_converts_a_legacy_rule_target(tmp_path, monkeypatch):
    db = tmp_path / "cov.sqlite3"

    hashes = _f(tmp_path, "hashes.txt", "aad3b435b51404ee\n")
    rules_path = _f(tmp_path, "r.rule", "$1\nc\n")
    words_path = _f(tmp_path, "w.txt", "a\n")

    target = ac._sha256_file(hashes)
    _old_store(db, target, ["deadbeef" * 8])  # unrelated old key, just to seed legacy
    s = ac.CoverageStore(db)
    monkeypatch.setattr(ac, "get_store", lambda: s)

    wl_fp = s.wordlist_fingerprint(words_path)
    scope = ac._sha256_file(rules_path)

    plan = ac.plan_run(
        ac.CoverageSpec(
            hash_file=hashes, wordlists=(words_path,), rule_files=(rules_path,)
        ),
        store=s,
    )
    assert plan.kind == "rule"

    assert s.is_converted(target, scope, "rule", wl_fp, "") is True
    s.close()


def test_plan_run_does_not_reconvert_on_a_second_call(tmp_path, monkeypatch):
    db = tmp_path / "cov.sqlite3"

    hashes = _f(tmp_path, "hashes.txt", "aad3b435b51404ee\n")
    rules_path = _f(tmp_path, "r.rule", "$1\nc\n")
    words_path = _f(tmp_path, "w.txt", "a\n")

    target = ac._sha256_file(hashes)
    _old_store(db, target, ["deadbeef" * 8])
    s = ac.CoverageStore(db)
    monkeypatch.setattr(ac, "get_store", lambda: s)

    ac.plan_run(
        ac.CoverageSpec(
            hash_file=hashes, wordlists=(words_path,), rule_files=(rules_path,)
        ),
        store=s,
    )

    def fail_legacy(*_a, **_k):
        pytest.fail("second plan_run must not re-query the legacy table")

    monkeypatch.setattr(s, "_covered_legacy", fail_legacy)

    plan2 = ac.plan_run(
        ac.CoverageSpec(
            hash_file=hashes, wordlists=(words_path,), rule_files=(rules_path,)
        ),
        store=s,
    )
    assert plan2.kind == "rule"
    s.close()


def test_plan_run_never_converts_a_non_legacy_target(tmp_path, monkeypatch):
    s = ac.CoverageStore(tmp_path / "cov.sqlite3")
    monkeypatch.setattr(ac, "get_store", lambda: s)

    def fail_converted(*_a, **_k):
        pytest.fail("a non-legacy target must never reach is_converted")

    monkeypatch.setattr(s, "is_converted", fail_converted)

    hashes = _f(tmp_path, "hashes.txt", "aad3b435b51404ee\n")
    rules_path = _f(tmp_path, "r.rule", "$1\nc\n")
    words_path = _f(tmp_path, "w.txt", "a\n")

    plan = ac.plan_run(
        ac.CoverageSpec(
            hash_file=hashes, wordlists=(words_path,), rule_files=(rules_path,)
        ),
        store=s,
    )
    assert plan.kind == "rule"
    s.close()


def test_wordlist_kind_legacy_key_formula_matches_old_code(tmp_path, monkeypatch):
    db = tmp_path / "cov.sqlite3"

    hashes = _f(tmp_path, "hashes.txt", "aad3b435b51404ee\n")
    words_path = _f(tmp_path, "w.txt", "a\n")

    target = ac._sha256_file(hashes)

    # Compute the wordlist fingerprint the way the store would, before we
    # know the store: use a throwaway store just to fingerprint the file.
    probe = ac.CoverageStore(tmp_path / "probe.sqlite3")
    wl_fp = probe.wordlist_fingerprint(words_path)
    probe.close()

    old_key = ac.entry_key(target, "wordlist", "", wl_fp, "")
    _old_store(db, target, [old_key])

    s = ac.CoverageStore(db)
    monkeypatch.setattr(ac, "get_store", lambda: s)

    plan = ac.plan_run(
        ac.CoverageSpec(hash_file=hashes, wordlists=(words_path,)),
        store=s,
    )
    assert plan.kind == "wordlist"
    assert plan.skip is True
    s.close()


def test_multi_file_mask_plan_skips_conversion_entirely(tmp_path, monkeypatch):
    db = tmp_path / "cov.sqlite3"
    hashes = _f(tmp_path, "hashes.txt", "aad3b435b51404ee\n")
    target = ac._sha256_file(hashes)
    _old_store(db, target, ["deadbeef" * 8])
    s = ac.CoverageStore(db)
    monkeypatch.setattr(ac, "get_store", lambda: s)

    def fail_converted(*_a, **_k):
        pytest.fail("a multi-file mask plan must never attempt conversion")

    monkeypatch.setattr(s, "is_converted", fail_converted)

    mask_a = _f(tmp_path, "a.hcmask", "?d?d?d?d\n")
    mask_b = _f(tmp_path, "b.hcmask", "?l?l?l?l\n")

    plan = ac.plan_run(
        ac.CoverageSpec(hash_file=hashes, mask_files=(mask_a, mask_b)),
        store=s,
    )
    assert plan.kind == "mask"
    s.close()
