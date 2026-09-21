"""Tests for integer-keyed coverage membership and recording."""

import pytest

from hate_crack import attack_coverage as ac


@pytest.fixture
def store(tmp_path):
    s = ac.CoverageStore(tmp_path / "cov.sqlite3")
    yield s
    s.close()


def test_record_then_covered_round_trip(store):
    run_id = store.log_run("t" * 64, attack="Dictionary", kind="rule")
    tid = store.intern_target("t" * 64)
    rows = [(1, 0, 10), (1, 0, 11)]
    assert store.record_ids(tid, rows, run_id) == 2
    assert store.covered_ids(tid, rows) == set(rows)


def test_covered_is_scoped_to_target(store):
    run_id = store.log_run("a" * 64)
    a = store.intern_target("a" * 64)
    b = store.intern_target("b" * 64)
    store.record_ids(a, [(1, 0, 10)], run_id)
    assert store.covered_ids(b, [(1, 0, 10)]) == set()


def test_covered_is_scoped_to_wordlist_and_variant(store):
    run_id = store.log_run("a" * 64)
    tid = store.intern_target("a" * 64)
    store.record_ids(tid, [(1, 0, 10)], run_id)
    assert store.covered_ids(tid, [(2, 0, 10)]) == set()
    assert store.covered_ids(tid, [(1, 5, 10)]) == set()


def test_record_is_idempotent(store):
    run_id = store.log_run("a" * 64)
    tid = store.intern_target("a" * 64)
    rows = [(1, 0, 10)]
    assert store.record_ids(tid, rows, run_id) == 1
    assert store.record_ids(tid, rows, run_id) == 0


def test_covered_handles_a_probe_larger_than_the_parameter_limit(store):
    run_id = store.log_run("a" * 64)
    tid = store.intern_target("a" * 64)
    rows = [(1, 0, n) for n in range(5000)]
    store.record_ids(tid, rows, run_id)
    assert len(store.covered_ids(tid, rows)) == 5000


def test_covered_empty_probe_returns_empty(store):
    assert store.covered_ids(1, []) == set()


def test_record_returns_zero_when_store_unusable(tmp_path, monkeypatch):
    s = ac.CoverageStore(tmp_path / "cov.sqlite3")
    monkeypatch.setattr(s, "_connect", lambda: None)
    assert s.record_ids(1, [(1, 0, 10)], 1) == 0
    assert s.covered_ids(1, [(1, 0, 10)]) == set()


def test_covered_ids_handles_out_of_range_entry_id(store):
    """Out-of-range entry_id in probe doesn't raise, returns empty."""
    run_id = store.log_run("a" * 64)
    tid = store.intern_target("a" * 64)
    store.record_ids(tid, [(1, 0, 10)], run_id)
    # 2**63 overflows the integer bind; covered_ids must handle it gracefully
    assert store.covered_ids(tid, [(1, 0, 2**63)]) == set()


def test_covered_ids_handles_out_of_range_target_id(store):
    """Out-of-range target_id doesn't raise, returns empty."""
    run_id = store.log_run("a" * 64)
    tid = store.intern_target("a" * 64)
    store.record_ids(tid, [(1, 0, 10)], run_id)
    # 2**63 overflows the integer bind; covered_ids must handle it gracefully
    assert store.covered_ids(2**63, [(1, 0, 10)]) == set()


def test_record_ids_handles_out_of_range_entry_id(store):
    """Out-of-range entry_id in rows doesn't raise, returns 0."""
    run_id = store.log_run("a" * 64)
    tid = store.intern_target("a" * 64)
    # 2**63 overflows the integer bind; record_ids must handle it gracefully
    assert store.record_ids(tid, [(1, 0, 2**63)], run_id) == 0


def test_record_ids_rollback_on_mixed_batch(store):
    """Mixed batch with one overflow doesn't insert any rows and doesn't raise."""
    run_id = store.log_run("a" * 64)
    tid = store.intern_target("a" * 64)
    # Mixed batch: two valid rows, one that will overflow
    rows = [(1, 0, 10), (1, 0, 11), (1, 0, 2**63)]
    assert store.record_ids(tid, rows, run_id) == 0
    # Verify that neither valid row was inserted despite transaction failure
    assert store.covered_ids(tid, [(1, 0, 10), (1, 0, 11)]) == set()
