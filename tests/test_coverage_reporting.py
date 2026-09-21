"""Reporting and forget across the old and new coverage schemas."""

import pytest

from hate_crack import attack_coverage as ac


@pytest.fixture
def store(tmp_path):
    s = ac.CoverageStore(tmp_path / "cov.sqlite3")
    yield s
    s.close()


def test_forget_clears_new_schema_rows_and_markers(store):
    target = "t" * 64
    run_id = store.log_run(target, kind="rule", attack="Dictionary")
    tid = store.intern_target(target)
    store.record_ids(tid, [(1, 0, 10)], run_id)
    store.convert_scope(target, "s", "rule", "w", "", [], run_id, tid)
    conn = store._connect()
    conn.execute("INSERT OR IGNORE INTO legacy_targets VALUES (?)", (target,))
    conn.commit()

    store.forget_target(target)

    assert store.covered_ids(tid, [(1, 0, 10)]) == set()
    assert store.is_converted(target, "s", "rule", "w", "") is False
    assert store.is_legacy_target(target) is False
    assert store.history(target) == []


def test_forget_leaves_another_target_alone(store):
    a, b = "a" * 64, "b" * 64
    ra = store.log_run(a, kind="rule")
    rb = store.log_run(b, kind="rule")
    ta, tb = store.intern_target(a), store.intern_target(b)
    store.record_ids(ta, [(1, 0, 10)], ra)
    store.record_ids(tb, [(1, 0, 10)], rb)
    store.forget_target(a)
    assert store.covered_ids(tb, [(1, 0, 10)]) == {(1, 0, 10)}


def test_summary_counts_interned_entries_per_attack(store):
    target = "t" * 64
    run_id = store.log_run(target, kind="rule", attack="Dictionary")
    tid = store.intern_target(target)
    store.record_ids(tid, [(1, 0, 10), (1, 0, 11)], run_id)
    out = store.summary(target)
    assert out["entries"] == 2
    assert out["runs"] == 1
    assert ("Dictionary", 2, 1) in out["by_attack"]


def test_summary_of_an_unknown_target_is_empty(store):
    out = store.summary("z" * 64)
    assert out["entries"] == 0
    assert out["runs"] == 0


def test_summary_by_attack_sums_across_multiple_runs_of_same_attack(store):
    """Two runs of the same attack, with 2 and 3 covered_v2 entries.

    A correct SUM(...) over the correlated subquery totals 2 + 3 = 5. The
    bare unwrapped correlated-subquery form (no SUM) is not aggregated by
    SQLite's GROUP BY -- it silently samples one row's value instead of
    summing across the group, so it would report a smaller, wrong count
    (implementation-defined which row, but never the true total of 5 with
    both runs contributing more than one row each).
    """
    target = "t" * 64
    tid = store.intern_target(target)
    run1 = store.log_run(target, kind="rule", attack="Dictionary")
    store.record_ids(tid, [(1, 0, 1), (1, 0, 2)], run1)
    run2 = store.log_run(target, kind="rule", attack="Dictionary")
    store.record_ids(tid, [(1, 0, 3), (1, 0, 4), (1, 0, 5)], run2)

    out = store.summary(target)
    assert out["entries"] == 5
    assert out["runs"] == 2
    matches = [row for row in out["by_attack"] if row[0] == "Dictionary"]
    assert len(matches) == 1
    assert matches[0] == ("Dictionary", 5, 2)
