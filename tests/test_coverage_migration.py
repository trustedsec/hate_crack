"""Migration sweep and dual-read for pre-interning targets."""

import sqlite3

import pytest

from hate_crack import attack_coverage as ac


def _old_store(path, target, keys):
    """Build a store in the pre-interning shape, as an upgrade would find."""
    conn = sqlite3.connect(str(path))
    conn.executescript(
        "CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "target TEXT NOT NULL, kind TEXT NOT NULL DEFAULT '', "
        "attack TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '', "
        "ran_at TEXT NOT NULL);"
        "CREATE TABLE covered (key TEXT PRIMARY KEY, run_id INTEGER NOT NULL) "
        "WITHOUT ROWID;"
    )
    conn.execute(
        "INSERT INTO runs (target, kind, attack, ran_at) VALUES (?,?,?,?)",
        (target, "rule", "Dictionary", "2026-01-01T00:00:00+00:00"),
    )
    conn.executemany(
        "INSERT INTO covered (key, run_id) VALUES (?, 1)", [(k,) for k in keys]
    )
    conn.commit()
    conn.close()


def test_sweep_marks_existing_targets_as_legacy(tmp_path):
    db = tmp_path / "cov.sqlite3"
    _old_store(db, "t" * 64, ["k" * 64])
    s = ac.CoverageStore(db)
    assert s.is_legacy_target("t" * 64) is True
    assert s.is_legacy_target("u" * 64) is False
    s.close()


def test_sweep_runs_once_and_not_again_after_compaction(tmp_path):
    db = tmp_path / "cov.sqlite3"
    _old_store(db, "t" * 64, ["k" * 64])
    s = ac.CoverageStore(db)
    conn = s._connect()
    # Simulate compaction emptying the table.
    conn.execute("DELETE FROM legacy_targets")
    conn.commit()
    s.close()
    s2 = ac.CoverageStore(db)
    # An empty legacy_targets is the steady state after compaction and must
    # not re-trigger the sweep.
    assert s2.is_legacy_target("t" * 64) is False
    s2.close()


def test_a_fresh_store_marks_nothing_legacy(tmp_path):
    s = ac.CoverageStore(tmp_path / "cov.sqlite3")
    assert s.is_legacy_target("t" * 64) is False
    s.close()


def test_dual_read_unions_old_and_new(tmp_path):
    db = tmp_path / "cov.sqlite3"
    target = "t" * 64
    old_key = ac.entry_key(target, "rule", "w" * 64, "$1", "")
    _old_store(db, target, [old_key])
    s = ac.CoverageStore(db)
    tid = s.intern_target(target)
    wl = s.intern_wordlist("w" * 64)
    var = s.intern_variant("")
    (eid,) = s.intern_entries("rule", ["$1"])
    (eid2,) = s.intern_entries("rule", ["c"])
    (eid3,) = s.intern_entries("rule", ["u"])
    run_id = s.log_run(target, kind="rule")
    s.record_ids(tid, [(wl, var, eid2)], run_id)
    probes = [(wl, var, eid), (wl, var, eid2), (wl, var, eid3)]
    legacy = ac.LegacyProbe(
        target=target,
        keys={
            (wl, var, eid): old_key,
            (wl, var, eid2): "z" * 64,
            (wl, var, eid3): "y" * 64,  # absent from the old covered table too
        },
    )
    assert s.covered_ids(tid, probes, legacy=legacy) == {
        (wl, var, eid),
        (wl, var, eid2),
    }
    s.close()


def test_a_non_legacy_target_never_queries_the_old_table(tmp_path, monkeypatch):
    s = ac.CoverageStore(tmp_path / "cov.sqlite3")
    tid = s.intern_target("t" * 64)
    monkeypatch.setattr(
        s, "_covered_legacy", lambda *a, **k: pytest.fail("old table queried")
    )
    assert s.covered_ids(tid, [(1, 0, 1)]) == set()
    s.close()


def test_corrupted_version_degrades_to_needing_a_sweep(tmp_path):
    db = tmp_path / "cov.sqlite3"
    target = "t" * 64
    _old_store(db, target, ["k" * 64])
    # Pre-create the migration tables directly (as _SCHEMA would) and plant a
    # non-numeric version value, simulating a corrupted schema_meta row from
    # before this store was ever opened by the new code.
    conn = sqlite3.connect(str(db))
    conn.executescript(ac._SCHEMA)
    conn.execute("DELETE FROM legacy_targets")
    conn.execute(
        "INSERT OR REPLACE INTO schema_meta (k, v) VALUES ('version', 'garbage')"
    )
    conn.commit()
    conn.close()

    s = ac.CoverageStore(db)
    # A non-numeric version must be treated as "needs a sweep", not as
    # "already swept" (which would silently strand the target on the old
    # table forever) and must not raise (which would take down the store).
    assert s.is_legacy_target(target) is True
    s.close()
