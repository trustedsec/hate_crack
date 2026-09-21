"""coverage compact converts legacy targets eagerly and reclaims space."""

import sqlite3

from hate_crack import attack_coverage as ac


def _old_store(path, target, keys, kind="rule", attack="Dictionary"):
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
        (target, kind, attack, "2026-01-01T00:00:00+00:00"),
    )
    conn.executemany(
        "INSERT INTO covered (key, run_id) VALUES (?, 1)", [(k,) for k in keys]
    )
    conn.commit()
    conn.close()


def test_compact_reports_what_it_could_not_convert(tmp_path):
    db = tmp_path / "cov.sqlite3"
    conn = sqlite3.connect(str(db))
    conn.executescript(
        "CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "target TEXT NOT NULL, kind TEXT NOT NULL DEFAULT '', "
        "attack TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '', "
        "ran_at TEXT NOT NULL);"
        "CREATE TABLE covered (key TEXT PRIMARY KEY, run_id INTEGER NOT NULL) "
        "WITHOUT ROWID;"
    )
    conn.execute(
        "INSERT INTO runs (target, kind, ran_at) VALUES (?,?,?)",
        ("t" * 64, "rule", "2026-01-01T00:00:00+00:00"),
    )
    # A key whose source rule file no longer exists cannot be reconstructed.
    conn.execute("INSERT INTO covered VALUES (?, 1)", ("k" * 64,))
    conn.commit()
    conn.close()

    s = ac.CoverageStore(db)
    out = s.compact([])
    assert out["unconvertible"] >= 1
    # Unconvertible coverage must block the drop rather than vanish silently.
    assert out["dropped_old_table"] is False
    s.close()


def test_compact_drops_the_old_table_when_everything_converted(tmp_path):
    s = ac.CoverageStore(tmp_path / "cov.sqlite3")
    out = s.compact([])
    # A fresh store has no legacy targets, so there is nothing blocking.
    assert out["unconvertible"] == 0
    s.close()


def test_compact_round_trip_preserves_coverage_and_drops_old_table(tmp_path):
    """Real rule/mask files, real old-format keys, full round trip.

    Proves the decisive property: after compact drops the old `covered`
    table, `covered_ids` -- using only `covered_v2` -- still reports exactly
    the same coverage a legacy dual-read would have reported before
    compaction.
    """
    target = "a" * 64
    rule_path = tmp_path / "some.rule"
    rule_path.write_text("$1\nc\nsa@\n")
    mask_path = tmp_path / "some.hcmask"
    mask_path.write_text("?d?d?l\nabc,?1?1\n")

    wl_fp = "w" * 64

    # Old keys: one rule covered against one wordlist, one mask covered with
    # no wordlist (masks don't cross wordlists), and a chosen variant.
    covered_rule_key = ac.entry_key(target, "rule", wl_fp, "$1", "")
    uncovered_rule_key = ac.entry_key(target, "rule", wl_fp, "c", "")
    covered_mask_key = ac.entry_key(target, "mask", "", "?d?d?l", "")

    db = tmp_path / "cov.sqlite3"
    _old_store(db, target, [covered_rule_key, covered_mask_key])

    # A real dictionary-plus-rules run also declares which wordlist it used,
    # in run_wordlists -- the file-backed sweep only tries wordlists it can
    # see there.
    conn = sqlite3.connect(str(db))
    run_id = conn.execute("SELECT id FROM runs LIMIT 1").fetchone()[0]
    conn.execute(
        "CREATE TABLE IF NOT EXISTS run_wordlists (run_id INTEGER NOT NULL, "
        "wordlist TEXT NOT NULL, PRIMARY KEY (run_id, wordlist)) WITHOUT ROWID"
    )
    conn.execute(
        "INSERT INTO run_wordlists (run_id, wordlist) VALUES (?, ?)",
        (run_id, wl_fp),
    )
    conn.commit()
    conn.close()

    s = ac.CoverageStore(db)
    tid = s.intern_target(target)
    wl_id = s.intern_wordlist(wl_fp)
    var_id = s.intern_variant("")
    rule_ids = s.intern_entries("rule", ["$1", "c", "sa@"])
    mask_ids = s.intern_entries("mask", ["?d?d?l", "abc,?1?1"])
    assert rule_ids is not None and mask_ids is not None

    # Pre-compaction: dual-read reports covered_rule and covered_mask, and
    # not the uncovered one.
    rule_legacy = ac.LegacyProbe(
        target=target,
        keys={
            (wl_id, var_id, rule_ids[0]): covered_rule_key,
            (wl_id, var_id, rule_ids[1]): uncovered_rule_key,
        },
    )
    before = s.covered_ids(
        tid,
        [(wl_id, var_id, rule_ids[0]), (wl_id, var_id, rule_ids[1])],
        legacy=rule_legacy,
    )
    assert before == {(wl_id, var_id, rule_ids[0])}

    empty_wl = s.intern_wordlist("")
    mask_legacy = ac.LegacyProbe(
        target=target,
        keys={(empty_wl, var_id, mask_ids[0]): covered_mask_key},
    )
    before_mask = s.covered_ids(
        tid, [(empty_wl, var_id, mask_ids[0])], legacy=mask_legacy
    )
    assert before_mask == {(empty_wl, var_id, mask_ids[0])}

    out = s.compact([(str(rule_path), "rule"), (str(mask_path), "mask")])

    assert out["unconvertible"] == 0
    assert out["dropped_old_table"] is True

    conn = s._connect()
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='covered'"
    ).fetchone()
    assert row is None

    # Decisive check: covered_ids (no legacy kwarg needed -- old table is
    # gone) still reports exactly the same coverage using only covered_v2.
    after = s.covered_ids(
        tid, [(wl_id, var_id, rule_ids[0]), (wl_id, var_id, rule_ids[1])]
    )
    assert after == {(wl_id, var_id, rule_ids[0])}
    after_mask = s.covered_ids(tid, [(empty_wl, var_id, mask_ids[0])])
    assert after_mask == {(empty_wl, var_id, mask_ids[0])}

    s.close()


def test_compact_leaves_unconvertible_target_in_legacy_targets(tmp_path):
    """An incomplete target's row must survive in legacy_targets.

    This is the decisive check for the per-target removal logic: without it,
    a target with unconvertible coverage would (wrongly) still get dropped
    from legacy_targets, and the drop condition (`legacy_targets` empty)
    would then fire the next time compact runs even though data was lost.
    """
    db = tmp_path / "cov.sqlite3"
    target = "b" * 64
    _old_store(db, target, ["k" * 64])  # no source file backs this key

    s = ac.CoverageStore(db)
    out = s.compact([])
    assert out["unconvertible"] >= 1
    assert out["dropped_old_table"] is False

    conn = s._connect()
    row = conn.execute(
        "SELECT 1 FROM legacy_targets WHERE target = ?", (target,)
    ).fetchone()
    assert row is not None
    s.close()


def test_compact_converts_wordlist_kind_legacy_coverage(tmp_path):
    """Wordlist-kind coverage (no source file) is swept independently."""
    db = tmp_path / "cov.sqlite3"
    target = "c" * 64
    wl_fp = "d" * 64
    old_key = ac.entry_key(target, "wordlist", "", wl_fp, "")
    _old_store(db, target, [old_key], kind="wordlist")

    conn = sqlite3.connect(str(db))
    run_id = conn.execute("SELECT id FROM runs LIMIT 1").fetchone()[0]
    conn.execute(
        "CREATE TABLE IF NOT EXISTS run_wordlists (run_id INTEGER NOT NULL, "
        "wordlist TEXT NOT NULL, PRIMARY KEY (run_id, wordlist)) WITHOUT ROWID"
    )
    conn.execute(
        "INSERT INTO run_wordlists (run_id, wordlist) VALUES (?, ?)",
        (run_id, wl_fp),
    )
    conn.commit()
    conn.close()

    s = ac.CoverageStore(db)
    out = s.compact([])
    assert out["converted"] >= 1
    assert out["unconvertible"] == 0
    assert out["dropped_old_table"] is True

    tid = s.intern_target(target)
    empty_wl = s.intern_wordlist("")
    var_id = s.intern_variant("")
    (wl_entry_id,) = s.intern_entries("wordlist", [wl_fp])
    after = s.covered_ids(tid, [(empty_wl, var_id, wl_entry_id)])
    assert after == {(empty_wl, var_id, wl_entry_id)}
    s.close()


def test_compact_refuses_to_drop_with_mixed_unconvertible_remnants(tmp_path):
    """Both file-backed and wordlist-kind unconvertible coverage count."""
    db = tmp_path / "cov.sqlite3"
    target = "e" * 64
    stray_rule_key = ac.entry_key(target, "rule", "z" * 64, "unbacked-rule", "")
    stray_wl_key = ac.entry_key(target, "wordlist", "", "z" * 64, "")
    _old_store(db, target, [stray_rule_key, stray_wl_key])

    s = ac.CoverageStore(db)
    out = s.compact([])
    assert out["unconvertible"] >= 2
    assert out["dropped_old_table"] is False
    s.close()


def test_compact_is_idempotent_after_drop(tmp_path):
    """A truly fresh store has no legacy targets, so the first call already
    finds nothing unconvertible and the (empty) old table still exists --
    it gets dropped immediately. The decisive idempotency check is the
    *second* call: the table is already gone, so there is nothing left to
    drop, and that must be reported honestly rather than as another drop.
    """
    db = tmp_path / "cov.sqlite3"
    s = ac.CoverageStore(db)
    first = s.compact([])
    assert first["converted"] == 0
    assert first["unconvertible"] == 0
    assert first["dropped_old_table"] is True
    second = s.compact([])
    assert second == {"converted": 0, "unconvertible": 0, "dropped_old_table": False}
    s.close()
