"""The per-hash-file coverage store (hate_crack.coverage_store)."""

import os
import sqlite3

import pytest

from hate_crack import coverage_store as cs


@pytest.fixture
def hash_file(tmp_path):
    path = tmp_path / "engagement" / "left.txt"
    path.parent.mkdir()
    path.write_text("aad3b435b51404eeaad3b435b51404ee\n")
    return path


@pytest.fixture
def store(hash_file):
    s = cs.CoverageStore(cs.store_path_for(str(hash_file)))
    yield s
    s.close()


def _wordlist(tmp_path, name="words.txt", text="alpha\nbeta\n"):
    path = tmp_path / name
    path.write_text(text)
    return path


# -- location ----------------------------------------------------------------


def test_store_lives_beside_the_hash_file(hash_file):
    assert cs.store_path_for(str(hash_file)) == hash_file.parent / (
        "left.txt" + cs.STORE_SUFFIX
    )


def test_a_symlinked_hash_file_resolves_to_the_same_store(tmp_path, hash_file):
    link = tmp_path / "link.txt"
    link.symlink_to(hash_file)
    assert cs.store_path_for(str(link)) == cs.store_path_for(str(hash_file))


def test_connecting_creates_the_file_and_stamps_the_version(store, hash_file):
    assert store.available()
    conn = sqlite3.connect(cs.store_path_for(str(hash_file)))
    assert conn.execute("PRAGMA user_version").fetchone()[0] == cs.SCHEMA_VERSION
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    assert {
        "targets",
        "wordlists",
        "variants",
        "runs",
        "run_wordlists",
        "covered",
    } <= tables
    conn.close()


def test_covered_is_without_rowid_and_has_no_run_id(store, hash_file):
    store.available()
    conn = sqlite3.connect(cs.store_path_for(str(hash_file)))
    sql = conn.execute(
        "SELECT sql FROM sqlite_master WHERE name = 'covered'"
    ).fetchone()[0]
    conn.close()
    assert "WITHOUT ROWID" in sql
    assert "run_id" not in sql


# -- journal mode ------------------------------------------------------------


def test_local_store_uses_wal(store, monkeypatch):
    monkeypatch.setattr(cs, "is_network_fs", lambda directory: False)
    conn = store._connect()
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_network_store_uses_a_rollback_journal(hash_file, monkeypatch):
    monkeypatch.setattr(cs, "is_network_fs", lambda directory: True)
    s = cs.CoverageStore(cs.store_path_for(str(hash_file)))
    conn = s._connect()
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
    s.close()


def test_network_detection_never_raises(monkeypatch):
    def boom(directory):
        raise OSError("statfs failed")

    monkeypatch.setattr(cs, "_platform_is_network_fs", boom)
    assert cs.is_network_fs("/") is False


# -- disable and warn --------------------------------------------------------


def test_unwritable_directory_disables_with_one_warning(tmp_path, capsys):
    locked = tmp_path / "locked"
    locked.mkdir()
    hashes = locked / "h.txt"
    hashes.write_text("x\n")
    locked.chmod(0o500)
    try:
        s = cs.CoverageStore(cs.store_path_for(str(hashes)))
        assert not s.available()
        assert not s.available()
        assert s.wordlist_id(str(hashes)) is None
    finally:
        locked.chmod(0o700)
    out = capsys.readouterr().out
    assert out.count("[!] Coverage disabled for h.txt:") == 1


def test_read_only_store_file_disables(hash_file, capsys):
    path = cs.store_path_for(str(hash_file))
    first = cs.CoverageStore(path)
    assert first.available()
    first.close()
    path.chmod(0o444)
    s = cs.CoverageStore(path)
    assert not s.available()
    assert "[!] Coverage disabled for left.txt:" in capsys.readouterr().out
    assert s.disabled_reason


def test_unknown_schema_version_disables(hash_file, capsys):
    path = cs.store_path_for(str(hash_file))
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA user_version = 99")
    conn.commit()
    conn.close()
    s = cs.CoverageStore(path)
    assert not s.available()
    assert "99" in capsys.readouterr().out


# -- wordlist identity -------------------------------------------------------


def test_same_path_and_stamp_gets_the_same_id_across_instances(tmp_path, hash_file):
    words = _wordlist(tmp_path)
    path = cs.store_path_for(str(hash_file))
    first = cs.CoverageStore(path).wordlist_id(str(words))
    second = cs.CoverageStore(path).wordlist_id(str(words))
    assert first is not None and first == second
    assert first != cs.NO_WORDLIST


def test_a_new_mtime_is_a_new_identity(tmp_path, store):
    words = _wordlist(tmp_path)
    before = store.wordlist_id(str(words))
    stat = words.stat()
    os.utime(words, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
    assert store.wordlist_id(str(words)) != before


def test_a_new_size_with_the_same_mtime_is_a_new_identity(tmp_path, store):
    words = _wordlist(tmp_path)
    before = store.wordlist_id(str(words))
    stat = words.stat()
    words.write_text("alpha\nbeta\ngamma\n")
    os.utime(words, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    assert store.wordlist_id(str(words)) != before


def test_wordlist_is_identified_without_being_read(tmp_path, store):
    huge = tmp_path / "huge.txt"
    with open(huge, "wb") as handle:
        handle.truncate(5 * 1024**3)  # sparse: no blocks written
    huge.chmod(0o000)
    try:
        assert store.wordlist_id(str(huge)) is not None
    finally:
        huge.chmod(0o600)


def test_a_symlinked_wordlist_shares_the_target_identity(tmp_path, store):
    words = _wordlist(tmp_path)
    link = tmp_path / "link.txt"
    link.symlink_to(words)
    assert store.wordlist_id(str(link)) == store.wordlist_id(str(words))


def test_missing_wordlist_has_no_identity(tmp_path, store):
    assert store.wordlist_id(str(tmp_path / "absent.txt")) is None


def test_a_directory_has_no_wordlist_identity(tmp_path, store):
    assert store.wordlist_id(str(tmp_path)) is None


# -- membership and record ---------------------------------------------------

T1 = "a" * 64
T2 = "b" * 64


def _record(
    store,
    rows,
    *,
    target=T1,
    kind="rule",
    variant="",
    attack="Quick Crack",
    wordlist_ids=(),
):
    return store.record(
        target=target,
        kind=kind,
        variant=variant,
        attack=attack,
        wordlist_ids=wordlist_ids,
        rows=rows,
    )


def test_recorded_rows_are_covered(store, tmp_path):
    wl = store.wordlist_id(str(_wordlist(tmp_path)))
    assert _record(store, [(wl, 11), (wl, -22)], wordlist_ids=[wl]) == 2
    assert store.covered(T1, wl, "", "rule", [11, -22, 33]) == {11, -22}


def test_record_is_idempotent(store, tmp_path):
    wl = store.wordlist_id(str(_wordlist(tmp_path)))
    _record(store, [(wl, 1)])
    assert _record(store, [(wl, 1)]) == 0


def test_extreme_hash_values_round_trip(store):
    extremes = [-(2**63), 2**63 - 1, 0, -1]
    _record(store, [(cs.NO_WORDLIST, h) for h in extremes], kind="mask")
    assert store.covered(T1, cs.NO_WORDLIST, "", "mask", extremes) == set(extremes)


def test_membership_handles_more_than_the_parameter_limit(store):
    hashes = list(range(5000))
    _record(store, [(cs.NO_WORDLIST, h) for h in hashes], kind="mask")
    assert store.covered(T1, cs.NO_WORDLIST, "", "mask", hashes) == set(hashes)


def test_membership_falls_back_without_json1(store, monkeypatch):
    _record(store, [(cs.NO_WORDLIST, 5)], kind="mask")
    monkeypatch.setattr(cs, "_COVERED_IN_JSON", "SELECT no_such_function(?)")
    assert store.covered(T1, cs.NO_WORDLIST, "", "mask", [5, 6]) == {5}


def test_unknown_target_or_variant_covers_nothing_and_writes_nothing(store, hash_file):
    assert store.covered(T2, 1, "never-seen", "rule", [1]) == set()
    conn = sqlite3.connect(cs.store_path_for(str(hash_file)))
    assert conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0] == 0
    conn.close()


# Each scope column must be part of the probe. Removing any one of them from
# _COVERED_IN_JSON has to turn one of these red: they are the guards against
# false-covered, which drops untried candidates silently.


def test_scope_target(store):
    _record(store, [(cs.NO_WORDLIST, 7)], target=T1, kind="mask")
    _record(store, [(cs.NO_WORDLIST, 8)], target=T2, kind="mask")
    assert store.covered(T2, cs.NO_WORDLIST, "", "mask", [7]) == set()


def test_scope_wordlist(store, tmp_path):
    a = store.wordlist_id(str(_wordlist(tmp_path, "a.txt")))
    b = store.wordlist_id(str(_wordlist(tmp_path, "b.txt")))
    _record(store, [(a, 7)])
    assert store.covered(T1, b, "", "rule", [7]) == set()


def test_scope_variant(store):
    _record(store, [(cs.NO_WORDLIST, 7)], kind="mask", variant="hybrid:a6")
    _record(store, [(cs.NO_WORDLIST, 8)], kind="mask", variant="hybrid:a7")
    assert store.covered(T1, cs.NO_WORDLIST, "hybrid:a7", "mask", [7]) == set()


def test_scope_kind(store):
    _record(store, [(cs.NO_WORDLIST, 7)], kind="mask")
    _record(store, [(cs.NO_WORDLIST, 8)], kind="rule")
    assert store.covered(T1, cs.NO_WORDLIST, "", "rule", [7]) == set()


def _hold_write_lock(path, mode="IMMEDIATE"):
    holder = sqlite3.connect(str(path), isolation_level=None)
    holder.execute(f"BEGIN {mode}")
    return holder


def test_locked_store_skips_the_record_without_disabling(
    store, tmp_path, capsys, monkeypatch
):
    monkeypatch.setattr(cs, "_BUSY_TIMEOUT_S", 0.1)
    wl = store.wordlist_id(str(_wordlist(tmp_path)))
    holder = _hold_write_lock(store._path)
    try:
        assert _record(store, [(wl, 1)], wordlist_ids=[wl]) == 0
        assert store.disabled_reason is None
        assert "[!] Coverage store for left.txt is locked" in capsys.readouterr().out
    finally:
        holder.rollback()
        holder.close()
    assert _record(store, [(wl, 1)], wordlist_ids=[wl]) == 1
    assert store.covered(T1, wl, "", "rule", [1]) == {1}


def test_locked_warning_prints_once_per_store(store, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(cs, "_BUSY_TIMEOUT_S", 0.1)
    wl = store.wordlist_id(str(_wordlist(tmp_path)))
    holder = _hold_write_lock(store._path)
    try:
        _record(store, [(wl, 1)], wordlist_ids=[wl])
        _record(store, [(wl, 2)], wordlist_ids=[wl])
    finally:
        holder.rollback()
        holder.close()
    assert capsys.readouterr().out.count("[!] Coverage store for") == 1


def test_locked_wordlist_id_and_forget_do_not_disable(
    store, tmp_path, capsys, monkeypatch
):
    monkeypatch.setattr(cs, "_BUSY_TIMEOUT_S", 0.1)
    assert store.available()
    _record(store, [(cs.NO_WORDLIST, 1)], kind="mask")
    wl_path = str(_wordlist(tmp_path))
    holder = _hold_write_lock(store._path)
    try:
        assert store.wordlist_id(wl_path) is None
        assert store.forget_target(T1) == 0
        assert store.disabled_reason is None
    finally:
        holder.rollback()
        holder.close()
    assert store.wordlist_id(wl_path) is not None
    assert store.forget_target(T1) == 1


def test_locked_covered_on_a_rollback_journal_answers_nothing_covered(
    store, capsys, monkeypatch
):
    monkeypatch.setattr(cs, "_BUSY_TIMEOUT_S", 0.1)
    monkeypatch.setattr(cs, "is_network_fs", lambda _d: True)
    _record(store, [(cs.NO_WORDLIST, 5)], kind="mask")
    holder = _hold_write_lock(store._path, "EXCLUSIVE")
    try:
        assert store.covered(T1, cs.NO_WORDLIST, "", "mask", [5]) == set()
        assert store.disabled_reason is None
        assert "[!] Coverage store for left.txt is locked" in capsys.readouterr().out
        assert store._conn is not None and store._conn.in_transaction is False
    finally:
        holder.rollback()
        holder.close()
    assert store.covered(T1, cs.NO_WORDLIST, "", "mask", [5]) == {5}


def test_a_lock_error_does_not_take_the_probe_table_fallback(store, monkeypatch):
    monkeypatch.setattr(cs, "_BUSY_TIMEOUT_S", 0.1)
    monkeypatch.setattr(cs, "is_network_fs", lambda _d: True)
    _record(store, [(cs.NO_WORDLIST, 5)], kind="mask")
    # Let the id lookups pass so the lock is first hit by the membership query.
    monkeypatch.setattr(cs.CoverageStore, "_existing_target_id", lambda *a: 1)
    monkeypatch.setattr(cs.CoverageStore, "_existing_variant_id", lambda *a: 1)
    called = []
    monkeypatch.setattr(
        cs.CoverageStore,
        "_covered_via_probe_table",
        lambda *a, **k: called.append(1) or [],
    )
    holder = _hold_write_lock(store._path, "EXCLUSIVE")
    try:
        assert store.covered(T1, cs.NO_WORDLIST, "", "mask", [5]) == set()
    finally:
        holder.rollback()
        holder.close()
    assert called == []
    assert store.disabled_reason is None


def test_probe_table_fallback_leaves_no_transaction_open(store, monkeypatch):
    _record(store, [(cs.NO_WORDLIST, 5)], kind="mask")
    monkeypatch.setattr(
        cs, "_COVERED_IN_JSON", "SELECT value FROM no_such_table_json_each(?)"
    )
    assert store.covered(T1, cs.NO_WORDLIST, "", "mask", [5, 6]) == {5}
    assert store._conn is not None
    assert store._conn.in_transaction is False


def test_failed_record_rolls_back_the_whole_run(store, tmp_path, capsys, monkeypatch):
    wl = store.wordlist_id(str(_wordlist(tmp_path)))
    monkeypatch.setattr(
        cs, "_INSERT_COVERED", "INSERT INTO no_such_table VALUES (?, ?, ?, ?, ?)"
    )
    assert _record(store, [(wl, 1)], wordlist_ids=[wl]) == 0
    assert "[!] Coverage disabled for left.txt:" in capsys.readouterr().out
    reopened = cs.CoverageStore(store._path)
    assert reopened.history(T1) == []


# -- history / summary / prior runs / forget ---------------------------------


def test_log_run_appears_in_history(store):
    store.log_run(T1, attack="PRINCE")
    store.log_run(T1, attack="OMEN")
    assert [row[0] for row in store.history(T1)] == ["PRINCE", "OMEN"]


def test_summary_counts_entries_and_runs_per_attack(store, tmp_path):
    wl = store.wordlist_id(str(_wordlist(tmp_path)))
    _record(store, [(wl, 1), (wl, 2)], attack="Quick Crack")
    _record(store, [(wl, 2), (wl, 3)], attack="Dictionary")
    store.log_run(T1, attack="PRINCE")
    summary = store.summary(T1)
    assert summary["entries"] == 3
    assert summary["runs"] == 3
    assert summary["by_attack"] == [
        ("Dictionary", 1, 1),
        ("PRINCE", 0, 1),
        ("Quick Crack", 2, 1),
    ]
    assert summary["last_run"]


def test_summary_of_unknown_target_is_empty(store):
    assert store.summary(T2) == {
        "entries": 0,
        "runs": 0,
        "by_attack": [],
        "last_run": None,
    }


def test_has_prior_run_scopes(store, tmp_path):
    a = store.wordlist_id(str(_wordlist(tmp_path, "a.txt")))
    b = store.wordlist_id(str(_wordlist(tmp_path, "b.txt")))
    _record(store, [(a, 1)], attack="Quick Crack", kind="rule", wordlist_ids=[a])
    assert store.has_prior_run(T1, "Quick Crack", [a], kind="rule")
    assert store.has_prior_run(T1, "Quick Crack", [b, a])
    assert not store.has_prior_run(T1, "Quick Crack", [b], kind="rule")
    assert not store.has_prior_run(T1, "Quick Crack", [a], kind="wordlist")
    assert not store.has_prior_run(T1, "Dictionary", [a])
    assert store.has_prior_run(T1, "Quick Crack", [])
    assert store.has_prior_run(T1, "Quick Crack", [], kind="rule")
    assert not store.has_prior_run(T1, "Quick Crack", [], kind="mask")
    assert not store.has_prior_run(T2, "Quick Crack", [a])


def test_forget_target_clears_only_that_target(store):
    _record(store, [(cs.NO_WORDLIST, 1), (cs.NO_WORDLIST, 2)], target=T1, kind="mask")
    _record(store, [(cs.NO_WORDLIST, 1)], target=T2, kind="mask")
    assert store.forget_target(T1) == 2
    assert store.history(T1) == []
    assert store.covered(T2, cs.NO_WORDLIST, "", "mask", [1]) == {1}


def test_reads_on_a_disabled_store_answer_unknown(tmp_path):
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "h.txt").write_text("x\n")
    locked.chmod(0o500)
    try:
        s = cs.CoverageStore(cs.store_path_for(str(locked / "h.txt")))
        assert s.covered(T1, 0, "", "mask", [1]) == set()
        assert (
            s.record(
                target=T1,
                kind="mask",
                variant="",
                attack="x",
                wordlist_ids=(),
                rows=[(0, 1)],
            )
            == 0
        )
        assert s.history(T1) == []
        assert not s.has_prior_run(T1, "x", [])
        assert s.forget_target(T1) == 0
    finally:
        locked.chmod(0o700)


# -- legacy store removal ----------------------------------------------------


def _legacy(home, size=2048):
    base = home / ".hate_crack" / "coverage"
    base.mkdir(parents=True)
    db = base / cs.LEGACY_STORE_NAME
    db.write_bytes(b"\0" * size)
    (base / (cs.LEGACY_STORE_NAME + "-wal")).write_bytes(b"")
    (base / (cs.LEGACY_STORE_NAME + "-shm")).write_bytes(b"\0" * 1024)
    db.chmod(0o444)
    return base


def test_legacy_store_is_removed_with_a_notice(tmp_path, capsys):
    base = _legacy(tmp_path)
    cs.remove_legacy_store(home=str(tmp_path))
    assert not base.exists()
    out = capsys.readouterr().out
    assert (
        "[*] Removed the legacy coverage store (3.0 KB); coverage now lives beside each hash file."
        in out
    )


def test_legacy_removal_keeps_a_directory_that_holds_other_files(tmp_path):
    base = _legacy(tmp_path)
    (base / "keep.txt").write_text("x")
    cs.remove_legacy_store(home=str(tmp_path))
    assert (base / "keep.txt").exists()
    assert not (base / cs.LEGACY_STORE_NAME).exists()


def test_legacy_removal_is_a_silent_no_op_when_absent(tmp_path, capsys):
    cs.remove_legacy_store(home=str(tmp_path))
    cs.remove_legacy_store(home=str(tmp_path))
    assert capsys.readouterr().out == ""


def test_legacy_removal_failure_warns_and_continues(tmp_path, capsys):
    base = _legacy(tmp_path)
    base.chmod(0o500)
    try:
        cs.remove_legacy_store(home=str(tmp_path))
    finally:
        base.chmod(0o700)
    assert (base / cs.LEGACY_STORE_NAME).exists()
    assert "[!] Could not remove the legacy coverage store" in capsys.readouterr().out


def test_main_removes_the_legacy_store_only_outside_skip_init():
    import inspect
    from hate_crack import main as main_module

    source = inspect.getsource(main_module.main)
    call = source.index("remove_legacy_store()")
    assert source.rindex("if not SKIP_INIT", 0, call) > source.index("_ui.set_ui(")


def test_legacy_removal_never_raises_when_the_directory_is_unsearchable(
    tmp_path, capsys
):
    base = _legacy(tmp_path)
    hc = tmp_path / ".hate_crack"
    hc.chmod(0o000)
    try:
        cs.remove_legacy_store(home=str(tmp_path))
    finally:
        hc.chmod(0o700)
    assert "[!] Could not remove the legacy coverage store" in capsys.readouterr().out
    assert (base / cs.LEGACY_STORE_NAME).exists()


def test_legacy_removal_keeps_the_db_when_a_sibling_cannot_be_removed(tmp_path, capsys):
    base = _legacy(tmp_path)
    shm = base / (cs.LEGACY_STORE_NAME + "-shm")
    shm.unlink()
    shm.mkdir()
    (shm / "x").write_text("x")
    cs.remove_legacy_store(home=str(tmp_path))
    assert (base / cs.LEGACY_STORE_NAME).exists()
    assert "[!] Could not remove the legacy coverage store" in capsys.readouterr().out
