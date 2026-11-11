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
