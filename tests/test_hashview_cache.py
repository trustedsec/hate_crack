import hashlib

import pytest

from hate_crack.hashview_cache import append_to_cache, cache_key, load_cache


@pytest.fixture(autouse=True)
def _isolate_home(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))


def test_cache_key_matches_manual_sha256():
    assert cache_key("deadbeef", "1000") == hashlib.sha256(b"deadbeef:1000").hexdigest()


def test_cache_key_coerces_int_hash_type():
    assert cache_key("deadbeef", 1000) == cache_key("deadbeef", "1000")


def test_load_cache_missing_file_returns_empty_set():
    assert load_cache() == set()


def test_append_then_load_round_trips():
    keys = [cache_key("aaa", "1000"), cache_key("bbb", "1000")]
    append_to_cache(keys)
    assert load_cache() == set(keys)


def test_append_is_additive_not_truncating():
    append_to_cache([cache_key("aaa", "1000")])
    append_to_cache([cache_key("bbb", "1000")])
    assert load_cache() == {cache_key("aaa", "1000"), cache_key("bbb", "1000")}


def test_append_empty_iterable_is_a_noop():
    append_to_cache([])
    assert load_cache() == set()


def test_load_cache_ignores_blank_lines(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    cache_dir = tmp_path / ".hate_crack"
    cache_dir.mkdir()
    (cache_dir / "hashview_uploaded_cache.txt").write_text("abc123\n\n   \ndef456\n")
    assert load_cache() == {"abc123", "def456"}
