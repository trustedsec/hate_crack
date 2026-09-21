"""coverage precompute warms the manifest cache."""

import pytest

from hate_crack import attack_coverage as ac


@pytest.fixture
def store(tmp_path):
    s = ac.CoverageStore(tmp_path / "cov.sqlite3")
    yield s
    s.close()


def test_precompute_builds_manifests(store, tmp_path):
    a = tmp_path / "a.rule"
    a.write_text("$1\nc\n", encoding="utf-8")
    b = tmp_path / "b.hcmask"
    b.write_text("?d?d\n", encoding="utf-8")
    built, failed = store.precompute([(str(a), "rule"), (str(b), "mask")])
    assert (built, failed) == (2, 0)


def test_precompute_counts_unreadable_files_as_failed(store, tmp_path):
    a = tmp_path / "a.rule"
    a.write_text("$1\n", encoding="utf-8")
    built, failed = store.precompute(
        [(str(a), "rule"), (str(tmp_path / "gone.rule"), "rule")]
    )
    assert (built, failed) == (1, 1)


def test_precompute_makes_the_next_plan_a_cache_hit(store, tmp_path, monkeypatch):
    """Precompute primes the manifest, so the next plan does not intern.

    Assert on intern_entries, NOT on read_entries. file_entry_ids reads and
    parses the file on every call, by design -- see
    test_manifest_hit_skips_interning_not_reading in Task 2. Asserting
    read_entries is skipped forces entries to be rebuilt from the
    dictionary, which corrupts mask files.
    """
    a = tmp_path / "a.rule"
    a.write_text("$1\nc\n", encoding="utf-8")
    store.precompute([(str(a), "rule")])
    monkeypatch.setattr(
        store,
        "intern_entries",
        lambda *args, **kwargs: pytest.fail("intern_entries ran after precompute"),
    )
    entries, ids = store.file_entry_ids(str(a), "rule")
    assert entries == ["$1", "c"]
    assert len(ids) == 2
