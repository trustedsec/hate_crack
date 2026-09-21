"""plan_run over interned ids rather than sha256 keys."""

import pytest

from hate_crack import attack_coverage as ac


@pytest.fixture
def store(tmp_path, monkeypatch):
    s = ac.CoverageStore(tmp_path / "cov.sqlite3")
    monkeypatch.setattr(ac, "get_store", lambda: s)
    yield s
    s.close()


def _f(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


def _spec(tmp_path, store, rule_text, wordlist_text="a\n"):
    hashes = _f(tmp_path, "hashes.txt", "aad3b435b51404ee\n")
    rules = _f(tmp_path, "r.rule", rule_text)
    words = _f(tmp_path, "w.txt", wordlist_text)
    return ac.CoverageSpec(hash_file=hashes, wordlists=(words,), rule_files=(rules,))


def test_fresh_plan_has_no_overlap(store, tmp_path):
    plan = ac.plan_run(_spec(tmp_path, store, "$1\nc\n"), store=store)
    assert plan.kind == "rule"
    assert plan.covered_count == 0
    assert plan.total_count == 2
    assert len(plan.record_rows) == 2


def test_record_rows_are_int_triples(store, tmp_path):
    """A malformed row must be structurally impossible, not merely caught by
    record_ids's silent fallback -- see Task 4 correction 6."""
    plan = ac.plan_run(_spec(tmp_path, store, "$1\nc\n"), store=store)
    assert plan.record_rows
    assert all(
        isinstance(t, tuple) and len(t) == 3 and all(isinstance(x, int) for x in t)
        for t in plan.record_rows
    )


def test_second_identical_plan_is_fully_covered(store, tmp_path):
    spec = _spec(tmp_path, store, "$1\nc\n")
    first = ac.plan_run(spec, store=store)
    run_id = store.log_run(first.target, attack="Dictionary", kind="rule")
    store.record_ids(first.target_id, first.record_rows, run_id)
    second = ac.plan_run(spec, store=store)
    assert second.skip is True
    assert second.covered_count == 2


def test_partial_overlap_filters_only_the_new_entries(store, tmp_path):
    spec = _spec(tmp_path, store, "$1\nc\n")
    first = ac.plan_run(spec, store=store)
    run_id = store.log_run(first.target, kind="rule")
    store.record_ids(first.target_id, first.record_rows, run_id)
    wider = _spec(tmp_path, store, "$1\nc\nsa@\n")
    plan = ac.plan_run(wider, store=store)
    assert plan.covered_count == 2
    assert plan.filtered_entries == ["sa@"]


def test_filtering_does_not_read_text_from_the_dictionary(store, tmp_path, monkeypatch):
    """filtered_entries must come from the in-memory file lines.

    Reading them back out of the dictionary would mean up to 6M lookups to
    write one filtered file, which could cost more than the scheme saves.
    """
    spec = _spec(tmp_path, store, "$1\nc\n")
    first = ac.plan_run(spec, store=store)
    run_id = store.log_run(first.target, kind="rule")
    store.record_ids(first.target_id, first.record_rows, run_id)
    wider = _spec(tmp_path, store, "$1\nc\nsa@\n")
    monkeypatch.setattr(
        store, "entry_text", lambda _id: pytest.fail("entry_text was called")
    )
    plan = ac.plan_run(wider, store=store)
    assert plan.filtered_entries == ["sa@"]


def test_intern_failure_yields_an_inert_plan(store, tmp_path, monkeypatch):
    monkeypatch.setattr(store, "intern_entries", lambda *a, **k: None)
    plan = ac.plan_run(_spec(tmp_path, store, "$1\n"), store=store)
    assert plan.is_inert


def test_target_intern_failure_yields_an_inert_plan(store, tmp_path, monkeypatch):
    monkeypatch.setattr(store, "intern_target", lambda *a, **k: None)
    plan = ac.plan_run(_spec(tmp_path, store, "$1\n"), store=store)
    assert plan.is_inert


def test_record_only_never_filters(store, tmp_path):
    hashes = _f(tmp_path, "hashes.txt", "aad3b435b51404ee\n")
    rules = _f(tmp_path, "r.rule", "$1\nc\n")
    words = _f(tmp_path, "w.txt", "a\n")
    spec = ac.CoverageSpec(
        hash_file=hashes,
        wordlists=(words,),
        rule_files=(rules,),
        record_only=True,
    )
    first = ac.plan_run(spec, store=store)
    run_id = store.log_run(first.target, kind="rule")
    store.record_ids(first.target_id, first.record_rows, run_id)
    second = ac.plan_run(spec, store=store)
    assert second.skip is False
    assert second.covered_count == 0


def test_chained_rule_files_stay_one_all_or_nothing_entry(store, tmp_path):
    hashes = _f(tmp_path, "hashes.txt", "aad3b435b51404ee\n")
    a = _f(tmp_path, "a.rule", "$1\n")
    b = _f(tmp_path, "b.rule", "c\n")
    words = _f(tmp_path, "w.txt", "a\n")
    spec = ac.CoverageSpec(hash_file=hashes, wordlists=(words,), rule_files=(a, b))
    plan = ac.plan_run(spec, store=store)
    assert plan.total_count == 1
    assert plan.filtered_entries is None
