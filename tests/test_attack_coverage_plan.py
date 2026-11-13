"""Tests for coverage-driven run planning (skip / filter decisions)."""

import pytest

from hate_crack import attack_coverage as ac


@pytest.fixture(autouse=True)
def _fresh_stores():
    ac.reset_store()
    ac.clear_target_memo()
    yield
    ac.reset_store()
    ac.clear_target_memo()


def _run_and_record(spec, attack="Quick Crack"):
    """Plan ``spec`` and record it as a clean completion, as main.py does."""
    plan = ac.plan_run(spec)
    assert not plan.is_inert
    ac.get_store(spec.hash_file).record(
        target=plan.target,
        kind=plan.kind,
        variant=plan.variant,
        attack=attack,
        wordlist_ids=plan.wordlist_ids,
        rows=plan.record_rows,
    )
    return plan


@pytest.fixture
def env(tmp_path):
    """A hash file, a wordlist and a 3-rule rule file."""
    hashes = tmp_path / "target.txt"
    hashes.write_text("aad3b435b51404eeaad3b435b51404ee\n")
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("alpha\nbravo\n")
    rules = tmp_path / "r.rule"
    rules.write_text("c\n$1\nu\n")
    return {
        "hashes": str(hashes),
        "wordlist": str(wordlist),
        "rules": str(rules),
        "tmp": tmp_path,
    }


def _spec(env, **kw):
    kw.setdefault("wordlists", (env["wordlist"],))
    kw.setdefault("rule_files", (env["rules"],))
    return ac.CoverageSpec(hash_file=env["hashes"], **kw)


# --- nothing recorded yet --------------------------------------------------


def test_fresh_target_runs_everything(env):
    plan = ac.plan_run(_spec(env))
    assert plan.skip is False
    assert plan.covered_count == 0
    assert plan.total_count == 3
    assert plan.has_overlap is False
    assert plan.filtered_entries is None
    assert len(plan.record_rows) == 3


# --- partial overlap ------------------------------------------------------


def test_partial_overlap_filters_to_novel_entries(env):
    # A prior session ran only the first two of the three rules.
    partial = env["tmp"] / "partial.rule"
    partial.write_text("c\n$1\n")
    _run_and_record(_spec(env, rule_files=(str(partial),)))

    plan = ac.plan_run(_spec(env))
    assert plan.skip is False
    assert plan.has_overlap is True
    assert plan.covered_count == 2
    assert plan.total_count == 3
    assert plan.filtered_entries == ["u"]
    assert len(plan.record_rows) == 1


def test_full_overlap_skips_the_run(env):
    _run_and_record(_spec(env))
    plan = ac.plan_run(_spec(env))
    assert plan.skip is True
    assert plan.covered_count == 3
    assert plan.total_count == 3


def test_same_rule_in_a_different_file_is_recognised(env):
    """The point of per-entry tracking: overlap across differently-named files."""
    _run_and_record(_spec(env))
    other = env["tmp"] / "custom.rule"
    other.write_text("c\n$1\n$2\n")  # 2 of 3 already covered by r.rule
    plan = ac.plan_run(_spec(env, rule_files=(str(other),)))
    assert plan.covered_count == 2
    assert plan.filtered_entries == ["$2"]


# --- the wordlist dimension ----------------------------------------------


def test_same_rules_against_a_new_wordlist_is_not_covered(env):
    _run_and_record(_spec(env))
    other_wl = env["tmp"] / "wl2.txt"
    other_wl.write_text("charlie\ndelta\n")
    plan = ac.plan_run(_spec(env, wordlists=(str(other_wl),)))
    assert plan.skip is False
    assert plan.covered_count == 0


def test_rule_kept_when_covered_for_only_some_wordlists(env):
    """Never skip work: an entry survives unless covered for every wordlist."""
    _run_and_record(_spec(env))
    other_wl = env["tmp"] / "wl2.txt"
    other_wl.write_text("charlie\n")
    plan = ac.plan_run(_spec(env, wordlists=(env["wordlist"], str(other_wl))))
    assert plan.skip is False
    assert plan.covered_count == 0
    assert plan.filtered_entries is None


def test_a_rewritten_wordlist_is_not_covered(env):
    spec = _spec(env)
    _run_and_record(spec)
    wordlist = env["tmp"] / "wl.txt"
    wordlist.write_text(wordlist.read_text() + "gamma\n")
    assert not ac.plan_run(spec).has_overlap


# --- chained rule files are a cartesian product ---------------------------


def test_chained_rule_files_are_all_or_nothing(env):
    """`-r a -r b` applies the product of both files, so per-entry filtering
    would silently drop combinations. Such runs are tracked as one unit."""
    second = env["tmp"] / "r2.rule"
    second.write_text("$9\n^z\n")
    spec = _spec(env, rule_files=(env["rules"], str(second)))

    plan = _run_and_record(spec)
    assert plan.skip is False
    assert plan.total_count == 1, "the whole chain is a single tracked unit"
    assert plan.filtered_entries is None

    repeat = ac.plan_run(spec)
    assert repeat.skip is True


def test_chained_rule_files_differ_from_the_reverse_order(env):
    second = env["tmp"] / "r2.rule"
    second.write_text("$9\n")
    forward = ac.plan_run(_spec(env, rule_files=(env["rules"], str(second))))
    reverse = ac.plan_run(_spec(env, rule_files=(str(second), env["rules"])))
    assert set(forward.record_rows) != set(reverse.record_rows)


# --- masks ----------------------------------------------------------------


def test_mask_file_entries_are_tracked_per_line(env):
    masks = env["tmp"] / "m.hcmask"
    masks.write_text("?u?l?l?l?d?d\n?l?l?l?l?d\n")
    spec = ac.CoverageSpec(hash_file=env["hashes"], mask_files=(str(masks),))

    plan = _run_and_record(spec)
    assert plan.total_count == 2

    # A later, differently-named mask file overlapping on one line.
    other = env["tmp"] / "regenerated.hcmask"
    other.write_text("?u?l?l?l?d?d\n?d?d?d?d\n")
    plan2 = ac.plan_run(
        ac.CoverageSpec(hash_file=env["hashes"], mask_files=(str(other),))
    )
    assert plan2.covered_count == 1
    assert plan2.filtered_entries == ["?d?d?d?d"]


def test_literal_masks_are_tracked(env):
    spec = ac.CoverageSpec(hash_file=env["hashes"], masks=("?a?a?a?a",))
    plan = _run_and_record(spec)
    assert plan.total_count == 1
    assert ac.plan_run(spec).skip is True


def test_variant_separates_increment_runs(env):
    plain = ac.CoverageSpec(hash_file=env["hashes"], masks=("?a?a?a?a",))
    incr = ac.CoverageSpec(
        hash_file=env["hashes"], masks=("?a?a?a?a",), variant="inc:1-4"
    )
    _run_and_record(plain)
    assert ac.plan_run(incr).skip is False


# --- safety: never filter when identity is unknown ------------------------


def test_unreadable_hash_file_disables_filtering(env, tmp_path):
    spec = ac.CoverageSpec(
        hash_file=str(tmp_path / "gone.txt"),
        wordlists=(env["wordlist"],),
        rule_files=(env["rules"],),
    )
    plan = ac.plan_run(spec)
    assert plan.skip is False
    assert plan.record_rows == ()
    assert plan.total_count == 0


def test_unstattable_wordlist_disables_filtering(env):
    """hcatDictionary falls back to a shell glob when no lists are found."""
    spec = _spec(env, wordlists=("/nonexistent/wordlists/*",))
    plan = ac.plan_run(spec)
    assert plan.skip is False
    assert plan.record_rows == ()
    assert plan.is_inert


def test_a_directory_named_as_a_wordlist_disables_filtering(env):
    spec = _spec(env, wordlists=(str(env["tmp"]),))
    assert ac.plan_run(spec).is_inert


def test_empty_rule_file_disables_filtering(env):
    empty = env["tmp"] / "empty.rule"
    empty.write_text("# only a comment\n")
    plan = ac.plan_run(_spec(env, rule_files=(str(empty),)))
    assert plan.skip is False
    assert plan.record_rows == ()


def test_wordlist_only_run_is_tracked_at_file_level(env):
    """A rule-less dictionary attack is a full repeat or nothing."""
    spec = ac.CoverageSpec(hash_file=env["hashes"], wordlists=(env["wordlist"],))
    plan = _run_and_record(spec)
    assert plan.total_count == 1
    assert plan.filtered_entries is None

    assert ac.plan_run(spec).skip is True


def test_wordlist_only_run_keeps_going_for_a_new_list(env):
    spec = ac.CoverageSpec(hash_file=env["hashes"], wordlists=(env["wordlist"],))
    _run_and_record(spec)
    other = env["tmp"] / "wl2.txt"
    other.write_text("charlie\n")
    two = ac.CoverageSpec(
        hash_file=env["hashes"], wordlists=(env["wordlist"], str(other))
    )
    plan = ac.plan_run(two)
    assert plan.skip is False
    assert plan.covered_count == 1
    assert plan.total_count == 2


def test_spec_with_no_dimension_at_all_is_inert(env):
    plan = ac.plan_run(ac.CoverageSpec(hash_file=env["hashes"]))
    assert plan.skip is False
    assert plan.record_rows == ()


def test_store_is_created_beside_the_hash_file(env):
    _run_and_record(_spec(env))
    assert (env["tmp"] / "target.txt.coverage.sqlite3").exists()


def test_disabled_store_makes_every_plan_inert(tmp_path):
    locked = tmp_path / "locked"
    locked.mkdir()
    hashes = locked / "h.txt"
    hashes.write_text("x\n")
    locked.chmod(0o500)
    try:
        spec = ac.CoverageSpec(str(hashes), masks=("?d?d",))
        assert ac.plan_run(spec).is_inert
    finally:
        locked.chmod(0o700)


# --- record-only specs ----------------------------------------------------


def test_record_only_never_filters(env):
    """A record-only run tries everything, so nothing is ever dropped from it."""
    _run_and_record(_spec(env))
    plan = ac.plan_run(_spec(env, record_only=True))
    assert plan.skip is False
    assert plan.covered_count == 0, "record-only must report no overlap, so no prompt"
    assert plan.filtered_entries is None
    assert plan.has_overlap is False
    assert len(plan.record_rows) == plan.total_count


def test_record_only_still_records_everything(env):
    """The asymmetry: it may not be filtered, but it really did try these."""
    plain = ac.plan_run(_spec(env))
    recorded = ac.plan_run(_spec(env, record_only=True))
    assert set(recorded.record_rows) == set(plain.record_rows)


def test_a_record_only_run_covers_a_later_ordinary_run(env):
    """A loopback run adds candidates, never removes them, so a later plain run
    of the same wordlist and rules is a genuine repeat."""
    _run_and_record(_spec(env, record_only=True))
    assert ac.plan_run(_spec(env)).skip is True


def test_a_record_only_run_is_never_skipped_by_an_earlier_one(env):
    _run_and_record(_spec(env, record_only=True))
    assert ac.plan_run(_spec(env, record_only=True)).skip is False


def test_record_only_still_goes_inert_when_identity_is_unknown(env, tmp_path):
    spec = ac.CoverageSpec(
        hash_file=str(tmp_path / "gone.txt"),
        wordlists=(env["wordlist"],),
        rule_files=(env["rules"],),
        record_only=True,
    )
    plan = ac.plan_run(spec)
    assert plan.is_inert
    assert plan.record_rows == ()
