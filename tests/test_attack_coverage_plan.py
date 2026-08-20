"""Tests for coverage-driven run planning (skip / filter decisions)."""

import pytest

from hate_crack import attack_coverage as ac


@pytest.fixture(autouse=True)
def _store(tmp_path, monkeypatch):
    s = ac.CoverageStore(tmp_path / "coverage" / "cov.sqlite3")
    monkeypatch.setattr(ac, "get_store", lambda: s)
    yield s
    s.close()


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
    plan = ac.plan_run(_spec(env), ac.set_lookup(set()))
    assert plan.skip is False
    assert plan.covered_count == 0
    assert plan.total_count == 3
    assert plan.has_overlap is False
    assert plan.filtered_entries is None
    assert len(plan.record_keys) == 3


# --- partial overlap ------------------------------------------------------


def test_partial_overlap_filters_to_novel_entries(env):
    # A prior session ran only the first two of the three rules.
    partial = env["tmp"] / "partial.rule"
    partial.write_text("c\n$1\n")
    covered = set(
        ac.plan_run(
            _spec(env, rule_files=(str(partial),)), ac.set_lookup(set())
        ).record_keys
    )

    plan = ac.plan_run(_spec(env), ac.set_lookup(covered))
    assert plan.skip is False
    assert plan.has_overlap is True
    assert plan.covered_count == 2
    assert plan.total_count == 3
    assert plan.filtered_entries == ["u"]


def test_full_overlap_skips_the_run(env):
    covered = set(ac.plan_run(_spec(env), ac.set_lookup(set())).record_keys)
    plan = ac.plan_run(_spec(env), ac.set_lookup(covered))
    assert plan.skip is True
    assert plan.covered_count == 3
    assert plan.total_count == 3


def test_same_rule_in_a_different_file_is_recognised(env):
    """The point of per-entry tracking: overlap across differently-named files."""
    covered = set(ac.plan_run(_spec(env), ac.set_lookup(set())).record_keys)
    other = env["tmp"] / "custom.rule"
    other.write_text("c\n$1\n$2\n")  # 2 of 3 already covered by r.rule
    plan = ac.plan_run(_spec(env, rule_files=(str(other),)), ac.set_lookup(covered))
    assert plan.covered_count == 2
    assert plan.filtered_entries == ["$2"]


# --- the wordlist dimension ----------------------------------------------


def test_same_rules_against_a_new_wordlist_is_not_covered(env):
    covered = set(ac.plan_run(_spec(env), ac.set_lookup(set())).record_keys)
    other_wl = env["tmp"] / "wl2.txt"
    other_wl.write_text("charlie\ndelta\n")
    plan = ac.plan_run(_spec(env, wordlists=(str(other_wl),)), ac.set_lookup(covered))
    assert plan.skip is False
    assert plan.covered_count == 0


def test_rule_kept_when_covered_for_only_some_wordlists(env):
    """Never skip work: an entry survives unless covered for every wordlist."""
    covered = set(ac.plan_run(_spec(env), ac.set_lookup(set())).record_keys)
    other_wl = env["tmp"] / "wl2.txt"
    other_wl.write_text("charlie\n")
    plan = ac.plan_run(
        _spec(env, wordlists=(env["wordlist"], str(other_wl))),
        ac.set_lookup(covered),
    )
    assert plan.skip is False
    assert plan.covered_count == 0
    assert plan.filtered_entries is None


# --- chained rule files are a cartesian product ---------------------------


def test_chained_rule_files_are_all_or_nothing(env):
    """`-r a -r b` applies the product of both files, so per-entry filtering
    would silently drop combinations. Such runs are tracked as one unit."""
    second = env["tmp"] / "r2.rule"
    second.write_text("$9\n^z\n")
    spec = _spec(env, rule_files=(env["rules"], str(second)))

    plan = ac.plan_run(spec, ac.set_lookup(set()))
    assert plan.skip is False
    assert plan.total_count == 1, "the whole chain is a single tracked unit"
    assert plan.filtered_entries is None

    covered = set(plan.record_keys)
    repeat = ac.plan_run(spec, ac.set_lookup(covered))
    assert repeat.skip is True


def test_chained_rule_files_differ_from_the_reverse_order(env):
    second = env["tmp"] / "r2.rule"
    second.write_text("$9\n")
    forward = ac.plan_run(
        _spec(env, rule_files=(env["rules"], str(second))), ac.set_lookup(set())
    )
    reverse = ac.plan_run(
        _spec(env, rule_files=(str(second), env["rules"])), ac.set_lookup(set())
    )
    assert set(forward.record_keys) != set(reverse.record_keys)


# --- masks ----------------------------------------------------------------


def test_mask_file_entries_are_tracked_per_line(env):
    masks = env["tmp"] / "m.hcmask"
    masks.write_text("?u?l?l?l?d?d\n?l?l?l?l?d\n")
    spec = ac.CoverageSpec(hash_file=env["hashes"], mask_files=(str(masks),))

    plan = ac.plan_run(spec, ac.set_lookup(set()))
    assert plan.total_count == 2
    covered = set(plan.record_keys)

    # A later, differently-named mask file overlapping on one line.
    other = env["tmp"] / "regenerated.hcmask"
    other.write_text("?u?l?l?l?d?d\n?d?d?d?d\n")
    plan2 = ac.plan_run(
        ac.CoverageSpec(hash_file=env["hashes"], mask_files=(str(other),)),
        ac.set_lookup(covered),
    )
    assert plan2.covered_count == 1
    assert plan2.filtered_entries == ["?d?d?d?d"]


def test_literal_masks_are_tracked(env):
    spec = ac.CoverageSpec(hash_file=env["hashes"], masks=("?a?a?a?a",))
    plan = ac.plan_run(spec, ac.set_lookup(set()))
    assert plan.total_count == 1
    covered = set(plan.record_keys)
    assert ac.plan_run(spec, ac.set_lookup(covered)).skip is True


def test_variant_separates_increment_runs(env):
    plain = ac.CoverageSpec(hash_file=env["hashes"], masks=("?a?a?a?a",))
    incr = ac.CoverageSpec(
        hash_file=env["hashes"], masks=("?a?a?a?a",), variant="inc:1-4"
    )
    covered = set(ac.plan_run(plain, ac.set_lookup(set())).record_keys)
    assert ac.plan_run(incr, ac.set_lookup(covered)).skip is False


# --- safety: never filter when identity is unknown ------------------------


def test_unreadable_hash_file_disables_filtering(env, tmp_path):
    spec = ac.CoverageSpec(
        hash_file=str(tmp_path / "gone.txt"),
        wordlists=(env["wordlist"],),
        rule_files=(env["rules"],),
    )
    plan = ac.plan_run(spec, ac.set_lookup(set()))
    assert plan.skip is False
    assert plan.record_keys == []
    assert plan.total_count == 0


def test_unfingerprintable_wordlist_disables_filtering(env):
    """hcatDictionary falls back to a shell glob when no lists are found."""
    spec = _spec(env, wordlists=("/nonexistent/wordlists/*",))
    plan = ac.plan_run(spec, ac.set_lookup(set()))
    assert plan.skip is False
    assert plan.record_keys == []


def test_empty_rule_file_disables_filtering(env):
    empty = env["tmp"] / "empty.rule"
    empty.write_text("# only a comment\n")
    plan = ac.plan_run(_spec(env, rule_files=(str(empty),)), ac.set_lookup(set()))
    assert plan.skip is False
    assert plan.record_keys == []


def test_wordlist_only_run_is_tracked_at_file_level(env):
    """A rule-less dictionary attack is a full repeat or nothing."""
    spec = ac.CoverageSpec(hash_file=env["hashes"], wordlists=(env["wordlist"],))
    plan = ac.plan_run(spec, ac.set_lookup(set()))
    assert plan.total_count == 1
    assert plan.filtered_entries is None

    covered = set(plan.record_keys)
    assert ac.plan_run(spec, ac.set_lookup(covered)).skip is True


def test_wordlist_only_run_keeps_going_for_a_new_list(env):
    spec = ac.CoverageSpec(hash_file=env["hashes"], wordlists=(env["wordlist"],))
    covered = set(ac.plan_run(spec, ac.set_lookup(set())).record_keys)
    other = env["tmp"] / "wl2.txt"
    other.write_text("charlie\n")
    two = ac.CoverageSpec(
        hash_file=env["hashes"], wordlists=(env["wordlist"], str(other))
    )
    plan = ac.plan_run(two, ac.set_lookup(covered))
    assert plan.skip is False
    assert plan.covered_count == 1
    assert plan.total_count == 2


def test_spec_with_no_dimension_at_all_is_inert(env):
    plan = ac.plan_run(ac.CoverageSpec(hash_file=env["hashes"]), ac.set_lookup(set()))
    assert plan.skip is False
    assert plan.record_keys == []
