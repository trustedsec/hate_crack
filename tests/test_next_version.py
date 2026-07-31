"""Tests for tools/next_version.py -- the release policy itself.

The policy is ordinary semver with the bump derived from the batch: the second
component moves only for features, `nightly-dev` cuts release candidates for the
version the batch is heading toward, and `main` cuts the final of that same
target.

Two prior schemes in this repo got the *ordering* wrong, so the ordering is
asserted here against the real PEP 440 parser rather than by eyeball:

* Tagging `vX.Y.0-rc.N` aimed candidates at the *current* cycle's version, so a
  candidate sorted below the release it was heading for.
* Making nightlies ordinary final versions removed the pre-release marker
  entirely, so any tool ranking versions considered a nightly to be the latest
  release.

Aiming candidates one version forward fixes both: a candidate sorts above the
release that precedes it and below the release it becomes, and it is still a
pre-release.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest
from packaging.version import parse

from tools.next_version import (
    commit_messages,
    compute,
    has_feature,
    latest_final,
    next_rc_number,
    parse_final,
    target_version,
)

# --- the baseline ------------------------------------------------------------


@pytest.mark.parametrize(
    "tag,expected",
    [
        ("v2.20.0", (2, 20, 0)),
        ("v10.4.7", (10, 4, 7)),
        # Not released versions: a candidate, a dev build, a local version, and
        # the shapes a hand-pushed tag might take.
        ("v2.20.1rc1", None),
        ("v2.20.1.dev3", None),
        ("v2.20.0+g1234567", None),
        ("2.20.0", None),
        ("v2.20", None),
        ("nightly", None),
    ],
)
def test_only_released_versions_are_baseline_candidates(tag, expected):
    """The baseline must be something that actually shipped.

    Letting a candidate be the baseline would compound: 2.20.1rc1 would beget
    2.20.2rc1 without 2.20.1 ever existing.
    """
    assert parse_final(tag) == expected


def test_latest_final_ignores_candidates_and_picks_the_highest():
    tags = ["v2.19.0", "v2.20.0", "v2.20.1rc1", "v2.20.1rc2", "v2.21.0rc1"]
    assert latest_final(tags) == (2, 20, 0)


def test_latest_final_compares_numerically_not_lexically():
    """The bug that started all of this was a lexical tie-break: '2.19.15' sorts
    above '2.20.0' as text, and below it as a version."""
    assert latest_final(["v2.9.0", "v2.10.0"]) == (2, 10, 0)
    assert latest_final(["v2.19.15", "v2.20.0"]) == (2, 20, 0)


def test_no_tags_at_all_starts_from_zero():
    assert latest_final([]) == (0, 0, 0)
    assert latest_final(["nightly", "some-marker"]) == (0, 0, 0)


# --- feature detection ------------------------------------------------------


@pytest.mark.parametrize(
    "subject",
    [
        "feat: add a thing",
        "feat(config): add a thing",
        "feat!: replace a thing",
        "feat(config)!: replace a thing",
        "FEAT: shouting still counts",
    ],
)
def test_feature_subjects_are_detected(subject):
    assert has_feature([subject])


@pytest.mark.parametrize(
    "subject",
    [
        "fix: repair a thing",
        "fix(config): repair a thing",
        "docs(changelog): write a thing",
        "chore: bump a thing",
        "test: cover a thing",
        "refactor: move a thing",
        "perf: speed a thing up",
        "ci: retag a thing",
    ],
)
def test_non_feature_subjects_are_not_features(subject):
    assert not has_feature([subject])


def test_the_word_feature_in_a_body_does_not_promote_the_batch():
    """Anchored at the subject on purpose. A fix whose body explains which
    feature it repairs must not cut a minor release."""
    message = "fix(attacks): correct the mask\n\nThis feature was broken: feat\n"
    assert not has_feature([message])


def test_a_breaking_footer_counts_as_a_feature_not_a_major():
    """Deliberate: an automatic major is one mistyped subject away from an
    irreversible published release, so major stays a human act."""
    assert has_feature(["fix: something\n\nBREAKING CHANGE: it moved\n"])
    assert has_feature(["refactor!: rename the entry point"])
    base = (2, 20, 0)
    assert target_version(base, ["refactor!: rename it"]) == (2, 21, 0)


def test_one_feature_among_many_fixes_still_cuts_a_minor():
    messages = ["fix: a", "docs: b", "feat: c", "chore: d"]
    assert target_version((2, 20, 0), messages) == (2, 21, 0)


# --- the target version -----------------------------------------------------


def test_fix_only_batch_moves_the_third_component():
    assert target_version((2, 20, 0), ["fix: a", "docs: b"]) == (2, 20, 1)


def test_fix_only_batch_builds_on_a_previous_patch():
    assert target_version((2, 20, 1), ["fix: a"]) == (2, 20, 2)


def test_feature_batch_moves_the_second_and_zeroes_the_third():
    assert target_version((2, 20, 7), ["feat: a"]) == (2, 21, 0)


def test_an_empty_batch_has_no_target():
    """A workflow re-run on an already-tagged commit must cut nothing rather
    than invent a version."""
    assert target_version((2, 20, 0), []) is None
    assert compute("stable", ["v2.20.0"], []) is None
    assert compute("nightly", ["v2.20.0"], []) is None


# --- candidate numbering ----------------------------------------------------


def test_first_candidate_for_a_target_is_rc1():
    assert next_rc_number((2, 20, 1), ["v2.20.0"]) == 1


def test_candidates_count_upward_within_a_target():
    tags = ["v2.20.0", "v2.20.1rc1", "v2.20.1rc2"]
    assert next_rc_number((2, 20, 1), tags) == 3


def test_candidate_numbering_is_per_target():
    """A feature landing mid-cycle changes the target, and the new target starts
    its own count rather than inheriting the old one."""
    tags = ["v2.20.0", "v2.20.1rc1", "v2.20.1rc2"]
    assert next_rc_number((2, 21, 0), tags) == 1


def test_candidate_numbering_survives_a_deleted_tag():
    """Counts from the highest seen, not from how many exist, so deleting rc2
    cannot hand out rc2 again to a different commit."""
    tags = ["v2.20.0", "v2.20.1rc1", "v2.20.1rc3"]
    assert next_rc_number((2, 20, 1), tags) == 4


# --- the two channels, and the ordering that motivates the whole design -----


def test_nightly_cuts_a_candidate_for_the_next_version():
    tags = ["v2.20.0"]
    assert compute("nightly", tags, ["fix: a"]) == "v2.20.1rc1"
    assert compute("nightly", tags, ["feat: a"]) == "v2.21.0rc1"


def test_main_cuts_the_final_of_the_same_target():
    """Merging nightly-dev down promotes the candidate rather than inventing a
    different number: the fix-only cycle above ends at 2.20.1, not 2.21.0."""
    tags = ["v2.20.0", "v2.20.1rc1", "v2.20.1rc2"]
    assert compute("stable", tags, ["fix: a"]) == "v2.20.1"
    assert compute("stable", ["v2.20.0", "v2.21.0rc1"], ["feat: a"]) == "v2.21.0"


def test_candidates_sort_above_the_previous_release_and_below_their_own():
    """The property both earlier schemes failed, checked with the real parser.

    A candidate must look newer than what shipped before it and older than what
    it becomes. Asserted end to end across a whole fix-only cycle.
    """
    shipped = parse("2.20.0")
    rc1 = parse(compute("nightly", ["v2.20.0"], ["fix: a"]).lstrip("v"))
    rc2 = parse(
        compute("nightly", ["v2.20.0", "v2.20.1rc1"], ["fix: a", "fix: b"]).lstrip("v")
    )
    final = parse(
        compute("stable", ["v2.20.0", "v2.20.1rc1", "v2.20.1rc2"], ["fix: a"]).lstrip(
            "v"
        )
    )

    assert shipped < rc1 < rc2 < final
    assert rc1.is_prerelease and rc2.is_prerelease
    assert not final.is_prerelease, "main must publish a real release, not a candidate"


def test_a_feature_cycle_also_orders_correctly_against_the_fix_cycle():
    """2.20.1 < 2.21.0rc1 < 2.21.0 -- a candidate for the next minor must not
    look older than the patch release that preceded it."""
    patch_release = parse("2.20.1")
    rc = parse(compute("nightly", ["v2.20.1"], ["feat: a"]).lstrip("v"))
    final = parse(compute("stable", ["v2.20.1", "v2.21.0rc1"], ["feat: a"]).lstrip("v"))
    assert patch_release < rc < final


def test_unknown_channel_is_a_loud_error():
    with pytest.raises(ValueError):
        compute("beta", ["v2.20.0"], ["fix: a"])


# --- the git boundary -------------------------------------------------------


def _git(*args, cwd):
    return subprocess.run(
        [str(shutil.which("git")), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@example.invalid",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@example.invalid",
        },
    ).stdout


def test_commit_messages_keeps_multi_line_bodies_intact(tmp_path):
    """NUL-delimited for a reason: a body with a blank line would otherwise be
    split into separate 'commits', and a BREAKING CHANGE footer would be read as
    its own subject."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git("init", "-q", "-b", "main", cwd=repo)
    (repo / "f.txt").write_text("a\n")
    _git("add", "-A", cwd=repo)
    _git("commit", "-qm", "fix: the first thing", cwd=repo)
    _git("tag", "v2.20.0", cwd=repo)

    (repo / "f.txt").write_text("b\n")
    _git("add", "-A", cwd=repo)
    _git(
        "commit",
        "-qm",
        "fix: the second thing\n\nA body with a blank line.\n\nBREAKING CHANGE: yes\n",
        cwd=repo,
    )

    messages = commit_messages(str(repo), (2, 20, 0))

    assert len(messages) == 1, f"body split into separate messages: {messages}"
    assert "BREAKING CHANGE: yes" in messages[0]
    # And the footer is therefore seen, which is the point.
    assert has_feature(messages)


def test_commit_messages_since_baseline_excludes_the_baseline_itself(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git("init", "-q", "-b", "main", cwd=repo)
    (repo / "f.txt").write_text("a\n")
    _git("add", "-A", cwd=repo)
    _git("commit", "-qm", "feat: shipped already", cwd=repo)
    _git("tag", "v2.20.0", cwd=repo)

    assert commit_messages(str(repo), (2, 20, 0)) == []

    (repo / "f.txt").write_text("b\n")
    _git("add", "-A", cwd=repo)
    _git("commit", "-qm", "fix: not yet shipped", cwd=repo)

    messages = commit_messages(str(repo), (2, 20, 0))
    assert len(messages) == 1
    assert "not yet shipped" in messages[0]
    assert not has_feature(messages), "the shipped feat must not leak into this batch"


def test_baseline_need_not_be_reachable_from_head(tmp_path):
    """main's release tag can sit on a commit nightly-dev does not contain.

    A reachability-restricted baseline would compute the next nightly from a
    stale release and hand out a version below what already shipped.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _git("init", "-q", "-b", "main", cwd=repo)
    (repo / "f.txt").write_text("a\n")
    _git("add", "-A", cwd=repo)
    _git("commit", "-qm", "fix: base", cwd=repo)
    _git("tag", "v2.20.0", cwd=repo)

    # A release that happened on main, on a commit this branch will not contain.
    (repo / "f.txt").write_text("released\n")
    _git("add", "-A", cwd=repo)
    _git("commit", "-qm", "fix: released on main", cwd=repo)
    _git("tag", "v2.20.1", cwd=repo)

    _git("checkout", "-q", "-b", "nightly-dev", "v2.20.0", cwd=repo)
    (repo / "f.txt").write_text("nightly\n")
    _git("add", "-A", cwd=repo)
    _git("commit", "-qm", "fix: on the nightly branch", cwd=repo)

    tags = [t for t in _git("tag", cwd=repo).splitlines() if t.strip()]
    assert latest_final(tags) == (2, 20, 1), "baseline must see main's release tag"

    messages = commit_messages(str(repo), (2, 20, 1))
    got = compute("nightly", tags, messages)
    assert got == "v2.20.2rc1", (
        f"the next nightly must sort above the release that already shipped, got {got}"
    )
    assert parse("2.20.1") < parse(got.lstrip("v"))
