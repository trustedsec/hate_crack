"""Tests for the release versioning policy in tools/next_version.py.

The policy: main carries `X.Y.0` and cuts `X.(Y+1).0` when nightly-dev is merged
down; nightly-dev uses the patch component as a per-merge counter, so `X.Y.1`,
`X.Y.2`, … land between releases.

The integration tests build real git repositories and walk a full cycle, because
the failure this policy is most exposed to is ordering — a nightly version that
sorts below the stable release it followed would put nightly users behind a
"downgrade to stable" prompt.
"""

import importlib.util
import os
import subprocess

import pytest
from packaging.version import parse as parse_version

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO_ROOT, "tools", "next_version.py")


def _load():
    spec = importlib.util.spec_from_file_location("next_version", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


nv = _load()


class TestParsing:
    def test_final_tags_parse(self):
        assert nv.parse_tag("v2.19.3") == (2, 19, 3)

    @pytest.mark.parametrize(
        "tag",
        [
            "v2.19.0-rc.3",  # retired pre-release scheme
            "v2.19.0rc3",
            "2.19.0",  # missing v
            "v2.19",
            "vX.Y.Z",
            "",
        ],
    )
    def test_non_final_tags_rejected(self, tag):
        assert nv.parse_tag(tag) is None

    def test_latest_release_ignores_pre_release_tags(self):
        """An rc tag left over from the old scheme must never be a baseline."""
        tags = ["v2.18.0", "v2.19.0-rc.8", "v2.18.1-rc.3"]
        assert nv.latest_release(tags) == (2, 18, 0)

    def test_latest_release_compares_numerically(self):
        assert nv.latest_release(["v2.9.0", "v2.10.0"]) == (2, 10, 0)

    def test_latest_release_with_no_tags(self):
        assert nv.latest_release([]) == (0, 0, 0)


class TestBreakingDetection:
    @pytest.mark.parametrize(
        "message",
        [
            "feat!: drop python 3.12",
            "refactor(api)!: rename everything",
            "fix: something\n\nBREAKING CHANGE: config moved\n",
            "fix: something\n\nBREAKING-CHANGE: config moved\n",
        ],
    )
    def test_breaking_recognised(self, message):
        assert nv.has_breaking_change([message]) is True

    @pytest.mark.parametrize(
        "message",
        [
            "feat: add rosetta attack",
            "fix(cleanup): default pwdump_format",
            "docs: note the breaking change policy",
            "chore: bump ruff",
        ],
    )
    def test_non_breaking(self, message):
        assert nv.has_breaking_change([message]) is False

    def test_breaking_anywhere_in_the_set_wins(self):
        assert nv.has_breaking_change(["chore: x", "feat!: y", "docs: z"]) is True


class TestStableBumps:
    def test_minor_bump_resets_patch_to_zero(self):
        """The defining property: a release is always X.Y.0."""
        assert nv.next_stable((2, 19, 5), breaking=False) == "v2.20.0"

    def test_breaking_bumps_major(self):
        assert nv.next_stable((2, 19, 5), breaking=True) == "v3.0.0"

    def test_first_release(self):
        assert nv.next_stable((0, 0, 0), breaking=False) == "v0.1.0"


class TestNightlyBumps:
    def test_counts_up_from_the_release(self):
        assert nv.next_nightly((2, 19, 0), ["v2.19.0"]) == "v2.19.1"

    def test_counts_up_from_the_previous_nightly(self):
        tags = ["v2.19.0", "v2.19.1", "v2.19.2"]
        assert nv.next_nightly((2, 19, 2), tags) == "v2.19.3"

    def test_skips_taken_numbers(self):
        """A hand-pushed or re-run tag must not stall the counter."""
        tags = ["v2.19.0", "v2.19.1", "v2.19.2", "v2.19.3"]
        # Base is behind the tags that exist (a re-run against an older commit),
        # so it walks up past 2, 3 rather than colliding on them.
        assert nv.next_nightly((2, 19, 1), tags) == "v2.19.4"
        assert nv.next_nightly((2, 19, 3), tags) == "v2.19.4"

    def test_never_produces_a_zero_patch(self):
        """X.Y.0 is reserved for releases, so nightly must never mint one."""
        for patch in range(0, 5):
            tag = nv.next_nightly((2, 19, patch), [])
            assert not tag.endswith(".0")


class TestOrdering:
    def test_nightlies_sort_between_the_releases_that_bracket_them(self):
        stable = parse_version("2.19.0")
        following = parse_version("2.20.0")
        for patch in range(1, 6):
            nightly = parse_version(f"2.19.{patch}")
            assert stable < nightly < following

    def test_a_nightly_never_sorts_below_its_starting_release(self):
        """This is what keeps the startup check from offering a downgrade."""
        base = (2, 19, 0)
        tags = ["v2.19.0"]
        for _ in range(4):
            tag = nv.next_nightly(base, tags)
            tags.append(tag)
            assert parse_version(tag.lstrip("v")) > parse_version("2.19.0")
            base = nv.parse_tag(tag)


def _run_git(repo, *args):
    subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@e",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@e",
        },
    )


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "repo"
    path.mkdir()
    _run_git(path, "init", "-b", "main")
    (path / "f").write_text("0\n")
    _run_git(path, "add", "f")
    _run_git(path, "commit", "-m", "chore: init")
    return path


def _commit(repo, message, content=None):
    (repo / "f").write_text(content or message)
    _run_git(repo, "add", "f")
    _run_git(repo, "commit", "-m", message)


class TestAgainstRealGit:
    def test_no_new_commits_means_no_tag(self, repo):
        _run_git(repo, "tag", "v2.19.0")
        assert nv.compute(nv.STABLE, str(repo)) is None
        assert nv.compute(nv.NIGHTLY, str(repo)) is None

    def test_chore_only_push_to_main_still_releases(self, repo):
        """The old policy skipped these, which would strand a chore-only merge."""
        _run_git(repo, "tag", "v2.19.0")
        _commit(repo, "docs: fix a typo")
        assert nv.compute(nv.STABLE, str(repo)) == "v2.20.0"

    def test_breaking_commit_in_the_merged_range_bumps_major(self, repo):
        _run_git(repo, "tag", "v2.19.0")
        _commit(repo, "feat!: rework the config")
        assert nv.compute(nv.STABLE, str(repo)) == "v3.0.0"

    def test_breaking_footer_in_a_commit_body_is_seen(self, repo):
        """Bodies must be read, not just subjects."""
        _run_git(repo, "tag", "v2.19.0")
        (repo / "f").write_text("x")
        _run_git(repo, "add", "f")
        _run_git(repo, "commit", "-m", "fix: x", "-m", "BREAKING CHANGE: dropped y")
        assert nv.compute(nv.STABLE, str(repo)) == "v3.0.0"

    def test_full_cycle_release_then_nightlies_then_release(self, repo):
        """Walk the documented lifecycle and assert it stays monotonic."""
        _run_git(repo, "tag", "v2.19.0")
        _run_git(repo, "checkout", "-b", "nightly-dev")

        seen = ["2.19.0"]
        for i in range(3):
            _commit(repo, f"feat: nightly work {i}")
            tag = nv.compute(nv.NIGHTLY, str(repo))
            assert tag == f"v2.19.{i + 1}"
            _run_git(repo, "tag", tag)
            seen.append(tag.lstrip("v"))

        _run_git(repo, "checkout", "main")
        _run_git(repo, "merge", "--no-ff", "nightly-dev", "-m", "Merge nightly-dev")
        release = nv.compute(nv.STABLE, str(repo))
        assert release == "v2.20.0"
        _run_git(repo, "tag", release)
        seen.append(release.lstrip("v"))

        parsed = [parse_version(v) for v in seen]
        assert parsed == sorted(parsed), f"versions went backwards: {seen}"

    def test_nightly_after_a_release_does_not_regress(self, repo):
        """The trap this policy is most exposed to.

        The v2.20.0 tag lives on main's merge commit, which nightly-dev does not
        contain. Computing the next nightly from tags *reachable from HEAD* would
        yield v2.19.4 — a version below the 2.20.0 release that already shipped,
        so every nightly user would be told to upgrade to stable.
        """
        _run_git(repo, "tag", "v2.19.0")
        _run_git(repo, "checkout", "-b", "nightly-dev")
        _commit(repo, "feat: a")
        _run_git(repo, "tag", "v2.19.1")

        _run_git(repo, "checkout", "main")
        _run_git(repo, "merge", "--no-ff", "nightly-dev", "-m", "Merge nightly-dev")
        _run_git(repo, "tag", "v2.20.0")

        _run_git(repo, "checkout", "nightly-dev")
        _commit(repo, "feat: b")
        tag = nv.compute(nv.NIGHTLY, str(repo))
        assert tag == "v2.20.1"
        assert parse_version(tag.lstrip("v")) > parse_version("2.20.0")

    def test_retired_rc_tags_do_not_become_a_baseline(self, repo):
        """The live repo still carries v2.19.0-rc.* from the old scheme."""
        _run_git(repo, "tag", "v2.18.0")
        _run_git(repo, "tag", "v2.19.0-rc.8")
        _commit(repo, "feat: next")
        assert nv.compute(nv.NIGHTLY, str(repo)) == "v2.18.1"
        assert nv.compute(nv.STABLE, str(repo)) == "v2.19.0"

    def test_cli_prints_the_tag(self, repo):
        _run_git(repo, "tag", "v2.19.0")
        _commit(repo, "feat: x")
        result = subprocess.run(
            ["python3", SCRIPT, "--channel", "nightly", "--repo-dir", str(repo)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert result.stdout.strip() == "v2.19.1"

    def test_cli_prints_nothing_when_there_is_nothing_to_tag(self, repo):
        _run_git(repo, "tag", "v2.19.0")
        result = subprocess.run(
            ["python3", SCRIPT, "--channel", "stable", "--repo-dir", str(repo)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert result.stdout.strip() == ""
