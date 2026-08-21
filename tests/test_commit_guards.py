"""Behavioural tests for the two pre-commit guard scripts in .github/scripts/.

These execute the real scripts as a real `pre-commit` hook inside throwaway git
repositories under ``tmp_path``, then assert on whether ``git commit`` actually
succeeded. Nothing here inspects ``prek.toml`` text: a hook id in a config file
proves only that a string exists, not that a commit gets refused. That
substring-vs-behaviour trap already bit this repo once (#222), where deleted
code was reinstated with the whole suite still green.

Consequence worth keeping: neuter either script to ``exit 0`` and the tests that
cover it must fail. That property is the point of the file.

The guards exist because on 2026-07-30 an index-corrupting prek pre-push
stash/restore produced a commit that deleted 85,280 lines and staged a
gitignored local-only file, and pushed it to a public remote (#224).
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / ".github" / "scripts"
BOUNDARY_SCRIPT = SCRIPTS_DIR / "check-publication-boundary.sh"
MASS_DELETE_SCRIPT = SCRIPTS_DIR / "check-mass-deletion.sh"

# The default in check-mass-deletion.sh. Tests derive their file counts from it
# so a threshold change cannot silently leave them testing the wrong side of the
# boundary.
MASS_DELETE_THRESHOLD = 50

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")


# --- begin guard constants: these must name the forbidden paths ---
# The publication-boundary paths, as the guard must see them. Kept literal here
# on purpose: a test that spelled them indirectly could not detect the guard
# silently narrowing.
#
# CLAUDE.md, .claude/settings.json and .claude/nested/deep/notes.md were removed
# from this tuple on 2026-08-21, when CLAUDE.md and .claude/ became published.
# They moved to NON_BOUNDARY_LOOKALIKES below, so this file now asserts the
# narrowing in both directions: the remaining paths are still refused, and the
# newly published ones are provably not.
BOUNDARY_FILES = (
    ".claude/settings.local.json",
    ".claude/plans/some-plan.md",
    ".claude/specs/some-design.md",
    "docs/plans/some-plan.md",
    "docs/superpowers/some-skill/SKILL.md",
)

# A boundary path used where a test needs one specific file rather than the whole
# set. Previously CLAUDE.md; it has to be a still-forbidden path now.
A_BOUNDARY_FILE = "docs/plans/some-plan.md"

# Paths the guard must NOT block. The first group is near misses -- the guard has
# to be precise or it becomes something people disable. The second is the
# now-published set: these were refused until 2026-08-21, so asserting they
# commit cleanly is what stops the old patterns being reinstated by a
# well-meaning revert.
NON_BOUNDARY_LOOKALIKES = (
    "docs/plans.md",
    "docs/planning/roadmap.md",
    "docs/superpowers-notes.md",
    "hate_crack/claude.py",
    "CLAUDE.md.example",
    "tests/test_claude_helper.py",
    # Published deliberately as of 2026-08-21.
    "CLAUDE.md",
    ".claude/settings.json",
    ".claude/audit-docs.sh",
    ".claude/nested/deep/notes.md",
    ".claude/skills/some-skill/SKILL.md",
)
# --- end guard constants ---


def _clean_env():
    """The ambient environment minus the guard's own knobs, so a stray export in
    the developer's shell cannot make an assertion pass for the wrong reason.
    """
    env = dict(os.environ)
    env.pop("HATE_CRACK_ALLOW_MASS_DELETE", None)
    env.pop("HATE_CRACK_MASS_DELETE_THRESHOLD", None)
    return env


def _run_git(repo: Path, *args, env=None, check=True):
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=check,
        env=_clean_env() if env is None else env,
    )


def _write(repo: Path, relpath: str, text: str = "placeholder\n") -> Path:
    target = repo / relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target


@pytest.fixture
def guarded_repo(tmp_path):
    """A throwaway repo with both guard scripts installed as its pre-commit hook.

    The scripts are copied rather than symlinked so that neutering the tracked
    original mid-session cannot be masked by a stale copy, and so a test can
    never mutate the real repo's files.
    """
    repo = tmp_path / "throwaway"
    repo.mkdir()
    _run_git(repo, "init", "-q", "-b", "main")
    _run_git(repo, "config", "user.email", "guard-test@example.invalid")
    _run_git(repo, "config", "user.name", "Guard Test")
    _run_git(repo, "config", "commit.gpgsign", "false")

    hook_dir = repo / ".git" / "hooks"
    hook_dir.mkdir(parents=True, exist_ok=True)
    for script in (BOUNDARY_SCRIPT, MASS_DELETE_SCRIPT):
        dest = hook_dir / script.name
        shutil.copyfile(script, dest)
        dest.chmod(0o755)
    hook = hook_dir / "pre-commit"
    hook.write_text(
        "#!/usr/bin/env bash\nset -e\n"
        f'exec_dir="$(dirname "$0")"\n'
        f'"$exec_dir/{BOUNDARY_SCRIPT.name}"\n'
        f'"$exec_dir/{MASS_DELETE_SCRIPT.name}"\n',
        encoding="utf-8",
    )
    hook.chmod(0o755)

    # A baseline commit, so the guards have a HEAD to diff against and the
    # boundary paths are gitignored exactly as they are in the real repo.
    _write(repo, "hate_crack/main.py", "print('placeholder')\n")
    _write(
        repo,
        ".gitignore",
        "\n".join(
            (
                ".claude/settings.local.json",
                "docs/plans/",
                "docs/superpowers/",
                "",
            )
        ),
    )
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-qm", "initial")
    return repo


def _head(repo: Path) -> str:
    return _run_git(repo, "rev-parse", "HEAD").stdout.strip()


def _commit(repo: Path, message: str, env=None):
    """Attempt a commit; return the CompletedProcess without raising."""
    return _run_git(repo, "commit", "-m", message, env=env, check=False)


# --------------------------------------------------------------------------
# Deliverable A: the publication-boundary guard
# --------------------------------------------------------------------------


@pytest.mark.parametrize("relpath", BOUNDARY_FILES)
def test_force_adding_a_boundary_path_is_refused(guarded_repo, relpath):
    """`git add -f` past .gitignore is the exact path that failed in #224."""
    _write(guarded_repo, relpath)
    _run_git(guarded_repo, "add", "-f", "--", relpath)
    before = _head(guarded_repo)

    result = _commit(guarded_repo, "should never land")

    assert result.returncode != 0, (
        f"committing {relpath} was allowed:\n{result.stdout}\n{result.stderr}"
    )
    assert _head(guarded_repo) == before, "a commit was created despite the guard"
    output = result.stdout + result.stderr
    assert relpath in output, f"the guard did not name the offending path: {output!r}"
    assert "public" in output.lower(), (
        f"the guard did not explain why this is refused: {output!r}"
    )


def test_the_guard_names_every_offender_not_just_the_first(guarded_repo):
    for relpath in BOUNDARY_FILES:
        _write(guarded_repo, relpath)
    _run_git(guarded_repo, "add", "-f", "--", *BOUNDARY_FILES)

    result = _commit(guarded_repo, "should never land")

    assert result.returncode != 0
    output = result.stdout + result.stderr
    missing = [p for p in BOUNDARY_FILES if p not in output]
    assert missing == [], f"unnamed offenders: {missing}\n{output}"


def test_modifying_an_already_tracked_boundary_path_is_refused(guarded_repo):
    """The 2026-07-25 purge means none are tracked now, but a re-added one must
    not become permanently editable just because it is no longer an addition.
    """
    _write(guarded_repo, A_BOUNDARY_FILE)
    _run_git(guarded_repo, "add", "-f", "--", A_BOUNDARY_FILE)
    # Sneak it into history the way the incident did, bypassing the hook.
    _run_git(guarded_repo, "commit", "-qm", "smuggled in", "--no-verify")

    _write(guarded_repo, A_BOUNDARY_FILE, "edited\n")
    _run_git(guarded_repo, "add", "-f", "--", A_BOUNDARY_FILE)
    before = _head(guarded_repo)

    result = _commit(guarded_repo, "edit the smuggled file")

    assert result.returncode != 0, "modifying a boundary path was allowed"
    assert _head(guarded_repo) == before


def test_deleting_a_tracked_boundary_path_is_allowed(guarded_repo):
    """Removing an accidentally tracked boundary file must stay possible --
    otherwise the guard blocks its own cleanup.
    """
    _write(guarded_repo, A_BOUNDARY_FILE)
    _run_git(guarded_repo, "add", "-f", "--", A_BOUNDARY_FILE)
    _run_git(guarded_repo, "commit", "-qm", "smuggled in", "--no-verify")
    before = _head(guarded_repo)

    _run_git(guarded_repo, "rm", "-q", "--cached", "--", A_BOUNDARY_FILE)
    result = _commit(guarded_repo, "remove the smuggled file")

    assert result.returncode == 0, (
        f"deleting a boundary path was blocked:\n{result.stdout}\n{result.stderr}"
    )
    assert _head(guarded_repo) != before


def test_an_ordinary_commit_is_allowed(guarded_repo):
    _write(guarded_repo, "hate_crack/main.py", "print('changed')\n")
    _write(guarded_repo, "docs/README-extra.md", "notes\n")
    _run_git(guarded_repo, "add", "-A")
    before = _head(guarded_repo)

    result = _commit(guarded_repo, "ordinary work")

    assert result.returncode == 0, (
        f"a normal commit was blocked:\n{result.stdout}\n{result.stderr}"
    )
    assert _head(guarded_repo) != before


@pytest.mark.parametrize("relpath", NON_BOUNDARY_LOOKALIKES)
def test_lookalike_paths_are_not_blocked(guarded_repo, relpath):
    _write(guarded_repo, relpath)
    _run_git(guarded_repo, "add", "-A")

    result = _commit(guarded_repo, "ordinary work")

    assert result.returncode == 0, (
        f"{relpath} was wrongly treated as a boundary path:"
        f"\n{result.stdout}\n{result.stderr}"
    )


def test_boundary_guard_runs_standalone_in_a_repo_with_no_commits(tmp_path):
    """The guard must not crash on a repo without HEAD -- an empty index still
    has a staged changeset, and the very first commit is checkable.
    """
    repo = tmp_path / "empty"
    repo.mkdir()
    _run_git(repo, "init", "-q", "-b", "main")
    _write(repo, A_BOUNDARY_FILE)
    _run_git(repo, "add", "-f", "--", A_BOUNDARY_FILE)

    result = subprocess.run(
        [str(BOUNDARY_SCRIPT)],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0, f"unblocked in a fresh repo:\n{result.stderr}"
    assert A_BOUNDARY_FILE in result.stdout + result.stderr


# --------------------------------------------------------------------------
# Deliverable B: the mass-deletion sanity check
# --------------------------------------------------------------------------


def _repo_with_many_tracked_files(repo: Path, count: int) -> list[str]:
    paths = [f"bulk/file_{i:03d}.txt" for i in range(count)]
    for path in paths:
        _write(repo, path, f"{path}\n")
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-qm", f"add {count} files", "--no-verify")
    return paths


def test_deleting_more_than_the_threshold_is_refused(guarded_repo):
    paths = _repo_with_many_tracked_files(guarded_repo, MASS_DELETE_THRESHOLD + 5)
    _run_git(guarded_repo, "rm", "-q", "--cached", "--", *paths)
    before = _head(guarded_repo)

    result = _commit(guarded_repo, "wipe the tree")

    assert result.returncode != 0, (
        f"a mass deletion was allowed:\n{result.stdout}\n{result.stderr}"
    )
    assert _head(guarded_repo) == before
    output = result.stdout + result.stderr
    assert str(len(paths)) in output, f"the count was not reported: {output!r}"
    # The message must carry the actual recovery, not just the diagnosis.
    assert "git config core.bare false" in output, output
    assert "git reset HEAD" in output, output
    assert "HATE_CRACK_ALLOW_MASS_DELETE=1" in output, output


def test_the_override_env_var_permits_a_genuine_mass_deletion(guarded_repo):
    paths = _repo_with_many_tracked_files(guarded_repo, MASS_DELETE_THRESHOLD + 5)
    _run_git(guarded_repo, "rm", "-q", "--cached", "--", *paths)
    before = _head(guarded_repo)

    env = {**_clean_env(), "HATE_CRACK_ALLOW_MASS_DELETE": "1"}
    result = _commit(guarded_repo, "intentional bulk removal", env=env)

    assert result.returncode == 0, (
        f"the override did not work:\n{result.stdout}\n{result.stderr}"
    )
    assert _head(guarded_repo) != before


def test_deleting_below_the_threshold_is_allowed(guarded_repo):
    paths = _repo_with_many_tracked_files(guarded_repo, MASS_DELETE_THRESHOLD - 1)
    _run_git(guarded_repo, "rm", "-q", "--cached", "--", *paths)
    before = _head(guarded_repo)

    result = _commit(guarded_repo, "ordinary cleanup")

    assert result.returncode == 0, (
        f"a plausible deletion was blocked:\n{result.stdout}\n{result.stderr}"
    )
    assert _head(guarded_repo) != before


def test_deletions_are_counted_by_file_not_by_line(guarded_repo):
    """A handful of very large files must not trip the guard: the incident's
    signature is the file count, and a line-count threshold would fire on any
    legitimate vendored-data removal.
    """
    paths = _repo_with_many_tracked_files(guarded_repo, 3)
    for path in paths:
        _write(guarded_repo, path, "line\n" * 50_000)
    _run_git(guarded_repo, "add", "-A")
    _run_git(guarded_repo, "commit", "-qm", "grow them", "--no-verify")
    _run_git(guarded_repo, "rm", "-q", "--cached", "--", *paths)

    result = _commit(guarded_repo, "remove three large files")

    assert result.returncode == 0, (
        f"a 3-file deletion was blocked:\n{result.stdout}\n{result.stderr}"
    )


# --------------------------------------------------------------------------
# Both guards must actually be reachable from a fresh clone.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("script", [BOUNDARY_SCRIPT, MASS_DELETE_SCRIPT])
def test_guard_scripts_are_tracked_and_executable(script):
    """A hook pointing at an untracked or non-executable script fails open on a
    fresh clone -- which is why the old audit-docs hook had to be removed.
    """
    rel = script.relative_to(REPO_ROOT).as_posix()
    tracked = subprocess.run(
        ["git", "ls-files", "-s", "--", rel],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    ).stdout.split()
    assert tracked, f"{rel} is not tracked"
    assert tracked[0] == "100755", f"{rel} is tracked without the executable bit"
