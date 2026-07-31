"""Guards on the release-versioning wiring.

The scheme is: ``main`` is stable at ``X.Y.0`` (a MINOR bump per merge) and
``nightly-dev`` rolls through patch numbers ``X.Y.1``, ``X.Y.2`` (a PATCH bump
per validated push). The arithmetic is commitizen's job, not this repo's.

These tests do not re-test commitizen's arithmetic -- that is the tool's job, and
re-encoding it here would resurrect the assumptions this setup removed. They
guard two other things:

* **Configuration coherence**, which breaks silently: a lost ``tag_format``, a
  dropped ``version_provider``, a drifted version pin.
* **The behaviour of the shell that remains.** The two load-bearing guards (tag
  idempotency and the empty-tag check) are tested by *extracting the step script
  from the YAML and running it* -- against a real git repository with a real bare
  remote, and against a stub ``uvx`` on ``PATH``. An earlier version of this file
  asserted those two by literal substring and a reviewer defeated both without
  any test failing: replacing the whole ``if``/``else`` with an unconditional
  ``git tag && git push`` still matched, because the substring lived elsewhere in
  the file. Substring assertions here are sensitive to formatting and blind to
  behaviour, which is exactly backwards. Do not convert these back.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
AUTO_TAG = WORKFLOWS / "auto-tag.yml"
NIGHTLY_TAG = WORKFLOWS / "nightly-tag.yml"

BOTH_WORKFLOWS = [
    pytest.param(AUTO_TAG, id="auto-tag"),
    pytest.param(NIGHTLY_TAG, id="nightly-tag"),
]

# The version commitizen is pinned to. Asserted to agree across the dev
# dependency group and both workflow invocations; see
# test_commitizen_pin_agrees_everywhere for why that matters.
COMMITIZEN_PIN = "4.17.0"


# --- parsing helpers ---------------------------------------------------------


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open("rb") as fh:
        loaded = yaml.safe_load(fh)
    assert isinstance(loaded, dict), f"{path.name} did not parse to a mapping"
    return loaded


def _commitizen_config() -> dict[str, Any]:
    tool = _pyproject().get("tool", {})
    assert "commitizen" in tool, "pyproject.toml is missing [tool.commitizen]"
    return tool["commitizen"]


def _pyproject() -> dict[str, Any]:
    with (REPO_ROOT / "pyproject.toml").open("rb") as fh:
        return tomllib.load(fh)


def _run_steps(path: Path) -> list[dict[str, Any]]:
    """Every step of every job in a workflow, as dicts."""
    workflow = _load_yaml(path)
    steps: list[dict[str, Any]] = []
    for job in workflow["jobs"].values():
        for step in job.get("steps", []):
            if isinstance(step, dict):
                steps.append(step)
    return steps


def _shell_body(path: Path) -> str:
    """Concatenated `run:` bodies of a workflow.

    Parsed out of the YAML rather than read as raw text, so that assertions
    about shell content cannot be satisfied (or defeated) by a comment
    elsewhere in the file.
    """
    return "\n".join(step["run"] for step in _run_steps(path) if "run" in step)


def _code_lines(path: Path) -> list[str]:
    """Shell lines of a workflow with comments and blanks removed.

    Comment stripping matters: every denial below would otherwise be trippable
    by a comment that merely *mentions* the forbidden construct, and this file
    is full of prose explaining what must not come back.
    """
    lines = []
    for raw in _shell_body(path).splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(raw)
    return lines


def _script(path: Path, step_name: str) -> str:
    """The `run:` script of the uniquely-named step."""
    matches = [s for s in _run_steps(path) if s.get("name") == step_name and "run" in s]
    assert len(matches) == 1, (
        f"{path.name} should have exactly one step named {step_name!r}, "
        f"found {len(matches)}"
    )
    return matches[0]["run"]


def _tag_step_name(path: Path) -> str:
    return "Create tag"


def _compute_step_name(path: Path) -> str:
    return "Compute release tag" if path == AUTO_TAG else "Compute nightly tag"


# --- commitizen configuration ------------------------------------------------


def test_commitizen_uses_v_prefixed_tag_format() -> None:
    """Tags must stay ``v``-prefixed.

    Commitizen defaults to a bare ``$version``. A regression here would create
    unprefixed tags that break continuity with every existing tag and with
    setuptools-scm's tag parsing.
    """
    assert _commitizen_config().get("tag_format") == "v$version"


def test_commitizen_reads_version_from_scm() -> None:
    """The version lives in git tags, not in a file.

    ``version_provider = "scm"`` is what lets commitizen compose with the
    setuptools-scm config: no version string to rewrite and no bump commit.
    """
    assert _commitizen_config().get("version_provider") == "scm"


def test_commitizen_pin_is_still_coherent() -> None:
    """commitizen is a local convenience now, not part of tagging.

    It used to compute the version in both workflows, which is why this test
    once asserted the pin agreed across three places. The policy moved to
    tools/next_version.py, so the workflows install nothing; only the dev-group
    pin remains, and it is asserted so `cz commit` keeps working locally.
    """
    dev = _pyproject()["dependency-groups"]["dev"]
    pins = [d for d in dev if d.split("==")[0].strip() == "commitizen"]
    assert pins == [f"commitizen=={COMMITIZEN_PIN}"], (
        f"dev group commitizen pin should be commitizen=={COMMITIZEN_PIN}, got {pins}"
    )

    for path in (AUTO_TAG, NIGHTLY_TAG):
        body = _shell_body(path)
        assert "cz bump" not in body, (
            f"{path.name} computes a version with commitizen again; the policy "
            "belongs in tools/next_version.py where it can be unit-tested"
        )


# --- the anti-hand-rolling invariant ----------------------------------------


@pytest.mark.parametrize(
    ("path", "channel"),
    [
        pytest.param(NIGHTLY_TAG, "nightly", id="nightly-dev-cuts-candidates"),
        pytest.param(AUTO_TAG, "stable", id="main-cuts-the-final"),
    ],
)
def test_the_policy_module_is_the_only_thing_that_produces_a_version(
    path: Path, channel: str
) -> None:
    """The user's hard constraint: do not hand-roll a versioning scheme.

    Stated as a POSITIVE invariant -- exactly one command computes the version,
    it is tools/next_version.py, and the tag actually used is read back from that
    command's output -- because the previous denylist-only form was defeatable. A
    reviewer reintroduced the exact rc-counter pipeline this change deleted
    (``git tag --list | sed -E ... | sort -n | tail -1`` feeding
    ``n=$(( last_n + 1 ))``) and every test still passed, because the denylist
    happened to enumerate ``$((major`` and friends but not ``sort -n``,
    ``sed -E`` or a bare ``$((``.

    The denials below are a second line of defence, not the primary one.
    """
    lines = _code_lines(path)

    calls = [ln for ln in lines if "next_version.py" in ln]
    assert len(calls) == 1, (
        f"{path.name} must call tools/next_version.py exactly once, found {len(calls)}"
    )
    assert f"--channel {channel}" in calls[0], (
        f"{path.name} must ask for the {channel!r} channel; got: {calls[0].strip()}"
    )

    # The tag that gets pushed must come from that call, not be assembled here.
    assignments = [ln for ln in lines if re.match(r"\s*new_tag=", ln)]
    assert assignments, f"{path.name} never assigns new_tag"
    for assignment in assignments:
        assert "next_version.py" in assignment, (
            f"{path.name} builds new_tag without asking the policy module, which "
            f"is hand-rolled versioning: {assignment.strip()}"
        )

    # Second line of defence: constructs that only appear when someone is
    # parsing, comparing or incrementing a version number in shell.
    forbidden = [
        "cut -d",  # splitting MAJOR.MINOR.PATCH
        "$((",  # any arithmetic expansion, not just $((patch
        "expr ",
        "sort -n",  # ranking an rc counter
        "sort -V",  # ranking version strings
        "sort -rV",
        "sort -v",
        "--sort=-v:refname",
        "sed -E",  # extracting a counter out of a tag name
        "git tag --list",  # enumerating tags to derive the next one
        "git tag -l",
        "git describe",
        "cz bump",  # the policy is no longer commitizen's to decide
    ]
    found = [snippet for snippet in forbidden if snippet in "\n".join(lines)]
    assert not found, f"{path.name} reintroduced hand-rolled version math: {found}"


# --- behavioural: tag creation is idempotent --------------------------------


def _init_repo_with_remote(tmp_path: Path) -> tuple[Path, Path]:
    """A real git repo with a real bare remote. No subprocess mocking.

    Asserting on a mocked ``subprocess`` would only re-check the command
    strings, which is what let the substring version of this test be defeated.
    A real remote means the push either happens or it does not.
    """
    git = shutil.which("git")
    assert git, "git is required for this test"
    remote = tmp_path / "remote.git"
    work = tmp_path / "work"
    subprocess.run([git, "init", "--bare", "-q", str(remote)], check=True)
    subprocess.run([git, "init", "-q", str(work)], check=True)
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    (work / "f.txt").write_text("x\n")
    subprocess.run([git, "add", "f.txt"], cwd=work, check=True, env=env)
    subprocess.run(
        [git, "commit", "-q", "-m", "c", "--no-gpg-sign"],
        cwd=work,
        check=True,
        env=env,
    )
    subprocess.run(
        [git, "remote", "add", "origin", str(remote)], cwd=work, check=True, env=env
    )
    return work, remote


def _run_script(
    script: str, cwd: Path, env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    bash = shutil.which("bash")
    assert bash, "bash is required for this test"
    return subprocess.run(
        [bash, "-c", script],
        cwd=cwd,
        env={**os.environ, **env},
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize("path", BOTH_WORKFLOWS)
def test_tag_creation_is_actually_idempotent(path: Path, tmp_path: Path) -> None:
    """Re-running the workflow must not fail on an already-existing tag.

    Behavioural, not textual: the real "Create tag" script runs twice against a
    real repo and a real bare remote. The substring form of this test survived
    the tag-existence ``if``/``else`` being replaced by an unconditional
    ``git tag && git push``, which is precisely the regression it is named for --
    the second run would then die on "tag already exists".
    """
    work, remote = _init_repo_with_remote(tmp_path)
    script = _script(path, _tag_step_name(path))
    env = {
        "NEW_TAG": "v9.9.9",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }

    first = _run_script(script, work, env)
    assert first.returncode == 0, f"first run failed:\n{first.stdout}\n{first.stderr}"
    remote_tags = subprocess.run(
        [str(shutil.which("git")), "tag", "--points-at", "HEAD"],
        cwd=work,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "v9.9.9" in remote_tags, "first run did not create the tag"
    pushed = subprocess.run(
        [str(shutil.which("git")), "ls-remote", "--tags", str(remote)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "refs/tags/v9.9.9" in pushed, "first run did not push the tag"

    second = _run_script(script, work, env)
    assert second.returncode == 0, (
        "re-running the tag step must not fail when the tag already exists, "
        f"but it exited {second.returncode}:\n{second.stdout}\n{second.stderr}"
    )


# --- behavioural: the empty-tag guard ---------------------------------------


def _git_env() -> dict[str, str]:
    return {
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }


def _git_cmd(*args: str, cwd: Path) -> str:
    return subprocess.run(
        [str(shutil.which("git")), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, **_git_env()},
    ).stdout


def _policy_repo(tmp_path: Path, subjects: list[str]) -> Path:
    """A repo released at v2.20.0, plus *subjects* committed on top.

    Carries a real copy of tools/next_version.py so the extracted workflow step
    runs the actual policy, not a stub. The stub this replaced could only prove
    the step parsed a fixed string; it could not have caught the policy itself
    being wrong, which is exactly what was wrong.
    """
    repo, _remote = _init_repo_with_remote(tmp_path)
    tools = repo / "tools"
    tools.mkdir(exist_ok=True)
    shutil.copy2(REPO_ROOT / "tools" / "next_version.py", tools / "next_version.py")
    _git_cmd("add", "-A", cwd=repo)
    _git_cmd("commit", "-qm", "chore: add the policy module", cwd=repo)
    _git_cmd("tag", "v2.20.0", cwd=repo)
    for subject in subjects:
        (repo / "f.txt").write_text(subject + "\n")
        _git_cmd("commit", "-qam", subject, cwd=repo)
    return repo


def _run_compute(path: Path, repo: Path, tmp_path: Path) -> tuple[str, object]:
    gh_output = tmp_path / "gh_output"
    gh_output.write_text("")
    result = _run_script(
        _script(path, _compute_step_name(path)),
        repo,
        {"GITHUB_OUTPUT": str(gh_output), **_git_env()},
    )
    return gh_output.read_text(), result


@pytest.mark.parametrize(
    ("path", "subjects", "expected"),
    [
        pytest.param(AUTO_TAG, ["fix: a", "docs: b"], "v2.20.1", id="main-fixes-patch"),
        pytest.param(
            AUTO_TAG, ["fix: a", "feat: b"], "v2.21.0", id="main-feature-minor"
        ),
        pytest.param(
            NIGHTLY_TAG, ["fix: a"], "v2.20.1rc1", id="nightly-fixes-patch-candidate"
        ),
        pytest.param(
            NIGHTLY_TAG, ["feat: a"], "v2.21.0rc1", id="nightly-feature-candidate"
        ),
    ],
)
def test_compute_step_emits_the_tag_the_policy_dictates(
    path: Path, subjects: list[str], expected: str, tmp_path: Path
) -> None:
    """End to end through the real step script and the real policy module.

    This is the test the old cz-stub version could not be: it asserts the *value*
    the workflow will tag, so a wrong policy fails here. The bug that prompted
    the rewrite -- every merge to main cutting a minor regardless of content --
    is caught by the ``main-fixes-patch`` case.
    """
    repo = _policy_repo(tmp_path, subjects)
    written, result = _run_compute(path, repo, tmp_path)
    assert result.returncode == 0, f"{result.stdout}\n{result.stderr}"
    assert f"new_tag={expected}" in written, (
        f"{path.name} would tag {written.strip()!r}, expected new_tag={expected}"
    )


@pytest.mark.parametrize("path", BOTH_WORKFLOWS)
def test_compute_step_emits_an_empty_tag_for_an_empty_batch(
    path: Path, tmp_path: Path
) -> None:
    """A re-run on an already-released commit has nothing to tag.

    It must succeed and emit an empty new_tag, so the create step can skip. The
    old shape failed the job here, which turned every workflow re-run red.
    """
    repo = _policy_repo(tmp_path, [])
    written, result = _run_compute(path, repo, tmp_path)
    assert result.returncode == 0, (
        f"an empty batch must not fail the job:\n{result.stdout}\n{result.stderr}"
    )
    assert "new_tag=\n" in written or written.strip() == "new_tag=", (
        f"expected an empty new_tag, got {written.strip()!r}"
    )


@pytest.mark.parametrize("path", BOTH_WORKFLOWS)
def test_create_tag_step_tags_nothing_when_the_tag_is_empty(
    path: Path, tmp_path: Path
) -> None:
    """The other half of the empty-batch path: never run `git tag ""`.

    Without this guard the create step tags the empty string, and the failure
    surfaces as something other than "there was nothing to release".
    """
    repo, _remote = _init_repo_with_remote(tmp_path)
    result = _run_script(
        _script(path, _tag_step_name(path)), repo, {"NEW_TAG": "", **_git_env()}
    )
    assert result.returncode == 0, f"{result.stdout}\n{result.stderr}"
    assert _git_cmd("tag", cwd=repo).strip() == "", "created a tag from an empty name"


# --- wiring that has no behaviour to execute --------------------------------


@pytest.mark.parametrize("path", BOTH_WORKFLOWS)
def test_workflow_checks_out_the_validated_commit_with_full_history(path: Path) -> None:
    """``workflow_run`` defaults to the default-branch tip, not the tested commit.

    ``fetch-depth: 0`` is equally load-bearing: commitizen resolves the current
    version from tags and a shallow clone has none.
    """
    checkouts = [
        s for s in _run_steps(path) if "actions/checkout" in str(s.get("uses"))
    ]
    assert len(checkouts) == 1, f"{path.name} should have exactly one checkout step"
    with_ = checkouts[0].get("with", {})
    assert with_.get("ref") == "${{ github.event.workflow_run.head_sha }}"
    assert with_.get("fetch-depth") == 0


def test_auto_tag_creates_a_github_release() -> None:
    """Tags pushed with GITHUB_TOKEN do not dispatch release.yml, so main's
    release has to be created here."""
    assert "gh release create" in _shell_body(AUTO_TAG)


def test_nightly_tag_creates_no_github_release() -> None:
    """Nightlies are addressable tags only; releases are cut on main."""
    body = _shell_body(NIGHTLY_TAG)
    assert "gh release create" not in body
    assert "softprops/action-gh-release" not in str(_run_steps(NIGHTLY_TAG))


def test_auto_tag_does_not_skip_chore_only_merges() -> None:
    """A merge into main is an explicit release event.

    The old workflow exited early when it found no feat/fix/perf commits. Both
    halves of that mechanism are checked: no step may be gated on a `skip`
    output, and no shell may emit one -- a reintroduced in-shell
    ``echo skip=true >> "$GITHUB_OUTPUT"; exit 0`` would otherwise pass.
    """
    for step in _run_steps(AUTO_TAG):
        condition = str(step.get("if", ""))
        assert "skip" not in condition, f"unexpected skip gate on step {step!r}"
    for line in _code_lines(AUTO_TAG):
        assert "skip=" not in line, f"auto-tag emits a skip output: {line.strip()}"


@pytest.mark.parametrize(
    ("path", "group"),
    [
        pytest.param(AUTO_TAG, "auto-tag", id="auto-tag"),
        pytest.param(NIGHTLY_TAG, "nightly-tag", id="nightly-tag"),
    ],
)
def test_workflow_serializes_instead_of_cancelling(path: Path, group: str) -> None:
    """Back-to-back merges must queue, not cancel, or one goes untagged."""
    concurrency = _load_yaml(path)["concurrency"]
    assert concurrency["group"] == group
    assert concurrency["cancel-in-progress"] is False
