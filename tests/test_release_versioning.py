"""Guards on the release-versioning wiring.

The scheme is: ``main`` is stable at ``X.Y.0`` (a MINOR bump per merge) and
``nightly-dev`` rolls through patch numbers ``X.Y.1``, ``X.Y.2`` (a PATCH bump
per validated push). The arithmetic is commitizen's job, not this repo's.

These tests deliberately assert the *configuration and wiring*, not the version
numbers commitizen produces. Re-testing commitizen's arithmetic here would just
re-encode the hand-rolled assumptions this setup exists to remove. What can break
silently is the glue: a lost ``tag_format``, a dropped ``--increment``, or the old
bash version math creeping back in.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
AUTO_TAG = WORKFLOWS / "auto-tag.yml"
NIGHTLY_TAG = WORKFLOWS / "nightly-tag.yml"


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open("rb") as fh:
        loaded = yaml.safe_load(fh)
    assert isinstance(loaded, dict), f"{path.name} did not parse to a mapping"
    return loaded


def _commitizen_config() -> dict[str, Any]:
    with (REPO_ROOT / "pyproject.toml").open("rb") as fh:
        data = tomllib.load(fh)
    tool = data.get("tool", {})
    assert "commitizen" in tool, "pyproject.toml is missing [tool.commitizen]"
    return tool["commitizen"]


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


def test_commitizen_is_pinned_in_dev_dependencies() -> None:
    with (REPO_ROOT / "pyproject.toml").open("rb") as fh:
        data = tomllib.load(fh)
    dev = data["dependency-groups"]["dev"]
    pins = [d for d in dev if d.split("==")[0].strip() == "commitizen"]
    assert pins, "commitizen missing from the dev dependency group"
    assert "==" in pins[0], f"commitizen must be pinned exactly, got {pins[0]!r}"


# --- workflow wiring ---------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "increment"),
    [
        pytest.param(NIGHTLY_TAG, "PATCH", id="nightly-dev-consumes-patch"),
        pytest.param(AUTO_TAG, "MINOR", id="main-cuts-minor"),
    ],
)
def test_workflow_forces_the_right_increment(path: Path, increment: str) -> None:
    """The branch decides the bump, and it must be forced explicitly.

    Without ``--increment`` commitizen would infer the bump from commit
    messages, which is the behaviour this scheme replaces.
    """
    body = _shell_body(path)
    assert "cz bump" in body, f"{path.name} does not invoke `cz bump`"
    assert f"--increment {increment}" in body, (
        f"{path.name} must force `--increment {increment}`"
    )
    other = "MINOR" if increment == "PATCH" else "PATCH"
    assert f"--increment {other}" not in body, (
        f"{path.name} must not also use `--increment {other}`"
    )


@pytest.mark.parametrize(
    "path",
    [
        pytest.param(AUTO_TAG, id="auto-tag"),
        pytest.param(NIGHTLY_TAG, id="nightly-tag"),
    ],
)
def test_workflow_has_no_hand_rolled_version_math(path: Path) -> None:
    """The bash version arithmetic must not creep back.

    These are the exact shapes the old workflows used: splitting a version with
    ``cut -d.`` and incrementing with arithmetic expansion.
    """
    body = _shell_body(path)
    forbidden = [
        "cut -d. -f",
        "$((major",
        "$((minor",
        "$((patch",
        "$(( major",
        "$(( minor",
        "$(( patch",
    ]
    found = [snippet for snippet in forbidden if snippet in body]
    assert not found, f"{path.name} reintroduced hand-rolled version math: {found}"


@pytest.mark.parametrize(
    "path",
    [
        pytest.param(AUTO_TAG, id="auto-tag"),
        pytest.param(NIGHTLY_TAG, id="nightly-tag"),
    ],
)
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

    The old workflow exited early when there were no feat/fix/perf commits; that
    early exit is gone, so no step may be gated on a `skip` output.
    """
    for step in _run_steps(AUTO_TAG):
        condition = str(step.get("if", ""))
        assert "skip" not in condition, f"unexpected skip gate on step {step!r}"


@pytest.mark.parametrize(
    "path",
    [
        pytest.param(AUTO_TAG, id="auto-tag"),
        pytest.param(NIGHTLY_TAG, id="nightly-tag"),
    ],
)
def test_workflow_tag_push_is_idempotent(path: Path) -> None:
    """A re-run must not fail the job on an already-existing tag."""
    assert "git rev-parse -q --verify" in _shell_body(path)


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
