"""The promotion-source check: main accepts PRs only from this repo's nightly-dev.

The step script is extracted from the workflow and executed, so these tests
exercise the shell that actually runs in CI rather than matching its text.
"""

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

WORKFLOW = (
    Path(__file__).resolve().parent.parent
    / ".github"
    / "workflows"
    / "promotion-source.yml"
)
REPO = "trustedsec/hate_crack"


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def _triggers() -> dict:
    # PyYAML parses a bare `on:` key as boolean True.
    return _workflow()[True]


def _step() -> dict:
    (step,) = _workflow()["jobs"]["promotion-source"]["steps"]
    return step


def _run(head_repo: str, head_ref: str) -> subprocess.CompletedProcess:
    bash = shutil.which("bash")
    assert bash is not None
    env = {"HEAD_REF": head_ref, "HEAD_REPO": head_repo, "BASE_REPO": REPO}
    return subprocess.run(  # noqa: S603 - fixed argv, script from a tracked file
        [bash, "-c", _step()["run"]],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_accepts_this_repos_nightly_dev() -> None:
    assert _run(REPO, "nightly-dev").returncode == 0


@pytest.mark.parametrize(
    ("head_repo", "head_ref"),
    [
        (REPO, "feature/thing"),
        (REPO, "main"),
        (REPO, "nightly-dev-old"),
        ("someone/hate_crack", "nightly-dev"),
        ("someone/hate_crack", "feature/thing"),
    ],
)
def test_rejects_any_other_head(head_repo: str, head_ref: str) -> None:
    result = _run(head_repo, head_ref)
    assert result.returncode == 1
    assert "::error::" in result.stdout


def test_head_ref_is_not_interpolated_into_the_script() -> None:
    """head_ref is attacker-chosen; it must arrive through env only."""
    assert "${{" not in _step()["run"]
    assert _step()["env"]["HEAD_REF"] == "${{ github.head_ref }}"


def test_runs_on_retarget_and_only_for_main() -> None:
    pr = _triggers()["pull_request"]
    assert pr["branches"] == ["main"]
    # `edited` is what fires when a PR is retargeted onto main; without it a
    # green result from the old base would satisfy the required check.
    assert set(pr["types"]) == {"opened", "synchronize", "reopened", "edited"}
    assert set(_triggers()) == {"pull_request"}


def test_check_name_is_stable() -> None:
    """The ruleset requires this context by name; renaming it silently
    leaves main requiring a check that never reports."""
    assert _workflow()["jobs"]["promotion-source"]["name"] == "Promotion source"
