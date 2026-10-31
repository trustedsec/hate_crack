"""Structural invariants of .github/workflows/dependabot-batch.yml.

This workflow pushes a branch and edits an issue, so the properties that keep it
from being triggerable or steerable by outsiders are pinned here. A change that
breaks one should fail loudly, not be noticed after the fact.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from tools import dependabot_batch as db

WORKFLOW = (
    Path(__file__).resolve().parent.parent
    / ".github"
    / "workflows"
    / "dependabot-batch.yml"
)


def _wf() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def _runs(job: str) -> list[str]:
    return [s.get("run", "") for s in _wf()["jobs"][job]["steps"]]


def test_triggers_are_exactly_schedule_and_dispatch():
    # PyYAML parses a bare `on:` key as boolean True.
    triggers = _wf()[True]
    assert set(triggers) == {"schedule", "workflow_dispatch"}
    assert triggers["schedule"] == [{"cron": "0 10 * * 2"}]
    assert not triggers["workflow_dispatch"]  # no inputs to inject through


def test_top_level_permissions_are_empty():
    assert _wf()["permissions"] == {}


def test_combine_never_gets_a_write_permission():
    perms = _wf()["jobs"]["combine"]["permissions"]
    assert perms == {"contents": "read", "pull-requests": "read"}


def test_publish_permissions_are_exactly_what_it_needs():
    perms = _wf()["jobs"]["publish"]["permissions"]
    assert perms == {"contents": "write", "issues": "write", "pull-requests": "read"}


def test_publish_never_installs_or_runs_the_project():
    job = _wf()["jobs"]["publish"]
    uses = [s.get("uses", "") for s in job["steps"]]
    assert not any("setup-uv" in u or "setup-python" in u for u in uses)
    for run in _runs("publish"):
        for word in ("uv ", "uvx", "pytest", "pip ", "make "):
            assert word not in run, (word, run)


def test_the_step_that_runs_bumped_code_holds_no_token():
    (step,) = [
        s for s in _wf()["jobs"]["combine"]["steps"] if " combine " in s.get("run", "")
    ]
    assert "GH_TOKEN" not in (step.get("env") or {})
    assert "GITHUB_TOKEN" not in (step.get("env") or {})
    assert "secrets." not in str(step) and "github.token" not in str(step)


def test_push_target_is_the_hardcoded_batch_branch():
    pushes = [r for r in _runs("publish") if "git push" in r]
    assert pushes
    for run in pushes:
        assert f"refs/heads/{db.BATCH_BRANCH}" in run
        assert "${{" not in run  # nothing interpolated into the script


def test_no_expression_is_interpolated_into_any_run_script():
    for job in ("combine", "publish"):
        for run in _runs(job):
            assert "${{" not in run, run


def test_both_jobs_check_out_nightly_dev():
    for job in ("combine", "publish"):
        (checkout,) = [
            s
            for s in _wf()["jobs"][job]["steps"]
            if "actions/checkout" in s.get("uses", "")
        ]
        assert checkout["with"]["ref"] == "nightly-dev"


def test_combine_does_not_use_a_shared_cache():
    (uv,) = [
        s for s in _wf()["jobs"]["combine"]["steps"] if "setup-uv" in s.get("uses", "")
    ]
    assert uv["with"]["enable-cache"] is False


def test_scripts_run_with_isolated_system_python():
    for job in ("combine", "publish"):
        for run in _runs(job):
            if "dependabot_batch.py" in run:
                assert "python3 -I tools/dependabot_batch.py" in run
