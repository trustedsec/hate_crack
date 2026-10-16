"""Repo-wide invariants over .github/workflows/.

Each of these is a property that GitHub settings (Task 6 of the 2026-10-15
hardening) or zizmor rely on, and each fails silently when broken.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"
FILES = sorted(WORKFLOWS.glob("*.yml"))
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")


def _steps(path: Path):
    for job in yaml.safe_load(path.read_text())["jobs"].values():
        for step in job.get("steps", []):
            if isinstance(step, dict):
                yield step


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_every_action_is_pinned_to_a_full_sha(path: Path) -> None:
    """Repo setting sha_pinning_required rejects the whole run otherwise."""
    for step in _steps(path):
        uses = step.get("uses")
        if uses and not uses.startswith("./"):
            assert PINNED.match(uses), f"{path.name}: {uses} is not SHA-pinned"


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_every_workflow_declares_top_level_permissions(path: Path) -> None:
    """The repo default is being lowered to read; a workflow that silently
    relied on the old write default must say so explicitly instead."""
    assert "permissions" in yaml.safe_load(path.read_text()), path.name


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_checkouts_do_not_persist_credentials_except_the_tag_job(path: Path) -> None:
    wf = yaml.safe_load(path.read_text())
    for name, job in wf["jobs"].items():
        for step in job.get("steps", []):
            if "actions/checkout" not in str(step.get("uses", "")):
                continue
            want = path.name == "ci.yml" and name == "tag"
            got = step.get("with", {}).get("persist-credentials")
            assert got is want, f"{path.name}:{name} persist-credentials={got!r}"


def test_workflow_lint_job_covers_the_whole_directory() -> None:
    job = yaml.safe_load((WORKFLOWS / "ci.yml").read_text())["jobs"]["workflow-lint"]
    assert job["name"] == "Workflow lint"
    runs = "\n".join(s.get("run", "") for s in job["steps"])
    assert "zizmor" in runs and ".github/workflows" in runs
    assert "actionlint" in runs
