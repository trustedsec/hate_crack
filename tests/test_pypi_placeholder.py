"""Guards on the PyPI name placeholder in packaging/pypi-placeholder.

The placeholder only does its job if it stays inert: version 0.0.0, no console
script, no dependencies, and a publish workflow that cannot be triggered by the
tag automation. Those are all one-line edits away from being wrong, and the
failure mode is a broken package on a public index under this project's name, so
they are asserted here rather than left to review.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tarfile
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PLACEHOLDER_DIR = REPO_ROOT / "packaging" / "pypi-placeholder"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "pypi-placeholder.yml"


@pytest.fixture(scope="module")
def placeholder_pyproject() -> dict:
    with (PLACEHOLDER_DIR / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)


@pytest.fixture(scope="module")
def backend_module():
    spec = importlib.util.spec_from_file_location(
        "_placeholder_backend_under_test",
        PLACEHOLDER_DIR / "placeholder_backend.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_placeholder_files_exist() -> None:
    for name in (
        "pyproject.toml",
        "placeholder_backend.py",
        "README.md",
        "MANIFEST.in",
    ):
        assert (PLACEHOLDER_DIR / name).is_file(), f"missing {name}"


def test_version_is_zero_and_project_is_marked_inactive(
    placeholder_pyproject: dict,
) -> None:
    project = placeholder_pyproject["project"]
    assert project["version"] == "0.0.0"
    assert "Development Status :: 7 - Inactive" in project["classifiers"]


def test_no_console_script_no_dependencies_no_packages(
    placeholder_pyproject: dict,
) -> None:
    project = placeholder_pyproject["project"]
    assert "scripts" not in project, (
        "a placeholder must not install a hate_crack command"
    )
    assert "gui-scripts" not in project
    assert project["dependencies"] == []
    assert placeholder_pyproject["tool"]["setuptools"]["packages"] == []


def test_description_and_readme_announce_the_placeholder(
    placeholder_pyproject: dict,
) -> None:
    assert "placeholder" in placeholder_pyproject["project"]["description"].lower()
    readme = (PLACEHOLDER_DIR / "README.md").read_text(encoding="utf-8")
    first_line = readme.splitlines()[0].lower()
    assert "placeholder" in first_line, "PyPI page must say so on the first line"
    assert "github.com/trustedsec/hate_crack" in readme


def test_placeholder_pyproject_is_not_the_real_project(
    placeholder_pyproject: dict,
) -> None:
    # Same distribution name, so a stray copy of the real metadata here would
    # publish the tool. Catch the tell-tale markers.
    project = placeholder_pyproject["project"]
    assert project["name"].replace("-", "_") == "hate_crack"
    assert "dynamic" not in project, "no setuptools-scm versioning for the placeholder"


@pytest.mark.parametrize(
    "hook",
    [
        "build_wheel",
        "prepare_metadata_for_build_wheel",
        "build_editable",
        "prepare_metadata_for_build_editable",
    ],
)
def test_wheel_hooks_refuse_with_install_instructions(
    backend_module, hook: str
) -> None:
    with pytest.raises(RuntimeError) as excinfo:
        getattr(backend_module, hook)("out")
    message = str(excinfo.value)
    assert "not installable from PyPI" in message
    assert "github.com/trustedsec/hate_crack" in message


def test_sdist_hooks_are_delegated_not_stubbed(backend_module, monkeypatch) -> None:
    # The sdist must still build; that is the artifact that gets uploaded. The
    # test venv has no setuptools, so stand in a fake and assert it is reached.
    calls: list[tuple[str, tuple]] = []

    class FakeBuildMeta:
        @staticmethod
        def build_sdist(*args):
            calls.append(("build_sdist", args))
            return "hate_crack-0.0.0.tar.gz"

        @staticmethod
        def get_requires_for_build_sdist(*args):
            calls.append(("get_requires_for_build_sdist", args))
            return []

    monkeypatch.setattr(backend_module, "_setuptools", lambda: FakeBuildMeta)

    assert backend_module.build_sdist("dist") == "hate_crack-0.0.0.tar.gz"
    assert backend_module.get_requires_for_build_sdist() == []
    assert [name for name, _ in calls] == [
        "build_sdist",
        "get_requires_for_build_sdist",
    ]


def test_workflow_is_manual_only_and_uses_trusted_publishing() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    trigger_block = text.split("permissions:", 1)[0]
    assert "workflow_dispatch:" in trigger_block
    for forbidden in (
        "push:",
        "pull_request:",
        "workflow_run:",
        "schedule:",
        "release:",
    ):
        assert forbidden not in trigger_block, (
            f"placeholder publish must not trigger on {forbidden}"
        )
    assert "id-token: write" in text
    assert "pypa/gh-action-pypi-publish@" in text
    assert "PYPI_API_TOKEN" not in text and "password:" not in text, (
        "Trusted Publishing only"
    )


def test_release_automation_does_not_reach_the_placeholder() -> None:
    workflows = REPO_ROOT / ".github" / "workflows"
    for path in sorted(workflows.glob("*.yml")):
        if path == WORKFLOW:
            continue
        text = path.read_text(encoding="utf-8")
        assert "pypi-placeholder" not in text, (
            f"{path.name} references the placeholder workflow"
        )
        assert "pypi-publish" not in text, f"{path.name} publishes to PyPI"


def test_placeholder_is_excluded_from_the_real_package_build() -> None:
    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        root = tomllib.load(handle)
    include = root["tool"]["setuptools"]["packages"]["find"]["include"]
    assert include == ["hate_crack*"], (
        "placeholder must not be picked up by the real build"
    )


@pytest.mark.skipif(
    os.environ.get("HATE_CRACK_RUN_PLACEHOLDER_BUILD") != "1",
    reason="set HATE_CRACK_RUN_PLACEHOLDER_BUILD=1 (needs network for build isolation)",
)
def test_sdist_builds_and_passes_the_publish_gate(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    subprocess.run(  # noqa: S603
        [sys.executable, "-m", "build", "--sdist", "--outdir", str(dist), "."],
        cwd=PLACEHOLDER_DIR,
        check=True,
    )
    sdists = list(dist.glob("*.tar.gz"))
    assert len(sdists) == 1
    with tarfile.open(sdists[0]) as tar:
        names = tar.getnames()
    assert not [n for n in names if n.endswith("entry_points.txt")]
    subprocess.run(  # noqa: S603
        [sys.executable, str(PLACEHOLDER_DIR / "verify_placeholder.py"), str(dist)],
        check=True,
    )
