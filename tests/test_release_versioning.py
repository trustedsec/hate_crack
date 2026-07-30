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


def test_commitizen_pin_agrees_everywhere() -> None:
    """The pin appears in three places and they must not drift.

    The workflows install commitizen with ``uvx --from`` and never run
    ``uv sync --dev``, so the dev-group pin does not constrain CI at all.
    Bumping only the dev group would change what a developer runs locally while
    CI silently kept tagging with the old version -- and nothing would fail.
    """
    dev = _pyproject()["dependency-groups"]["dev"]
    pins = [d for d in dev if d.split("==")[0].strip() == "commitizen"]
    assert pins == [f"commitizen=={COMMITIZEN_PIN}"], (
        f"dev group commitizen pin should be commitizen=={COMMITIZEN_PIN}, got {pins}"
    )

    for path in (AUTO_TAG, NIGHTLY_TAG):
        found = re.findall(r"--from\s+'commitizen==([0-9][^']*)'", _shell_body(path))
        assert found, f"{path.name} does not install a pinned commitizen"
        assert set(found) == {COMMITIZEN_PIN}, (
            f"{path.name} pins commitizen{found}, expected {COMMITIZEN_PIN} "
            "to match the dev dependency group"
        )


# --- the anti-hand-rolling invariant ----------------------------------------


@pytest.mark.parametrize(
    ("path", "increment"),
    [
        pytest.param(NIGHTLY_TAG, "PATCH", id="nightly-dev-consumes-patch"),
        pytest.param(AUTO_TAG, "MINOR", id="main-cuts-minor"),
    ],
)
def test_cz_bump_is_the_only_thing_that_produces_a_version(
    path: Path, increment: str
) -> None:
    """The user's hard constraint: do not hand-roll a versioning scheme.

    This is stated as a POSITIVE invariant -- exactly one command computes the
    version, it is ``cz bump``, and the tag actually used is read back from that
    command's output -- because the previous denylist-only form was defeatable.
    A reviewer reintroduced the exact rc-counter pipeline this change deleted
    (``git tag --list | sed -E ... | sort -n | tail -1`` feeding
    ``n=$(( last_n + 1 ))``) and every test still passed, because the denylist
    happened to enumerate ``$((major`` and friends but not ``sort -n``,
    ``sed -E`` or a bare ``$((``.

    The denials below are a second line of defence, not the primary one.
    """
    lines = _code_lines(path)

    bump_lines = [ln for ln in lines if "cz bump" in ln]
    assert len(bump_lines) == 1, (
        f"{path.name} must invoke `cz bump` exactly once, found {len(bump_lines)}"
    )
    bump = bump_lines[0]
    assert f"--increment {increment}" in bump, (
        f"{path.name} must force `--increment {increment}`; got: {bump.strip()}"
    )
    assert "--dry-run" in bump, (
        f"{path.name} must use --dry-run; the tag is pushed explicitly afterwards"
    )
    other = "MINOR" if increment == "PATCH" else "PATCH"
    assert other not in _shell_body(path), f"{path.name} must not reference `{other}`"

    # The tag that gets pushed must come from cz's own output, not be assembled
    # locally. Any assignment to new_tag has to read the cz log.
    assignments = [ln for ln in lines if re.match(r"\s*new_tag=", ln)]
    assert assignments, f"{path.name} never assigns new_tag"
    for assignment in assignments:
        assert "cz-bump.log" in assignment, (
            f"{path.name} builds new_tag without reading cz's output, which is "
            f"hand-rolled versioning: {assignment.strip()}"
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


def _uvx_stub(tmp_path: Path, output: str, exit_code: int = 0) -> Path:
    """A directory to prepend to PATH containing a fake `uvx`.

    Lets the compute step run without network access or a real commitizen, so
    the guard around cz's *output* can be exercised directly.
    """
    bindir = tmp_path / "stubbin"
    bindir.mkdir()
    stub = bindir / "uvx"
    stub.write_text(f"#!/bin/sh\ncat <<'CZEOF'\n{output}\nCZEOF\nexit {exit_code}\n")
    stub.chmod(0o755)
    return bindir


@pytest.mark.parametrize("path", BOTH_WORKFLOWS)
def test_compute_step_extracts_the_tag_cz_reports(path: Path, tmp_path: Path) -> None:
    """The happy path: the pushed tag is whatever cz said, verbatim.

    Also exercises the deliberately pipeline-free extraction. Piping cz into
    ``sed`` directly would risk the producer dying on SIGPIPE (141) under
    ``set -o pipefail`` and failing the step on a *successful* match.
    """
    output = (
        "bump: version 4.5.6 -> 4.5.7\ntag to create: v4.5.7\nincrement detected: PATCH"
    )
    bindir = _uvx_stub(tmp_path, output)
    gh_output = tmp_path / "gh_output"
    gh_output.write_text("")
    result = _run_script(
        _script(path, _compute_step_name(path)),
        tmp_path,
        {
            "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
            "RUNNER_TEMP": str(tmp_path),
            "GITHUB_OUTPUT": str(gh_output),
        },
    )
    assert result.returncode == 0, f"{result.stdout}\n{result.stderr}"
    assert "new_tag=v4.5.7" in gh_output.read_text()


@pytest.mark.parametrize("path", BOTH_WORKFLOWS)
def test_compute_step_fails_when_cz_reports_no_tag(path: Path, tmp_path: Path) -> None:
    """An unparseable cz output must fail the job, not push an empty tag.

    Nothing asserted this guard existed before. Without it a change to
    commitizen's output wording -- a rename of the "tag to create:" line -- makes
    the next step run ``git tag ""``, and the failure would be reported as
    something other than "we could not read the version".
    """
    bindir = _uvx_stub(tmp_path, "bump: nothing to do, and no tag line at all")
    gh_output = tmp_path / "gh_output"
    gh_output.write_text("")
    result = _run_script(
        _script(path, _compute_step_name(path)),
        tmp_path,
        {
            "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
            "RUNNER_TEMP": str(tmp_path),
            "GITHUB_OUTPUT": str(gh_output),
        },
    )
    assert result.returncode != 0, (
        "the compute step must fail when cz reports no tag, otherwise the next "
        f"step tags the empty string. stdout:\n{result.stdout}"
    )
    assert "new_tag=" not in gh_output.read_text(), (
        "no new_tag may be emitted when the tag could not be determined"
    )


@pytest.mark.parametrize("path", BOTH_WORKFLOWS)
def test_compute_step_writes_to_runner_temp(path: Path) -> None:
    """Use the runner's scratch dir, not a fixed path in /tmp."""
    body = _shell_body(path)
    assert "$RUNNER_TEMP" in body or "${RUNNER_TEMP}" in body
    assert "/tmp/cz-bump" not in body


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
