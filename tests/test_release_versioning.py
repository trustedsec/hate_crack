"""Guards on the release-versioning wiring.

The scheme is ordinary semver with the bump derived from the batch: any ``feat``
since the last release targets ``X.(Y+1).0``, a batch of only fixes, docs and
chores targets ``X.Y.(Z+1)``. ``nightly-dev`` tags release candidates for that
target (``v2.20.1rc1``, ``v2.20.1rc2``, ...) and merging down to ``main``
promotes the same target to its final release. The policy itself lives in
tools/next_version.py and is unit-tested in tests/test_next_version.py; nothing
here re-implements it.

An earlier scheme forced the increment per branch -- MINOR on every merge to
``main``, PATCH on every nightly push -- with commitizen doing the arithmetic.
It was removed on 2026-07-31 for cutting a minor release per bugfix merge. Do
not restore it, and do not read a claim that ``main`` is always ``X.Y.0``
anywhere as current.

What this file guards, given the policy is tested elsewhere:

* **Configuration coherence**, which breaks silently: a lost ``tag_format``, a
  dropped ``version_provider``, a drifted commitizen pin.
* **That the policy module remains the only thing producing a version**, stated
  as a positive invariant (exactly one ``next_version.py`` call, and the pushed
  tag read back from its output) with a denylist of shell version-math as a
  second line of defence. The denylist alone was defeatable -- see
  ``test_the_policy_module_is_the_only_thing_that_produces_a_version``.
* **The behaviour of the shell that remains.** The load-bearing guards (the
  computed tag's value, tag idempotency, and the empty-batch path) are tested by
  *extracting the step script from the YAML and running it* against a real git
  repository, a real bare remote, and a real copy of the policy module. An
  earlier version of this file asserted those by literal substring and a
  reviewer defeated them without any test failing: replacing the whole
  ``if``/``else`` with an unconditional ``git tag && git push`` still matched,
  because the substring lived elsewhere in the file. Substring assertions here
  are sensitive to formatting and blind to behaviour, which is exactly
  backwards. Do not convert these back.
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
CI = WORKFLOWS / "ci.yml"
TAG_JOB = "tag"
CHANNELS = [
    pytest.param("refs/heads/main", id="main"),
    pytest.param("refs/heads/nightly-dev", id="nightly-dev"),
]

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


def _tag_job() -> dict[str, Any]:
    return _load_yaml(CI)["jobs"][TAG_JOB]


def _run_steps(path: Path = CI) -> list[dict[str, Any]]:
    """Every step of the ci.yml `tag` job, as dicts."""
    return [s for s in _tag_job().get("steps", []) if isinstance(s, dict)]


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
    return "Compute tag"


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

    What is asserted is that the pin exists and is exact -- deliberately not
    which version it names. An earlier revision compared against a literal, so
    every Dependabot bump of commitizen failed here and needed a matching edit
    to this file before it could land (#322). Neither thing this test documents
    depends on the version number, so pinning it bought nothing and cost a red
    CI run per bump.
    """
    dev = _pyproject()["dependency-groups"]["dev"]
    pins = [d for d in dev if d.split("==")[0].strip() == "commitizen"]
    assert len(pins) == 1, f"expected exactly one commitizen pin, got {pins}"
    assert re.fullmatch(r"commitizen==\d+\.\d+\.\d+", pins[0].strip()), (
        f"dev group commitizen must be pinned exactly (commitizen==X.Y.Z), got {pins[0]!r}"
    )

    assert "cz bump" not in _shell_body(CI), (
        f"{CI.name} computes a version with commitizen again; the policy "
        "belongs in tools/next_version.py where it can be unit-tested"
    )


# --- the anti-hand-rolling invariant ----------------------------------------


def test_the_policy_module_is_the_only_thing_that_produces_a_version() -> None:
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
    path = CI
    lines = _code_lines(path)

    calls = [ln for ln in lines if "next_version.py" in ln]
    assert len(calls) == 1, (
        f"{path.name} must call tools/next_version.py exactly once, found {len(calls)}"
    )
    assert '--channel "$channel"' in calls[0], (
        f"{path.name} must pass the branch's channel; got: {calls[0].strip()}"
    )
    body = "\n".join(lines)
    assert "channel=stable" in body
    assert "channel=nightly" in body

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


def test_tag_creation_is_actually_idempotent(tmp_path: Path) -> None:
    """Re-running the workflow must not fail on an already-existing tag.

    Behavioural, not textual: the real "Create tag" script runs twice against a
    real repo and a real bare remote. The substring form of this test survived
    the tag-existence ``if``/``else`` being replaced by an unconditional
    ``git tag && git push``, which is precisely the regression it is named for --
    the second run would then die on "tag already exists".
    """
    work, remote = _init_repo_with_remote(tmp_path)
    script = _script(CI, _tag_step_name(CI))
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
    # tools/next_version.py draws the baseline from tags merged into
    # origin/main and fails loudly without that ref.
    _git_cmd("update-ref", "refs/remotes/origin/main", "HEAD", cwd=repo)
    for subject in subjects:
        (repo / "f.txt").write_text(subject + "\n")
        _git_cmd("commit", "-qam", subject, cwd=repo)
    return repo


def _run_compute(ref: str, repo: Path, tmp_path: Path) -> tuple[str, Any]:
    gh_output = tmp_path / "gh_output"
    gh_output.write_text("")
    result = _run_script(
        _script(CI, _compute_step_name(CI)),
        repo,
        {"GITHUB_REF": ref, "GITHUB_OUTPUT": str(gh_output), **_git_env()},
    )
    return gh_output.read_text(), result


@pytest.mark.parametrize(
    ("ref", "subjects", "expected"),
    [
        pytest.param(
            "refs/heads/main", ["fix: a", "docs: b"], "v2.20.1", id="main-fixes-patch"
        ),
        pytest.param(
            "refs/heads/main", ["fix: a", "feat: b"], "v2.21.0", id="main-feature-minor"
        ),
        pytest.param(
            "refs/heads/nightly-dev",
            ["fix: a"],
            "v2.20.1rc1",
            id="nightly-fixes-patch-candidate",
        ),
        pytest.param(
            "refs/heads/nightly-dev",
            ["feat: a"],
            "v2.21.0rc1",
            id="nightly-feature-candidate",
        ),
    ],
)
def test_compute_step_emits_the_tag_the_policy_dictates(
    ref: str, subjects: list[str], expected: str, tmp_path: Path
) -> None:
    """End to end through the real step script and the real policy module.

    This is the test the old cz-stub version could not be: it asserts the *value*
    the workflow will tag, so a wrong policy fails here. The bug that prompted
    the rewrite -- every merge to main cutting a minor regardless of content --
    is caught by the ``main-fixes-patch`` case.
    """
    repo = _policy_repo(tmp_path, subjects)
    written, result = _run_compute(ref, repo, tmp_path)
    assert result.returncode == 0, f"{result.stdout}\n{result.stderr}"
    assert f"new_tag={expected}" in written, (
        f"{ref} would tag {written.strip()!r}, expected new_tag={expected}"
    )
    # The Create GitHub release step is gated on this output: only main may
    # publish a release.
    channel = "stable" if ref == "refs/heads/main" else "nightly"
    assert f"channel={channel}\n" in written, (
        f"{ref} must write channel={channel}, got {written!r}"
    )


@pytest.mark.parametrize("ref", CHANNELS)
def test_compute_step_emits_an_empty_tag_for_an_empty_batch(
    ref: str, tmp_path: Path
) -> None:
    """A re-run on an already-released commit has nothing to tag.

    It must succeed and emit an empty new_tag, so the create step can skip. The
    old shape failed the job here, which turned every workflow re-run red.
    """
    repo = _policy_repo(tmp_path, [])
    written, result = _run_compute(ref, repo, tmp_path)
    assert result.returncode == 0, (
        f"an empty batch must not fail the job:\n{result.stdout}\n{result.stderr}"
    )
    assert "new_tag=\n" in written or written.strip() == "new_tag=", (
        f"expected an empty new_tag, got {written.strip()!r}"
    )


def test_create_tag_step_tags_nothing_when_the_tag_is_empty(tmp_path: Path) -> None:
    """The other half of the empty-batch path: never run `git tag ""`.

    Without this guard the create step tags the empty string, and the failure
    surfaces as something other than "there was nothing to release".
    """
    repo, _remote = _init_repo_with_remote(tmp_path)
    result = _run_script(
        _script(CI, _tag_step_name(CI)),
        repo,
        {"NEW_TAG": "", **_git_env()},
    )
    assert result.returncode == 0, f"{result.stdout}\n{result.stderr}"
    assert _git_cmd("tag", cwd=repo).strip() == "", "created a tag from an empty name"


# --- wiring that has no behaviour to execute --------------------------------


# --- the tag job's wiring ----------------------------------------------------

VALIDATING_JOBS = {"checks", "bandit", "pip-audit"}


def test_no_workflow_uses_workflow_run() -> None:
    """workflow_run is zizmor's error-level dangerous trigger. The tag job is a
    `needs` dependent instead; do not reintroduce a workflow_run tagger."""
    for path in sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")]):
        workflow = _load_yaml(path)
        on = workflow.get(True) or workflow.get("on")
        assert "workflow_run" not in (on or {}), f"{path.name} uses workflow_run"


def test_the_old_tag_workflows_are_gone() -> None:
    assert not (WORKFLOWS / "auto-tag.yml").exists()
    assert not (WORKFLOWS / "nightly-tag.yml").exists()


def test_tag_job_needs_every_validating_job() -> None:
    """Drop one and a tag can land on a commit that failed it. Every job in
    ci.yml other than `tag` itself must be listed."""
    jobs = set(_load_yaml(CI)["jobs"])
    needs = set(_tag_job()["needs"])
    assert needs == jobs - {TAG_JOB}
    assert VALIDATING_JOBS <= needs


def test_tag_job_runs_only_on_pushes_to_the_two_release_branches() -> None:
    cond = " ".join(str(_tag_job()["if"]).split())
    assert "github.event_name == 'push'" in cond
    assert "github.ref == 'refs/heads/main'" in cond
    assert "github.ref == 'refs/heads/nightly-dev'" in cond


def test_ci_still_runs_on_pushes_to_nightly_dev() -> None:
    """Without this, the tag job never runs on nightly-dev and no candidate is
    ever cut -- with no error anywhere."""
    branches = _load_yaml(CI)[True]["push"]["branches"]
    assert {"main", "nightly-dev"} <= set(branches)


def test_only_the_tag_job_can_write() -> None:
    ci = _load_yaml(CI)
    assert ci["permissions"] == {"contents": "read"}
    for name, job in ci["jobs"].items():
        perms = job.get("permissions")
        if name == TAG_JOB:
            assert perms == {"contents": "write"}
        else:
            assert perms is None, f"job {name} declares its own permissions"


def test_tag_job_checkout_has_full_history_and_explicit_credentials() -> None:
    """fetch-depth 0: the baseline is derived from tags and origin/main, and a
    shallow clone has neither. persist-credentials true is the one deliberate
    exception in this repo -- the job pushes a tag."""
    checkouts = [s for s in _run_steps() if "actions/checkout" in str(s.get("uses"))]
    assert len(checkouts) == 1
    with_ = checkouts[0]["with"]
    assert with_["fetch-depth"] == 0
    assert with_["persist-credentials"] is True
    assert "ref" not in with_, "a push-triggered job tags the commit it was run for"


def test_tag_job_serializes_per_branch_instead_of_cancelling() -> None:
    concurrency = _tag_job()["concurrency"]
    assert concurrency["group"] == "tag-${{ github.ref }}"
    assert concurrency["cancel-in-progress"] is False


def test_workflow_level_cancellation_is_scoped_to_pull_requests() -> None:
    """A workflow-level cancel-in-progress: true would cancel an in-flight tag
    job the moment a second push to the same branch arrives -- that push's
    commit would never be tagged."""
    cancel = _load_yaml(CI)["concurrency"]["cancel-in-progress"]
    assert cancel == "${{ github.event_name == 'pull_request' }}"


def test_only_main_creates_a_github_release() -> None:
    steps = [s for s in _run_steps() if s.get("name") == "Create GitHub release"]
    assert len(steps) == 1
    assert steps[0]["if"] == "steps.bump.outputs.channel == 'stable'"
    assert "gh release create" in steps[0]["run"]
    assert "--verify-tag" in steps[0]["run"]


def test_release_step_has_no_skip_gate() -> None:
    """A docs- or chore-only merge to main is still a release (a patch)."""
    for step in _run_steps():
        assert "skip" not in str(step.get("if", ""))
    for line in _code_lines(CI):
        assert "skip=" not in line, f"tag job emits a skip output: {line.strip()}"


# --- the human-pushed tag path: release.yml ----------------------------------

RELEASE = WORKFLOWS / "release.yml"


def _release_steps() -> list[dict[str, Any]]:
    return [
        s
        for s in _load_yaml(RELEASE)["jobs"]["release"]["steps"]
        if isinstance(s, dict)
    ]


def _release_script(name: str) -> str:
    matches = [s["run"] for s in _release_steps() if s.get("name") == name]
    assert len(matches) == 1, f"expected one step named {name!r}"
    return matches[0]


def test_release_uses_no_third_party_action() -> None:
    uses = [str(s.get("uses", "")) for s in _release_steps() if s.get("uses")]
    assert all(u.startswith("actions/checkout@") for u in uses), uses


def test_release_checkout_has_history_and_no_credentials() -> None:
    (checkout,) = [
        s for s in _release_steps() if "actions/checkout" in str(s.get("uses"))
    ]
    assert checkout["with"]["fetch-depth"] == 0
    assert checkout["with"]["persist-credentials"] is False


@pytest.mark.parametrize(
    ("tag", "on_main", "ok", "annotated"),
    [
        pytest.param("v9.0.0", True, True, False, id="final-on-main"),
        pytest.param("v9.0.0", False, False, False, id="final-off-main"),
        pytest.param("v9.0.0rc1", False, True, False, id="candidate-off-main"),
        pytest.param("v9.0.0", True, True, True, id="final-on-main-annotated"),
        pytest.param("v9.0.0", False, False, True, id="final-off-main-annotated"),
    ],
)
def test_main_containment_guard(
    tag: str, on_main: bool, ok: bool, annotated: bool, tmp_path: Path
) -> None:
    """Behavioural, like the tag-step tests: run the real step script.

    The annotated rows matter: an annotated tag is a tag object, and the
    containment check has to peel it to its commit to answer correctly.
    """
    repo, _remote = _init_repo_with_remote(tmp_path)
    _git_cmd("update-ref", "refs/remotes/origin/main", "HEAD", cwd=repo)
    if not on_main:
        _git_cmd("checkout", "-qb", "side", cwd=repo)
        (repo / "f.txt").write_text("side\n")
        _git_cmd("commit", "-qam", "chore: side", cwd=repo)
    if annotated:
        _git_cmd("tag", "-a", "-m", "release", tag, cwd=repo)
    else:
        _git_cmd("tag", tag, cwd=repo)
    result = _run_script(
        _release_script("Refuse a final tag that main does not contain"),
        repo,
        {"GITHUB_REF_NAME": tag, **_git_env()},
    )
    assert (result.returncode == 0) is ok, f"{result.stdout}\n{result.stderr}"


# A stub `gh` on PATH: records each call's argv and fails `release view` so the
# create path runs. The real step script is what gets executed.
_GH_STUB = """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$GH_STUB_LOG"
if [[ "$1 $2" == "release view" ]]; then exit 1; fi
exit 0
"""


@pytest.mark.parametrize(
    ("tag", "final"),
    [
        pytest.param("v9.0.0", True, id="final"),
        pytest.param("v9.0.0rc1", False, id="candidate"),
        pytest.param("v9.0.0-foo", False, id="unexpected-shape"),
    ],
)
def test_release_create_argv_by_tag_shape(
    tag: str, final: bool, tmp_path: Path
) -> None:
    """Behavioural: a final is the only shape that may become "latest"; every
    other shape must be a prerelease that is never latest."""
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    gh = stub_dir / "gh"
    gh.write_text(_GH_STUB)
    gh.chmod(0o755)
    log = tmp_path / "gh.log"
    result = _run_script(
        _release_script("Create GitHub release"),
        tmp_path,
        {
            "GITHUB_REF_NAME": tag,
            "GH_TOKEN": "stub",
            "GH_STUB_LOG": str(log),
            "PATH": f"{stub_dir}{os.pathsep}{os.environ['PATH']}",
            **_git_env(),
        },
    )
    assert result.returncode == 0, f"{result.stdout}\n{result.stderr}"
    calls = log.read_text().splitlines()
    creates = [c.split() for c in calls if c.startswith("release create ")]
    assert len(creates) == 1, calls
    argv = creates[0]
    assert tag in argv
    assert "--verify-tag" in argv
    assert "--generate-notes" in argv
    if final:
        assert "--prerelease" not in argv
        assert "--latest=false" not in argv
    else:
        assert "--prerelease" in argv
        assert "--latest=false" in argv
