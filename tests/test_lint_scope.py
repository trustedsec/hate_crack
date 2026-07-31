"""The lint entry points must agree, and nothing may sit outside them.

Issue #237: tools/ was linted by nothing at all -- the Makefile and both
pre-push hooks scoped to hate_crack, CI added tests -- so an F541 and a
formatting drift sat in tools/ollama_benchmark.py until someone ran ruff by
hand. The failure mode is silence: a new top-level package is simply never
mentioned, and nobody finds out.

These tests read the real config files rather than a copy of the intended
scope, so they fail when the files disagree with each other.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

# Every directory holding first-party Python that must be linted. Adding a new
# top-level package means adding it here, which is the point: the test then
# fails until the four entry points are updated too.
LINTED_DIRS = ("hate_crack", "tests", "tools", "packaging")

# Directories excluded on purpose, with the reason. Anything not in either list
# trips test_no_first_party_python_is_unlinted.
NOT_LINTED = {
    ".venv": "third-party",
    "build": "generated",
    "dist": "generated",
    "hashcat-utils": "vendored submodule",
    "HashcatRosetta": "vendored submodule",
    "omen": "vendored submodule",
    "pcfg_cracker": "vendored submodule",
    "princeprocessor": "vendored submodule",
    "PACK": "vendored, python2",
    "hashcat_debug": "vendored submodule",
    "lima": "vm config, no first-party python",
    "masks": "data",
    "rules": "data",
    "hate_crack.egg-info": "generated",
    "__pycache__": "generated",
}


def _ruff_commands() -> dict[str, list[str]]:
    """Every ruff invocation in the repo's config, keyed by where it lives."""
    found: dict[str, list[str]] = {}

    makefile = (REPO_ROOT / "Makefile").read_text()
    found["Makefile"] = re.findall(
        r"uv run ruff (?:check|format[^\n]*?) ([^\n]+)", makefile
    )

    prek = tomllib.loads((REPO_ROOT / "prek.toml").read_text())
    entries = [
        hook["entry"]
        for hook in prek.get("repos", [{}])[0].get("hooks", [])
        if "ruff" in hook.get("entry", "")
    ]
    # prek.toml uses [[repos.hooks]] tables; collect from wherever they landed.
    if not entries:
        entries = [
            h["entry"]
            for repo in prek.get("repos", [])
            for h in repo.get("hooks", [])
            if "ruff" in h.get("entry", "")
        ]
    found["prek.toml"] = [
        e.split("--check")[-1].strip()
        if "--check" in e
        else e.split("check")[-1].strip()
        for e in entries
    ]

    ci = yaml.safe_load((REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text())
    ci_runs = [
        step["run"]
        for job in ci["jobs"].values()
        for step in job.get("steps", [])
        if "run" in step and "ruff" in step["run"]
    ]
    found["ci.yml"] = [
        r.split("--check")[-1].strip()
        if "--check" in r
        else r.split("check")[-1].strip()
        for r in ci_runs
    ]
    return found


def _normalize(scope: str) -> tuple[str, ...]:
    return tuple(sorted(part for part in scope.split() if not part.startswith("-")))


EXPECTED = tuple(sorted(LINTED_DIRS))


@pytest.mark.parametrize("source", ["Makefile", "prek.toml", "ci.yml"])
def test_every_ruff_invocation_uses_the_same_scope(source):
    """A local gate narrower than CI means `make check` passing proves nothing."""
    commands = _ruff_commands()[source]
    assert commands, f"no ruff invocation found in {source}"
    for scope in commands:
        assert _normalize(scope) == EXPECTED, (
            f"{source} lints {_normalize(scope)}, expected {EXPECTED}. All four "
            "entry points must agree or a finding slips through the narrow one."
        )


def test_both_lint_and_format_are_checked_everywhere():
    """The Makefile once ran `ruff check` but not `ruff format --check`, so a
    formatting-only problem passed locally and failed in CI."""
    for source, commands in _ruff_commands().items():
        assert len(commands) >= 2, (
            f"{source} has {len(commands)} ruff invocation(s); both `check` and "
            "`format --check` are required"
        )


def test_no_first_party_python_is_unlinted():
    """The actual failure in #237: a directory nobody thought to mention.

    Any top-level directory containing .py files must be either linted or
    explicitly excused, so a new package cannot be silently unlinted.
    """
    unaccounted = []
    for child in sorted(REPO_ROOT.iterdir()):
        if not child.is_dir() or child.name.startswith("."):
            continue
        if child.name in NOT_LINTED or child.name in LINTED_DIRS:
            continue
        if any(child.rglob("*.py")):
            unaccounted.append(child.name)
    assert not unaccounted, (
        f"these directories hold Python and are neither linted nor excused: "
        f"{unaccounted}. Add them to LINTED_DIRS and to all four entry points, "
        "or to NOT_LINTED with a reason."
    )


def test_the_declared_scope_actually_passes():
    """Belt and braces: run ruff over the declared scope and require success, so
    the config cannot claim a scope that does not hold."""
    for args in (["check"], ["format", "--check"]):
        result = subprocess.run(
            [sys.executable, "-m", "ruff", *args, *LINTED_DIRS],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"ruff {' '.join(args)} fails on the declared scope:\n"
            f"{result.stdout}\n{result.stderr}"
        )
