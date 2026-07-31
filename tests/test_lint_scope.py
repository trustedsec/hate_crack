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
import tomllib
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

# Every directory holding first-party Python that must be linted. Adding a new
# top-level package means adding it here, which is the point: the test then
# fails until the four entry points are updated too.
LINTED_DIRS = ("hate_crack", "tests", "tools", "packaging")

# Root-level .py files (siblings of the directories above) that must be
# linted too. hate_crack.py is the documented entry point (README.md) and was
# missed entirely by the directory-only scan below -- the exact #237 failure
# mode, still open for one file.
LINTED_ROOT_FILES = ("hate_crack.py",)

# Directories excluded on purpose, with the reason. Anything not in either list
# trips test_no_first_party_python_is_unlinted.
NOT_LINTED = {
    "build": "generated",
    "dist": "generated",
    "hashcat-utils": "vendored submodule",
    "HashcatRosetta": "vendored submodule",
    "omen": "vendored submodule",
    "pcfg_cracker": "vendored submodule",
    "princeprocessor": "vendored submodule",
    "PACK": "vendored, python2",
    "hashcat_debug": "gitignored runtime debug-log directory (.gitignore), not tracked",
    "lima": "vm config, no first-party python",
    "masks": "data",
    "rules": "data",
    "hate_crack.egg-info": "generated",
    "__pycache__": "generated",
}

# Root-level .py files excluded on purpose, with the reason. Same discipline
# as NOT_LINTED, for the files LINTED_ROOT_FILES doesn't cover.
NOT_LINTED_ROOT_FILES: dict[str, str] = {}


def _ruff_commands() -> dict[str, list[tuple[str, str]]]:
    """Every ruff invocation in the repo's config, keyed by where it lives.

    Each entry is a (verb, scope) pair, e.g. ("check", "hate_crack tests") or
    ("format --check", "hate_crack tests"), so callers can check both which
    scope is used and which verb was actually run.
    """
    found: dict[str, list[tuple[str, str]]] = {}

    makefile = (REPO_ROOT / "Makefile").read_text()
    found["Makefile"] = [
        (verb, scope.strip())
        for verb, scope in re.findall(
            r"uv run ruff (check|format(?: --check)?) ([^\n]+)", makefile
        )
    ]

    prek = tomllib.loads((REPO_ROOT / "prek.toml").read_text())
    entries = [
        hook["entry"]
        for repo in prek.get("repos", [])
        for hook in repo.get("hooks", [])
        if "ruff" in hook.get("entry", "")
    ]
    found["prek.toml"] = [
        (m.group(1), m.group(2).strip())
        for e in entries
        for m in [re.search(r"ruff (check|format(?: --check)?) (.+)", e)]
        if m
    ]

    ci = yaml.safe_load((REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text())
    ci_runs = [
        step["run"]
        for job in ci["jobs"].values()
        for step in job.get("steps", [])
        if "run" in step and "ruff" in step["run"]
    ]
    found["ci.yml"] = [
        (m.group(1), m.group(2).strip())
        for r in ci_runs
        for m in [re.search(r"ruff (check|format(?: --check)?) (.+)", r)]
        if m
    ]
    return found


def _normalize(scope: str) -> tuple[str, ...]:
    return tuple(sorted(part for part in scope.split() if not part.startswith("-")))


EXPECTED = tuple(sorted(LINTED_DIRS + LINTED_ROOT_FILES))


@pytest.mark.parametrize("source", ["Makefile", "prek.toml", "ci.yml"])
def test_every_ruff_invocation_uses_the_same_scope(source):
    """A local gate narrower than CI means `make check` passing proves nothing."""
    commands = _ruff_commands()[source]
    assert commands, f"no ruff invocation found in {source}"
    for _verb, scope in commands:
        assert _normalize(scope) == EXPECTED, (
            f"{source} lints {_normalize(scope)}, expected {EXPECTED}. All four "
            "entry points must agree or a finding slips through the narrow one."
        )


def test_both_lint_and_format_are_checked_everywhere():
    """The Makefile once ran `ruff check` but not `ruff format --check`, so a
    formatting-only problem passed locally and failed in CI."""
    required = {"check", "format --check"}
    for source, commands in _ruff_commands().items():
        assert len(commands) >= 2, (
            f"{source} has {len(commands)} ruff invocation(s); both `check` and "
            "`format --check` are required"
        )
        verbs = {verb for verb, _scope in commands}
        missing = required - verbs
        assert not missing, (
            f"{source} is missing {missing}; found verbs {verbs}. Both `ruff "
            "check` and `ruff format --check` must run, or a formatting-only "
            "problem passes locally and fails in CI."
        )


def test_no_first_party_python_is_unlinted():
    """The actual failure in #237: a directory (or root module) nobody thought
    to mention.

    Any top-level directory or root-level .py file containing/being
    first-party Python must be either linted or explicitly excused, so a new
    package or module cannot be silently unlinted.
    """
    unaccounted = []
    for child in sorted(REPO_ROOT.iterdir()):
        if child.name.startswith("."):
            continue
        if child.is_dir():
            if child.name in NOT_LINTED or child.name in LINTED_DIRS:
                continue
            if any(child.rglob("*.py")):
                unaccounted.append(child.name)
        elif child.suffix == ".py":
            if child.name in NOT_LINTED_ROOT_FILES or child.name in LINTED_ROOT_FILES:
                continue
            unaccounted.append(child.name)
    assert not unaccounted, (
        f"these hold Python and are neither linted nor excused: {unaccounted}. "
        "Add directories to LINTED_DIRS, root-level files to LINTED_ROOT_FILES, "
        "and update all four entry points -- or add an excuse to NOT_LINTED / "
        "NOT_LINTED_ROOT_FILES with a reason."
    )


def test_the_declared_scope_actually_passes():
    """Belt and braces: run ruff over the declared scope and require success, so
    the config cannot claim a scope that does not hold.

    Invoked as `uv run ruff`, matching every real gate (Makefile, prek.toml,
    ci.yml) -- a bare `python -m ruff` can resolve a different ruff than `uv`
    manages, which would make this test's pass/fail disagree with the gates
    it is meant to police.
    """
    for args in (["check"], ["format", "--check"]):
        result = subprocess.run(
            ["uv", "run", "ruff", *args, *LINTED_DIRS, *LINTED_ROOT_FILES],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"ruff {' '.join(args)} fails on the declared scope:\n"
            f"{result.stdout}\n{result.stderr}"
        )
