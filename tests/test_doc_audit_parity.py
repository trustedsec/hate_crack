"""Guards the documentation-audit heuristic in .claude/audit-docs.sh and
.claude/check-docs.sh.

Both scripts decide the same thing — did this commit change code without
changing documentation — and each carries its own copy of the two grep patterns
that decide it. Drift between the two copies is the failure this file exists to
catch, so every case is asserted against *both* scripts.

They are exercised by running the real scripts against throwaway git repos
holding real commits, never by matching on command strings. A string-matching
test here would pass while the actual git-shelling behaviour was broken, and
that trap has already cost this repo a green suite over a real bug (#222).

Two exclusions in those patterns are load-bearing and easy to "simplify" away,
which is why each has its own case below:

* ``CHANGELOG.md`` does not count as documentation. It changes on nearly every
  commit here, so counting it silenced the audit on most real changes.
* ``tests/`` does not count as code. A test-only commit changes no documented
  behaviour, so flagging it is pure noise.

This test could only move here from ``.claude/`` once ``.claude/`` became
published on 2026-08-21; before that, ``test_no_tracked_file_references_
unpublished_dev_paths`` refused any tracked file that cited the path.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

CLAUDE_DIR = Path(__file__).resolve().parents[1] / ".claude"
AUDIT = CLAUDE_DIR / "audit-docs.sh"
CHECK = CLAUDE_DIR / "check-docs.sh"

# (id, files_in_commit, should_flag)
#
# The heuristic: flag when a commit touches code outside tests/ but touches no
# documentation, where CHANGELOG.md does not count as documentation.
CASES = [
    ("code_and_changelog_only", ["hate_crack/main.py", "CHANGELOG.md"], True),
    ("code_only", ["hate_crack/main.py"], True),
    ("code_and_readme", ["hate_crack/main.py", "README.md"], False),
    ("code_and_other_doc", ["hate_crack/main.py", "TESTING.md"], False),
    ("tests_only_and_changelog", ["tests/test_x.py", "CHANGELOG.md"], False),
    ("tests_only", ["tests/test_x.py"], False),
    ("docs_only", ["CHANGELOG.md"], False),
    ("config_example_and_changelog", ["config.json", "CHANGELOG.md"], True),
]


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


@pytest.fixture(scope="module")
def repo(tmp_path_factory: pytest.TempPathFactory) -> dict[str, object]:
    """A throwaway repo with one commit per case, plus the scripts under test.

    The scripts resolve PROJECT_ROOT as the parent of their own directory, so
    copying them into <repo>/.claude/ points them at this repo and never at the
    real checkout.
    """
    root = tmp_path_factory.mktemp("audit-parity")
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "Test")

    dst = root / ".claude"
    dst.mkdir()
    for src in (AUDIT, CHECK):
        (dst / src.name).write_text(src.read_text())

    # A base commit so diff-tree has a parent to compare against.
    (root / "seed").write_text("seed\n")
    _git(root, "add", "seed")
    _git(root, "commit", "-qm", "seed")

    shas: dict[str, str] = {}
    for case_id, files, _ in CASES:
        for rel in files:
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            # Append so every commit is a real change, even on a repeated path.
            with target.open("a") as fh:
                fh.write(f"{case_id}\n")
            _git(root, "add", rel)
        _git(root, "commit", "-qm", case_id)
        shas[case_id] = _git(root, "rev-parse", "HEAD")

    return {"root": root, "shas": shas}


def _audit_flags(repo_root: Path, sha: str) -> bool:
    """True when audit-docs.sh emits its code-changed-but-docs-didn't warning."""
    out = subprocess.run(
        ["bash", str(repo_root / ".claude" / "audit-docs.sh"), sha],
        capture_output=True,
        text=True,
    )
    assert out.returncode == 0, f"audit-docs.sh failed: {out.stderr}"
    return "documentation was not updated" in out.stdout


def _check_flags(repo_root: Path, sha: str, depth: int) -> bool:
    """True when check-docs.sh names ``sha`` as a problem commit."""
    out = subprocess.run(
        ["bash", str(repo_root / ".claude" / "check-docs.sh"), str(depth)],
        capture_output=True,
        text=True,
    )
    assert out.returncode == 0, f"check-docs.sh failed: {out.stderr}"
    short = sha[:7]
    return any(
        short in line and "Code changed but docs not updated" in line
        for line in out.stdout.splitlines()
    )


@pytest.mark.parametrize(
    ("case_id", "expected"),
    [(c[0], c[2]) for c in CASES],
    ids=[c[0] for c in CASES],
)
def test_audit_docs_verdict(repo, case_id: str, expected: bool) -> None:
    """audit-docs.sh flags exactly the commits it should."""
    root, sha = repo["root"], repo["shas"][case_id]
    assert _audit_flags(root, sha) is expected


@pytest.mark.parametrize(
    ("case_id", "expected"),
    [(c[0], c[2]) for c in CASES],
    ids=[c[0] for c in CASES],
)
def test_check_docs_agrees_with_audit_docs(repo, case_id: str, expected: bool) -> None:
    """check-docs.sh reaches the same verdict — this is the anti-drift guard.

    The two scripts duplicate the heuristic, so they are compared against the
    same expectation rather than against each other; a shared regression in both
    still fails here.
    """
    root, sha = repo["root"], repo["shas"][case_id]
    depth = len(CASES) + 2  # deep enough to cover every case commit
    assert _check_flags(root, sha, depth) is expected


def test_changelog_exclusion_is_present_in_both_scripts() -> None:
    """Static backstop: the exclusions must be spelled the same way in both.

    The behavioural tests above are the real check, but they run against a
    synthetic repo. This catches the narrower mistake of fixing one script and
    forgetting the other, and names the fix in its message.
    """
    for script in (AUDIT, CHECK):
        text = script.read_text()
        assert "CHANGELOG" in text, (
            f"{script.name} lost its CHANGELOG.md exclusion; a changelog entry "
            "would once again silence the audit on most commits."
        )
        assert "^tests/" in text, (
            f"{script.name} lost its tests/ exclusion; test-only commits would "
            "again be flagged as needing a README update."
        )
