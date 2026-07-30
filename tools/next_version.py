#!/usr/bin/env python3
"""Compute the next version tag for a branch, per hate_crack's release policy.

The policy has one rule per channel:

* **stable (`main`)** — the patch component is always ``0``. Merging
  ``nightly-dev`` down is the release event, so it cuts ``X.(Y+1).0``, or
  ``(X+1).0.0`` when any commit since the last tag is breaking.
* **nightly (`nightly-dev`)** — the patch component is a counter. Each merge
  that passes CI cuts ``X.Y.(P+1)``, so ``2.19.1``, ``2.19.2``, … accumulate
  between releases and sort after the current stable release and before the next
  one.

Nightly versions are therefore ordinary final versions rather than ``-rc``
pre-releases. Nothing marks them as nightly in the version string; what keeps
them out of an operator's upgrade path is that only ``main`` publishes a GitHub
release, and the startup check reads the releases endpoint.

Baseline is the highest final tag in the repository, deliberately NOT restricted
to tags reachable from HEAD. A nightly-dev tip does not contain the tag created
on main's merge commit, so a reachability-restricted lookup would compute the
next nightly from a stale baseline and hand out a version lower than the stable
release that already shipped.

Both tagging workflows call this so the policy lives in one place. It is a
library first and a CLI second: everything above the git boundary is pure and
unit-tested in tests/test_next_version.py.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

# Final release tags only. Any pre-release spelling (v2.19.0-rc.3, left over
# from the retired rc scheme) must not become a baseline.
TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")

BREAKING_SUBJECT_RE = re.compile(r"^[a-zA-Z]+(\(.+\))?!:")
BREAKING_FOOTER_RE = re.compile(r"^(BREAKING CHANGE|BREAKING-CHANGE):", re.MULTILINE)

STABLE = "stable"
NIGHTLY = "nightly"


def parse_tag(tag: str) -> tuple[int, int, int] | None:
    """Return (major, minor, patch) for a final release tag, else None."""
    match = TAG_RE.match(tag.strip())
    if match is None:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def latest_release(tags: list[str]) -> tuple[int, int, int]:
    """Highest final release version among *tags*, or (0, 0, 0) if there is none.

    Compared as integer tuples rather than strings so 2.9.0 does not outrank
    2.10.0.
    """
    versions = [v for v in (parse_tag(t) for t in tags) if v is not None]
    return max(versions) if versions else (0, 0, 0)


def has_breaking_change(messages: list[str]) -> bool:
    """True if any commit message declares a breaking change.

    Recognises both Conventional Commits spellings: a ``!`` before the colon in
    the subject, and a ``BREAKING CHANGE:`` footer in the body.
    """
    for message in messages:
        subject = message.lstrip().split("\n", 1)[0]
        if BREAKING_SUBJECT_RE.match(subject):
            return True
        if BREAKING_FOOTER_RE.search(message):
            return True
    return False


def next_stable(base: tuple[int, int, int], breaking: bool) -> str:
    """Next release version for main. Patch is always 0.

    Note there is no "no releasable commits" case: on main, having new commits at
    all is the release event. The old policy skipped tagging a docs-only or
    chore-only push, which under this scheme would mean a nightly merge carrying
    only such commits never got released.
    """
    major, minor, _ = base
    if breaking:
        return f"v{major + 1}.0.0"
    return f"v{major}.{minor + 1}.0"


def next_nightly(base: tuple[int, int, int], tags: list[str]) -> str:
    """Next nightly version: the lowest free patch above *base*.

    Skipping past taken numbers rather than failing on a collision keeps a
    re-run, or a hand-pushed tag, from stalling the counter.
    """
    major, minor, patch = base
    existing = {t.strip() for t in tags}
    candidate = patch + 1
    while f"v{major}.{minor}.{candidate}" in existing:
        candidate += 1
    return f"v{major}.{minor}.{candidate}"


def _git(args: list[str], repo_dir: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repo_dir,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def git_tags(repo_dir: str) -> list[str]:
    return [line for line in _git(["tag"], repo_dir).splitlines() if line.strip()]


def commit_messages(repo_dir: str, base: tuple[int, int, int]) -> list[str]:
    """Commit messages on HEAD since the *base* tag, newest first.

    A (0, 0, 0) base means no release tag exists yet, so the whole history counts.
    """
    major, minor, patch = base
    rev_range = "HEAD" if base == (0, 0, 0) else f"v{major}.{minor}.{patch}..HEAD"
    out = _git(["log", rev_range, "--format=%B%x00"], repo_dir)
    return [chunk for chunk in out.split("\0") if chunk.strip()]


def compute(channel: str, repo_dir: str) -> str | None:
    """Next tag for *channel*, or None when there is nothing to tag."""
    tags = git_tags(repo_dir)
    base = latest_release(tags)
    messages = commit_messages(repo_dir, base)

    if not messages:
        return None

    if channel == NIGHTLY:
        return next_nightly(base, tags)
    return next_stable(base, has_breaking_change(messages))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--channel", required=True, choices=[STABLE, NIGHTLY])
    parser.add_argument("--repo-dir", default=".")
    args = parser.parse_args(argv)

    tag = compute(args.channel, args.repo_dir)
    if tag is None:
        # Empty stdout is the "nothing to do" signal; the workflows test for it.
        print(
            f"No new commits since the last release tag ({args.channel})",
            file=sys.stderr,
        )
        return 0
    print(tag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
