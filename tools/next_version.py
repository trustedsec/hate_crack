#!/usr/bin/env python3
"""Compute the next version tag for a branch, per hate_crack's release policy.

The policy is ordinary semver, with the bump derived from what is actually in
the batch:

* **The second component moves only for features.** Any ``feat`` commit since
  the last release means the batch is heading for ``X.(Y+1).0``. A batch of
  nothing but fixes, docs and chores is heading for ``X.Y.(Z+1)``.
* **``nightly-dev`` cuts release candidates** for whichever version the batch is
  heading toward: ``v2.20.1rc1``, ``v2.20.1rc2``, … These are real PEP 440
  pre-releases, so they sort *above* the release that precedes them and *below*
  the release they become::

      2.20.0  <  2.20.1rc1  <  2.20.1rc2  <  2.20.1  <  2.21.0rc1  <  2.21.0

  That ordering is the whole point of targeting the *next* version rather than
  the current one. An earlier scheme in this repo tagged ``v2.19.0-rc.N`` and was
  removed for sorting below the release it was heading for; the fix is not to
  abandon pre-releases but to aim them one version forward.
* **``main`` cuts the final** of that same target. Merging ``nightly-dev`` down
  promotes the candidate: a fix-only cycle ends at ``2.20.1``, a cycle with a
  feature ends at ``2.21.0``.

The major component is never bumped automatically. A ``!`` subject or a
``BREAKING CHANGE:`` footer is treated as a feature here, because an automatic
major is an irreversible published mistake waiting for one mistyped subject
line; a major release stays an explicit human act (tag and push it by hand).

Baseline is the highest final tag in the repository, deliberately NOT restricted
to tags reachable from HEAD. ``main``'s release tag can sit on a commit that the
``nightly-dev`` tip does not contain, and a reachability-restricted lookup would
then compute the next nightly from a stale baseline and hand out a version below
the release that already shipped.

Everything above the git boundary is pure and unit-tested in
tests/test_next_version.py. Both tagging workflows call this so the policy lives
in exactly one place, expressed in Python where it can be tested rather than in
YAML where it cannot.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

# A released version: exactly vX.Y.Z. Anything with a pre-release, post-release
# or local segment is deliberately excluded -- the baseline must be a version
# that actually shipped.
FINAL_TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")

# A candidate this policy produces: vX.Y.ZrcN.
RC_TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)rc(\d+)$")

# A conventional-commit subject introducing a feature: `feat:`, `feat(scope):`,
# and the breaking forms `feat!:` / `feat(scope)!:`. Anchored at the start of the
# subject so a `feat` mentioned mid-sentence in a fix's body cannot promote the
# whole batch to a minor bump.
FEATURE_SUBJECT = re.compile(r"^feat(\([^)]*\))?!?:", re.IGNORECASE)

# A breaking change under conventional commits: any type with `!` before the
# colon, or a `BREAKING CHANGE:` footer. Treated as a feature, not a major --
# see the module docstring.
BREAKING = re.compile(
    r"^[a-z]+(\([^)]*\))?!:|^BREAKING[ -]CHANGE:", re.IGNORECASE | re.MULTILINE
)

Version = tuple[int, int, int]


def parse_final(tag: str) -> Version | None:
    """``(major, minor, patch)`` for a released tag, else ``None``."""
    match = FINAL_TAG.match(tag.strip())
    if not match:
        return None
    return (int(match[1]), int(match[2]), int(match[3]))


def latest_final(tags: list[str]) -> Version:
    """Highest released version among *tags*, or ``(0, 0, 0)`` if there is none.

    ``(0, 0, 0)`` means "nothing has shipped yet", which makes the first fix-only
    batch 0.0.1 and the first batch with a feature 0.1.0.
    """
    finals = [v for v in (parse_final(tag) for tag in tags) if v is not None]
    return max(finals) if finals else (0, 0, 0)


def has_feature(messages: list[str]) -> bool:
    """Does any commit in *messages* introduce a feature (or break something)?

    Each element is a whole commit message, so the subject is its first line;
    the ``BREAKING CHANGE:`` footer is matched anywhere in the body.
    """
    for message in messages:
        subject = message.strip().splitlines()[0] if message.strip() else ""
        if FEATURE_SUBJECT.match(subject.strip()):
            return True
        if BREAKING.search(message):
            return True
    return False


def target_version(base: Version, messages: list[str]) -> Version | None:
    """The version this batch is heading for, or ``None`` if it is empty.

    ``None`` is not an error: a re-run of a workflow on an already-tagged commit
    has no commits since the baseline, and the right answer there is "nothing to
    tag" rather than a version nobody asked for.
    """
    if not messages:
        return None
    major, minor, patch = base
    if has_feature(messages):
        return (major, minor + 1, 0)
    return (major, minor, patch + 1)


def next_rc_number(target: Version, tags: list[str]) -> int:
    """The next candidate number for *target*: one above the highest seen.

    Counts from the tags rather than from a stored counter so a deleted or
    re-pushed tag cannot make this hand out a number that is already taken.
    """
    highest = 0
    for tag in tags:
        match = RC_TAG.match(tag.strip())
        if not match:
            continue
        if (int(match[1]), int(match[2]), int(match[3])) == target:
            highest = max(highest, int(match[4]))
    return highest + 1


def format_version(version: Version) -> str:
    return f"v{version[0]}.{version[1]}.{version[2]}"


def compute(channel: str, tags: list[str], messages: list[str]) -> str | None:
    """The tag to create for *channel*, or ``None`` when there is nothing to tag.

    Pure: every input is passed in, so the whole policy is testable without a
    repository. ``stable`` is ``main``'s final release; ``nightly`` is the
    candidate heading for the same target.
    """
    if channel not in ("stable", "nightly"):
        raise ValueError(f"unknown channel {channel!r}")
    target = target_version(latest_final(tags), messages)
    if target is None:
        return None
    if channel == "stable":
        return format_version(target)
    return f"{format_version(target)}rc{next_rc_number(target, tags)}"


# ---------------------------------------------------------------------------
# git boundary -- the only impure part, kept as thin as possible
# ---------------------------------------------------------------------------


def _git(args: list[str], repo_dir: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_dir,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def git_tags(repo_dir: str) -> list[str]:
    """Every tag in the repository, unordered.

    Ordering is this module's job, not git's: asking git to sort would put the
    policy back in a shell pipeline, which is what having this file avoids.
    """
    return [line for line in _git(["tag"], repo_dir).splitlines() if line.strip()]


def commit_messages(repo_dir: str, base: Version) -> list[str]:
    """Whole commit messages on HEAD since the *base* release, newest first.

    A ``(0, 0, 0)`` base means nothing has shipped, so the entire history counts.
    NUL-delimited because a commit body contains blank lines and any line-based
    split would chop one message into several.
    """
    rev_range = "HEAD" if base == (0, 0, 0) else f"{format_version(base)}..HEAD"
    out = _git(["log", rev_range, "--format=%B%x00"], repo_dir)
    return [chunk for chunk in out.split("\0") if chunk.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--channel", required=True, choices=["stable", "nightly"])
    parser.add_argument("--repo-dir", default=".")
    args = parser.parse_args(argv)

    tags = git_tags(args.repo_dir)
    messages = commit_messages(args.repo_dir, latest_final(tags))
    tag = compute(args.channel, tags, messages)
    if tag is None:
        return 0
    print(tag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
