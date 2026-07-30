#!/usr/bin/env bash
#
# Aborts a commit that deletes an implausible number of tracked files.
#
# On 2026-07-30 the prek pre-push hook's stash/restore cycle corrupted the index
# and left the entire tracked tree staged as deleted. The commit that captured
# that state succeeded silently -- it looked normal in `git log`, and only
# `git diff --shortstat` revealed 85,280 removed lines. It reached the public
# remote before anyone noticed. See issue #224.
#
# Threshold: the incident staged roughly 165 deletions. No commit in the last
# 400 commits of this repository's history deleted more than ONE file, so 50 is
# two orders of magnitude above real work while still catching a whole-tree
# wipe. A genuine mass deletion sets the override named in the message below.
#
# Exit 0 when the staged deletion count is plausible, 1 when it is not.

set -euo pipefail

THRESHOLD=${HATE_CRACK_MASS_DELETE_THRESHOLD:-50}

# Escape hatch for a real bulk removal (vendored tree drop, directory rename
# recorded as delete+add). Documented in the failure message so nobody has to
# resort to --no-verify, which would also skip the publication-boundary guard.
if [ "${HATE_CRACK_ALLOW_MASS_DELETE:-}" = "1" ]; then
	exit 0
fi

if git rev-parse --verify --quiet HEAD >/dev/null; then
	against=HEAD
else
	against=$(git hash-object -t tree /dev/null)
fi

deleted=$(git diff --cached --name-only --diff-filter=D "$against" | grep -c . || true)

if [ "$deleted" -le "$THRESHOLD" ]; then
	exit 0
fi

{
	echo "BLOCKED: this commit would delete $deleted tracked files (limit $THRESHOLD)."
	echo
	echo "That is far more than any real change in this repository's history."
	echo "The usual cause is a corrupt index, not an intentional deletion -- a"
	echo "known prek pre-push stash/restore failure stages the whole tree as"
	echo "deleted and can also flip core.bare on a normal checkout (issue #224)."
	echo
	echo "Recover with, in order -- neither command touches files on disk:"
	echo
	echo "    git config core.bare false   # if git says 'must be run in a work tree'"
	echo "    git reset HEAD               # rebuild the index from HEAD"
	echo "    git status --short           # expect empty"
	echo "    git log --oneline -3         # confirm your commits survive"
	echo
	echo "If the deletion really is intended, re-run the commit with:"
	echo
	echo "    HATE_CRACK_ALLOW_MASS_DELETE=1 git commit ..."
	echo
	echo "Use that rather than --no-verify, which would also skip the"
	echo "publication-boundary guard."
} >&2

exit 1
