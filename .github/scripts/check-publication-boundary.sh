#!/usr/bin/env bash
#
# Refuses a commit that adds or modifies a publication-boundary path.
#
# trustedsec/hate_crack is a public repository. A handful of paths are local
# development aids only: they are gitignored, and they were purged from git
# history on 2026-07-25. Until now that rule lived only in prose, so a `git add
# -f` -- or an index-corrupting hook -- could stage one anyway. On 2026-07-30 a
# commit did exactly that and reached the public remote.
#
# CLAUDE.md and .claude/ were removed from this list on 2026-08-21 and are now
# published on purpose. The list narrowed rather than disappeared: what remains
# is either per-developer state (.claude/settings.local.json) or local planning
# notes (.claude/plans/, .claude/specs/, docs/plans/, docs/superpowers/).
# Narrowing is the point -- a guard that blocks things people have decided to
# publish is a guard people switch off.
#
# Note that .claude/ is published but two of its subdirectories are not. Plans
# and specs are per-task scratch: they are written in the future tense, go stale
# the moment the work lands, and a reader cannot tell a shipped design from an
# abandoned one. The tooling beside them is live and is published.
#
# This reads the staged changeset from the index rather than trusting
# .gitignore, because forcing past .gitignore is precisely the failure mode.
#
# Deletions are deliberately allowed: removing an accidentally tracked boundary
# file must stay possible.
#
# Exit 0 when the staged changeset is clean, 1 when it is not.

set -euo pipefail

# Any staged path matching one of these globs is refused. Keep in sync with the
# corresponding .gitignore entries and with the test suite's copy of this list.
PATTERNS=(
	'.claude/settings.local.json'
	'*/.claude/settings.local.json'
	'.claude/plans'
	'.claude/plans/*'
	'*/.claude/plans/*'
	'.claude/specs'
	'.claude/specs/*'
	'*/.claude/specs/*'
	'docs/plans'
	'docs/plans/*'
	'*/docs/plans/*'
	'docs/superpowers'
	'docs/superpowers/*'
	'*/docs/superpowers/*'
)

# An empty repository has no HEAD to diff against; use the empty tree so the
# very first commit is still checked.
if git rev-parse --verify --quiet HEAD >/dev/null; then
	against=HEAD
else
	against=$(git hash-object -t tree /dev/null)
fi

# --diff-filter excludes D, so deletions never reach the loop. For a rename
# --name-only reports the destination path, which is the one that would land in
# the tree.
staged=$(git diff --cached --name-only --diff-filter=ACMRT "$against")

offenders=()
while IFS= read -r path; do
	[ -n "$path" ] || continue
	for pattern in "${PATTERNS[@]}"; do
		# shellcheck disable=SC2053  # glob match is intended, not equality
		if [[ $path == $pattern ]]; then
			offenders+=("$path")
			break
		fi
	done
done <<<"$staged"

if [ ${#offenders[@]} -eq 0 ]; then
	exit 0
fi

{
	echo "BLOCKED: the staged changeset contains publication-boundary paths."
	echo
	for path in "${offenders[@]}"; do
		echo "    $path"
	done
	echo
	echo "These paths are local-only. This repository is PUBLIC, and these"
	echo "paths are gitignored and must not be committed."
	echo
	echo ".claude/plans/, .claude/specs/, docs/plans/ and docs/superpowers/"
	echo "are local planning notes, not part of the shipped project."
	echo ".claude/settings.local.json is per-developer permission state,"
	echo "personal by design."
	echo
	echo "To proceed, unstage them:"
	echo
	for path in "${offenders[@]}"; do
		echo "    git restore --staged -- '$path'"
	done
	echo
	echo "If you did not stage these yourself, your index may be corrupt --"
	echo "a known prek pre-push stash/restore failure does this (issue #224)."
	echo "Recover with, in order:"
	echo
	echo "    git config core.bare false   # if git says 'must be run in a work tree'"
	echo "    git reset HEAD               # rebuild the index from HEAD"
	echo "    git status --short           # expect empty"
	echo
	echo "Nothing on disk is lost by either command."
	echo
	echo "There is no override for this check. Deleting one of these paths is"
	echo "always allowed; only adding or modifying one is refused."
} >&2

exit 1
