#!/bin/bash
# Quick Documentation Check
# Use this script within Claude Code to verify that documentation is in sync
# with recent code changes.
#
# Usage: .claude/check-docs.sh [optional: number of commits to check]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
NUM_COMMITS="${1:-3}"

echo "Documentation Status Check"
echo "==========================="
echo ""
echo "Analyzing the last $NUM_COMMITS commits for code changes without documentation updates..."
echo ""

cd "$PROJECT_ROOT"

# Get the last N commits
COMMITS=$(git log -n "$NUM_COMMITS" --pretty=format:"%h")

DOC_ISSUES=0

for commit in $COMMITS; do
  # Get files changed in this commit
  CHANGED=$(git diff-tree --no-commit-id --name-only -r "$commit" || echo "")

  if [ -z "$CHANGED" ]; then
    continue
  fi

  # Check for code changes
  CODE_CHANGED=$(echo "$CHANGED" | grep -E "\.py$|config\.json|pyproject\.toml|Makefile" || true)

  # Check for doc changes
  DOC_CHANGED=$(echo "$CHANGED" | grep -E "README|CLAUDE|\.md$" || true)

  if [ -n "$CODE_CHANGED" ] && [ -z "$DOC_CHANGED" ]; then
    echo "❌ Commit $commit: Code changed but docs not updated"
    echo "   Files:"
    # shellcheck disable=SC2001
    echo "$CODE_CHANGED" | sed 's/^/     /'
    echo ""
    DOC_ISSUES=$((DOC_ISSUES + 1))
  fi
done

if [ $DOC_ISSUES -eq 0 ]; then
  echo "✅ All recent commits have corresponding documentation updates!"
else
  echo "⚠️  Found $DOC_ISSUES commit(s) with code changes but no documentation updates"
  echo ""
  echo "Next steps:"
  echo "1. Review the code changes in the flagged commits"
  echo "2. Update README.md or other documentation as needed"
  echo "3. Re-run this check to verify"
fi

echo ""
