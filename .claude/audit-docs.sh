#!/bin/bash
# Documentation Audit Script
# This script is called by Claude Code after commits to ensure README files
# accurately reflect code changes.
#
# Usage: .claude/audit-docs.sh [last_commit_sha]
# If no SHA provided, audits the most recent commit.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
COMMIT_SHA="${1:-HEAD}"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[Documentation Audit]${NC} Analyzing changes in ${COMMIT_SHA}..."

# Get list of changed files
CHANGED_FILES=$(git -C "$PROJECT_ROOT" diff-tree --no-commit-id --name-only -r "$COMMIT_SHA" || echo "")

if [ -z "$CHANGED_FILES" ]; then
  echo -e "${YELLOW}[Documentation Audit]${NC} No files changed in commit (possibly a merge)"
  exit 0
fi

echo -e "${GREEN}[Documentation Audit]${NC} Changed files:"
# shellcheck disable=SC2001
echo "$CHANGED_FILES" | sed 's/^/  /'

# Check if any documentation or config files changed
HAS_DOC_CHANGES=false
if echo "$CHANGED_FILES" | grep -qE "README|CLAUDE|\.md$"; then
  HAS_DOC_CHANGES=true
  echo -e "${YELLOW}[Documentation Audit]${NC} Documentation files detected"
fi

# Check if code files changed (Python, config, etc.)
HAS_CODE_CHANGES=false
if echo "$CHANGED_FILES" | grep -qE "\.py$|config\.json|pyproject\.toml|Makefile"; then
  HAS_CODE_CHANGES=true
  echo -e "${YELLOW}[Documentation Audit]${NC} Code/config files detected"
fi

# If code changed but docs didn't, flag for manual review
if [ "$HAS_CODE_CHANGES" = true ] && [ "$HAS_DOC_CHANGES" = false ]; then
  echo -e "${YELLOW}[Documentation Audit]${NC} WARNING: Code changed but documentation was not updated"
  echo -e "${YELLOW}[Documentation Audit]${NC} This is a reminder to review and update README.md if needed"
  echo ""
  echo "Changed code files:"
  # shellcheck disable=SC2001
  echo "$CHANGED_FILES" | grep -E "\.py$|config\.json|pyproject\.toml|Makefile" | sed 's/^/  /'
  echo ""
  echo "To audit documentation manually, run:"
  echo "  .claude/audit-docs.sh $COMMIT_SHA"
fi

exit 0
