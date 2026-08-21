#!/bin/bash
# Verify Documentation Audit System Setup
# Run this to confirm everything is installed and working correctly.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Documentation Audit System - Verification"
echo "=========================================="
echo ""

# Check if in git repo. Ask git rather than looking for a .git directory: in a
# linked worktree -- which this project's own policy requires for all edits --
# .git is a FILE containing a gitdir pointer, so the directory test reported
# "not a git repository" in every worktree.
if ! git -C "$PROJECT_ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  echo "❌ Not in a git repository"
  exit 1
fi

echo "✓ Git repository found"

# Check for required files
# The post-commit hook is deliberately NOT required. It was removed from
# prek.toml along with the automatic audit; audits are triggered by hand now, so
# requiring the hook made this script report failure on a correctly configured
# checkout.
REQUIRED_FILES=(
  "$SCRIPT_DIR/settings.json"
  "$SCRIPT_DIR/audit-docs.sh"
  "$SCRIPT_DIR/install-hooks.sh"
  "$SCRIPT_DIR/check-docs.sh"
  "$SCRIPT_DIR/DOCUMENTATION-AUDIT.md"
)

MISSING=0
for file in "${REQUIRED_FILES[@]}"; do
  if [ -f "$file" ]; then
    echo "✓ $(basename "$file")"
  else
    echo "❌ Missing: $file"
    MISSING=$((MISSING + 1))
  fi
done

echo ""

# The PostToolUse hook in settings.json is what still fires automatically: it
# watches Bash output for the audit warning and asks for the readme-documentarian
# agent. Report on it rather than on the retired post-commit hook.
if [ -f "$SCRIPT_DIR/hooks/doc-audit-trigger.sh" ]; then
  if grep -q 'doc-audit-trigger.sh' "$SCRIPT_DIR/settings.json"; then
    echo "✓ PostToolUse audit trigger is wired in settings.json"
  else
    echo "⚠️  doc-audit-trigger.sh exists but settings.json does not reference it"
  fi
else
  echo "⚠️  doc-audit-trigger.sh not found (manual audits still work)"
fi

if [ -f "$PROJECT_ROOT/.git/hooks/post-commit" ]; then
  echo "ℹ️  A post-commit hook is installed; the audit no longer uses one."
fi

echo ""

# Check CLAUDE.md for documentation section
if grep -q "Documentation Auditing" "$PROJECT_ROOT/CLAUDE.md"; then
  echo "✓ CLAUDE.md updated with audit documentation"
else
  echo "⚠️  CLAUDE.md does not have Documentation Auditing section"
fi

echo ""

if [ $MISSING -eq 0 ]; then
  echo "✅ System is fully installed and ready!"
  echo ""
  echo "Nothing audits on commit; the audit is manual. Run one of:"
  echo ""
  echo "Manual audit:"
  echo "  bash .claude/audit-docs.sh HEAD"
  echo ""
  echo "Status check:"
  echo "  bash .claude/check-docs.sh 3"
else
  echo "❌ System has $MISSING missing file(s)"
  echo ""
  echo "To fix, run:"
  echo "  bash .claude/install-hooks.sh"
fi

echo ""
