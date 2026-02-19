#!/bin/bash
# Verify Documentation Audit System Setup
# Run this to confirm everything is installed and working correctly.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Documentation Audit System - Verification"
echo "=========================================="
echo ""

# Check if in git repo
if [ ! -d "$PROJECT_ROOT/.git" ]; then
  echo "❌ Not in a git repository"
  exit 1
fi

echo "✓ Git repository found"

# Check for required files
REQUIRED_FILES=(
  "$SCRIPT_DIR/settings.json"
  "$SCRIPT_DIR/audit-docs.sh"
  "$SCRIPT_DIR/install-hooks.sh"
  "$SCRIPT_DIR/check-docs.sh"
  "$SCRIPT_DIR/DOCUMENTATION-AUDIT.md"
  "$PROJECT_ROOT/.git/hooks/post-commit"
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

# Check hook permissions
if [ -f "$PROJECT_ROOT/.git/hooks/post-commit" ]; then
  if [ -x "$PROJECT_ROOT/.git/hooks/post-commit" ]; then
    echo "✓ Post-commit hook is executable"
  else
    echo "⚠️  Post-commit hook exists but is not executable"
    echo "   Fixing permissions..."
    chmod +x "$PROJECT_ROOT/.git/hooks/post-commit"
    echo "✓ Fixed: hook is now executable"
  fi
else
  echo "❌ Post-commit hook not found"
  MISSING=$((MISSING + 1))
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
  echo "Quick test:"
  echo "  git commit --allow-empty -m 'test: trigger audit hook'"
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
