#!/bin/bash
# Install Git Hooks for Documentation Auditing
# This script sets up a post-commit hook that automatically checks if
# documentation needs updating after each commit.
#
# Usage: .claude/install-hooks.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
GIT_HOOKS_DIR="$PROJECT_ROOT/.git/hooks"

if [ ! -d "$GIT_HOOKS_DIR" ]; then
  echo "Error: Not in a git repository"
  exit 1
fi

# Create post-commit hook
POST_COMMIT_HOOK="$GIT_HOOKS_DIR/post-commit"

cat > "$POST_COMMIT_HOOK" << 'EOF'
#!/bin/bash
set -euo pipefail
# Auto-generated: Post-commit hook for documentation auditing
# Remove this file to disable automatic documentation audits.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
AUDIT_SCRIPT="$PROJECT_ROOT/.claude/audit-docs.sh"

if [ -f "$AUDIT_SCRIPT" ]; then
  bash "$AUDIT_SCRIPT" HEAD
fi
EOF

chmod +x "$POST_COMMIT_HOOK"

echo "✓ Post-commit hook installed at $POST_COMMIT_HOOK"
echo ""
echo "Documentation audits will now run automatically after each commit."
echo "To remove this behavior, delete: $POST_COMMIT_HOOK"
echo ""
echo "Alternatively, you can run audits manually:"
echo "  bash .claude/audit-docs.sh HEAD"
