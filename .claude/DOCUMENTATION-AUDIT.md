# Documentation Audit System

This project includes an automated documentation audit system that ensures README files and other documentation stay in sync with code changes.

## Overview

The system consists of:

1. **Audit Script** (`.claude/audit-docs.sh`) - Analyzes git commits and flags when documentation may need updating
2. **Settings File** (`.claude/settings.json`) - Configuration for documentation audit behavior
3. **Hook Installer** (`.claude/install-hooks.sh`) - Sets up automatic audits on each commit
4. **This Guide** - Documentation for using the system

## Quick Start

Install automatic post-commit documentation audits:

```bash
bash .claude/install-hooks.sh
```

This installs a git hook that will run the audit script after every commit.

## Manual Audits

Run a documentation audit for any commit:

```bash
bash .claude/audit-docs.sh HEAD          # Audit the last commit
bash .claude/audit-docs.sh <commit_sha>  # Audit a specific commit
```

## How It Works

### Automatic Audits (with hook installed)

When you run `git commit`:

1. Git creates the commit
2. The `.git/hooks/post-commit` hook runs automatically
3. The audit script checks what files changed
4. If code changed but docs didn't, you get a warning message

Example output:

```
[Documentation Audit] Analyzing changes in HEAD...
[Documentation Audit] Changed files:
  hate_crack/attacks.py
  hate_crack/main.py
[Documentation Audit] Code/config files detected
[Documentation Audit] WARNING: Code changed but documentation was not updated
[Documentation Audit] This is a reminder to review and update README.md if needed

Changed code files:
  hate_crack/attacks.py
  hate_crack/main.py

To audit documentation manually, run:
  .claude/audit-docs.sh HEAD
```

### Manual Audits

When using Claude Code's `Edit` or `Write` tools on documentation, you can manually trigger an audit:

```bash
bash .claude/audit-docs.sh HEAD
```

This helps verify that your documentation updates match the code changes.

## What Gets Audited

The audit script checks for changes in:

- **Code files**: `*.py`, `pyproject.toml`, `Makefile`, `config.json`
- **Documentation files**: `README.md`, `*.md` in any directory, `CLAUDE.md`

The script will warn if code changes don't have corresponding documentation updates.

## Removing the Hook

If you want to stop automatic audits:

```bash
rm .git/hooks/post-commit
```

Or just delete the hook file directly. The audit script will continue to work for manual runs.

## Integration with Claude Code

When you make code changes in Claude Code, this system works with the Documentation Auditor role:

1. After committing code changes, the hook runs automatically
2. If docs need updating, it produces a clear warning
3. You can use Claude Code to read the changed files and update documentation as needed
4. Run the audit again to confirm documentation is in sync

## Philosophy

Documentation should:

- Always reflect the current state of the code
- Be updated when features are added, removed, or changed
- Stay in sync with real implementation details
- Serve as the source of truth for users

This audit system helps catch gaps where code changes aren't documented, ensuring users always have accurate guidance.

## Troubleshooting

### Hook doesn't seem to run

Check that the hook file exists and is executable:

```bash
ls -la .git/hooks/post-commit
# Should show: -rwxr-xr-x
```

If not executable, fix with:

```bash
chmod +x .git/hooks/post-commit
```

### Want to see the hook in action

Run a test commit with no actual changes:

```bash
git commit --allow-empty -m "test: trigger audit"
```

The audit script will run and show output.

## Files in This System

- `.claude/settings.json` - Configuration and metadata
- `.claude/audit-docs.sh` - Main audit script
- `.claude/install-hooks.sh` - Hook installation script
- `.claude/DOCUMENTATION-AUDIT.md` - This guide
