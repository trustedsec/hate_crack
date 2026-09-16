#!/bin/bash
# PostToolUse hook: detects the documentation audit warning from prek post-commit
# hooks and injects a prompt for Claude to invoke the readme-documentarian agent.
set -euo pipefail

input=$(cat)

stdout=$(echo "$input" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    resp = d.get('tool_response', {})
    if isinstance(resp, dict):
        print(resp.get('stdout', ''))
    else:
        print(str(resp))
except Exception:
    pass
")

# Claude Code reads additionalContext only from inside hookSpecificOutput, and
# only when that object names its event. A top-level additionalContext parses
# fine and is then dropped as an unrecognized key - no error, no stderr - which
# left this whole audit silently disarmed. tests/test_doc_audit_hook.py pins the
# envelope so it cannot regress quietly again.
if echo "$stdout" | grep -q '\[Documentation Audit\].*documentation was not updated'; then
    printf '{"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": "The documentation audit flagged that code changed but README.md was not updated. Invoke the readme-documentarian agent now to review the recent changes and update the documentation."}}\n'
fi
