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

if echo "$stdout" | grep -q '\[Documentation Audit\].*documentation was not updated'; then
    printf '{"additionalContext": "The post-commit documentation audit flagged that code changed but README.md was not updated. Invoke the readme-documentarian agent now to review the recent changes and update the documentation."}\n'
fi
