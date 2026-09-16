"""Guards the JSON contract of .claude/hooks/doc-audit-trigger.sh.

The hook is the last link in the documentation-audit chain: ``audit-docs.sh``
prints a warning, a Claude Code ``PostToolUse`` hook on ``Bash`` greps every
tool result for it, and on a match the hook returns JSON asking Claude to invoke
the ``readme-documentarian`` agent. ``test_doc_audit_parity.py`` covers the
detection half; this file covers the emission half.

It exists because the emission half was silently broken. The hook returned a
*top-level* ``additionalContext`` key, but Claude Code reads that key only from
inside ``hookSpecificOutput``, and only when that object also carries a
``hookEventName``. An unrecognized top-level key is dropped without an error, a
non-zero exit, or anything on stderr — so the whole audit system looked like a
hook that simply never fired. Nothing failed loudly, which is exactly why this
needs a test rather than a comment.

The shape asserted here is the one the CLI documents:

    {"hookSpecificOutput": {"hookEventName": "PostToolUse",
                            "additionalContext": "..."}}

Note this pins the *envelope*, not the prose inside ``additionalContext`` —
rewording the instruction to Claude is fine, moving or renaming the keys is not.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

HOOK = (
    Path(__file__).resolve().parents[1] / ".claude" / "hooks" / "doc-audit-trigger.sh"
)

# The exact string audit-docs.sh prints when a commit changed code but no docs.
# Kept verbatim rather than imported, so that rewording the script's WARNING
# line fails here instead of silently disarming the trigger.
FLAGGED_STDOUT = (
    "\033[1;33m[Documentation Audit]\033[0m WARNING: Code changed but "
    "documentation was not updated"
)

CLEAN_STDOUT = "\033[0;32m[Documentation Audit]\033[0m Changed files:\n  README.md"


def _run_hook(tool_response: object) -> str:
    payload = json.dumps({"tool_name": "Bash", "tool_response": tool_response})
    proc = subprocess.run(
        ["bash", str(HOOK)],
        input=payload,
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout


def test_emits_post_tool_use_envelope_when_flagged() -> None:
    """A flagged audit must produce JSON Claude Code actually reads.

    A top-level ``additionalContext`` parses fine and is then discarded as an
    unrecognized key, so asserting merely "some JSON with additionalContext in
    it somewhere" would pass against the broken version.
    """
    out = _run_hook({"stdout": FLAGGED_STDOUT})
    doc = json.loads(out)

    assert "additionalContext" not in doc, (
        "additionalContext must live under hookSpecificOutput; Claude Code "
        "ignores it at the top level"
    )
    specific = doc["hookSpecificOutput"]
    assert specific["hookEventName"] == "PostToolUse"
    assert "readme-documentarian" in specific["additionalContext"]


def test_silent_when_audit_did_not_flag() -> None:
    """No warning in the tool output means no context injected."""
    assert _run_hook({"stdout": CLEAN_STDOUT}).strip() == ""


@pytest.mark.parametrize(
    "tool_response",
    [
        pytest.param({}, id="no_stdout_key"),
        pytest.param("plain string response", id="non_dict_response"),
        pytest.param({"stdout": ""}, id="empty_stdout"),
    ],
)
def test_tolerates_tool_responses_without_a_warning(tool_response: object) -> None:
    """The hook runs on *every* Bash call, so odd payloads must not break it.

    ``set -euo pipefail`` plus a non-zero grep makes silence the easy thing to
    get wrong here: a hook that exits non-zero on ordinary tool output would
    surface an error on unrelated commands.
    """
    assert _run_hook(tool_response).strip() == ""
