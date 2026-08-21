"""Tripwires on the agent-instruction surface published from ``.claude/``.

Publishing ``CLAUDE.md`` and ``.claude/`` on 2026-08-21 created an attack
surface this repo did not have while they were gitignored: a pull request can
now propose changes to files that a maintainer's coding agent *reads as
instructions*, and — in the case of hooks — *executes as code*. A hostile PR
does not need to touch ``hate_crack/`` at all. It can add a ``PostToolUse``
hook, redefine a subagent, or bury a directive in a skill, and the payload runs
in the reviewer's session rather than in CI.

**What these tests do and do not do.** They cannot detect a cleverly worded
instruction; natural language has no parser that settles intent, and anyone
claiming otherwise is selling something. What they do is remove the *quiet*
path. Every executable and instruction entry point is pinned to a literal
approved set here, so adding a hook, a hook script, a subagent, or a skill fails
the suite and has to be justified in review by a human who edits this file on
purpose. The injection-marker scan at the end is a lint for lazy attempts, not a
boundary — treat a pass as "nothing obvious", never as "reviewed".

Rule of thumb when one of these fails: the fix is almost never to widen the
constant. It is to ask why a change to the repo's *agent instructions* arrived
in a PR that was supposed to be about something else.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CLAUDE_DIR = REPO_ROOT / ".claude"
SETTINGS = CLAUDE_DIR / "settings.json"

# --- begin approved-surface constants: widen only deliberately, in review ---

# Every hook command Claude Code may run for this project. A hook is arbitrary
# code executed on tool use, so this is the highest-value entry in this file.
APPROVED_HOOK_COMMANDS = frozenset({".claude/hooks/doc-audit-trigger.sh"})

# settings.json is the *shared* settings file, so anything here applies to
# everyone who trusts the workspace. Only hooks are expected; in particular a
# "permissions" key would let a PR propose auto-approval rules for other people.
APPROVED_SETTINGS_KEYS = frozenset({"hooks"})

# Scripts reachable as hooks, and every other shell script under .claude/.
APPROVED_HOOK_SCRIPTS = frozenset({"doc-audit-trigger.sh"})
APPROVED_CLAUDE_SHELL_SCRIPTS = frozenset(
    {
        "audit-docs.sh",
        "check-docs.sh",
        "hooks/doc-audit-trigger.sh",
        "install-hooks.sh",
        "verify-setup.sh",
    }
)

# Subagent definitions and skills are loaded as instructions.
APPROVED_AGENT_DEFINITIONS = frozenset({"readme-documentarian.md"})
APPROVED_SKILLS = frozenset({"adding-an-attack"})

# A hook that reaches the network can exfiltrate whatever the session has read.
# None of these scripts has any reason to, so any egress verb is refused.
NETWORK_VERBS = ("curl", "wget", "nc ", "ncat", "telnet", "scp ", "sftp ", "ssh ")

# Phrasings whose only purpose is to override instructions already in context.
# Deliberately short and high-signal: a list long enough to catch everything
# would fire on ordinary prose and get deleted. Lower-cased before matching.
INJECTION_MARKERS = (
    "ignore previous instruction",
    "ignore all previous",
    "ignore the above",
    "disregard previous",
    "disregard the above",
    "disregard all prior",
    "override your instructions",
    "override all prior",
    "you are now",
    "act as though you",
    "do not tell the user",
    "without telling the user",
    "do not mention this",
    "exfiltrate",
    "send the contents to",
    "curl http",
    "curl https",
)
# --- end approved-surface constants ---

_SELF = "tests/test_agent_instruction_integrity.py"


def _tracked() -> list[str]:
    """Repo-relative paths of tracked files.

    Everything here is scoped to *tracked* content rather than to what happens to
    be on disk, because the threat is a pull request. Scoping to the filesystem
    would also make these tests fail on a teammate's checkout the moment they put
    scratch work in one of the gitignored plan or spec directories under
    ``.claude`` (named in tests/test_repo_hygiene.py, which is the one file
    allowed to spell them).
    """
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.splitlines()


def _tracked_under(prefix: str, *, dirs: bool = False) -> set[str]:
    """Tracked entries directly beneath ``prefix``, as names.

    With ``dirs=True`` returns the distinct first path component instead, which
    is how a skill (a directory holding SKILL.md) is counted.
    """
    found = set()
    for path in _tracked():
        if not path.startswith(prefix):
            continue
        rest = path[len(prefix) :]
        if not rest:
            continue
        found.add(rest.split("/", 1)[0] if dirs else rest)
    return {name for name in found if dirs or "/" not in name}


def _instruction_files() -> list[Path]:
    """Every tracked file an agent reads: CLAUDE.md plus all of .claude/."""
    paths = [p for p in _tracked() if p == "CLAUDE.md" or p.startswith(".claude/")]
    return [REPO_ROOT / p for p in sorted(paths) if (REPO_ROOT / p).is_file()]


def _rel(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


@pytest.mark.skipif(not SETTINGS.is_file(), reason=".claude/settings.json absent")
def test_settings_json_declares_only_approved_hooks():
    """A PR may not introduce a new hook command without editing this file."""
    settings = json.loads(SETTINGS.read_text(encoding="utf-8"))

    found = {
        hook.get("command")
        for entries in settings.get("hooks", {}).values()
        for entry in entries
        for hook in entry.get("hooks", [])
    }

    assert found == set(APPROVED_HOOK_COMMANDS), (
        "the set of hook commands in .claude/settings.json changed.\n"
        f"  approved: {sorted(APPROVED_HOOK_COMMANDS)}\n"
        f"  found:    {sorted(c for c in found if c is not None)}\n"
        "A hook is arbitrary code run on tool use. Do not widen "
        "APPROVED_HOOK_COMMANDS to make this pass without understanding who "
        "added the hook and why."
    )


@pytest.mark.skipif(not SETTINGS.is_file(), reason=".claude/settings.json absent")
def test_settings_json_grants_no_shared_permissions():
    """`permissions` in the shared settings file applies to every collaborator.

    Kept separate from the hook test so the failure message can say what is
    actually at stake: this is the file that would hand out auto-approval.
    """
    settings = json.loads(SETTINGS.read_text(encoding="utf-8"))
    unexpected = sorted(set(settings) - set(APPROVED_SETTINGS_KEYS))

    assert unexpected == [], (
        f"unexpected top-level keys in .claude/settings.json: {unexpected}. "
        "A 'permissions' block here proposes allow rules for everyone who "
        "trusts this workspace, not just its author. Personal rules belong in "
        "settings.local.json, which is gitignored."
    )


def test_hook_scripts_are_the_approved_set():
    found = _tracked_under(".claude/hooks/")
    assert found == set(APPROVED_HOOK_SCRIPTS), (
        f"scripts under .claude/hooks/ changed.\n"
        f"  approved: {sorted(APPROVED_HOOK_SCRIPTS)}\n"
        f"  found:    {sorted(found)}"
    )


def test_agent_definitions_are_the_approved_set():
    found = _tracked_under(".claude/agents/")
    assert found == set(APPROVED_AGENT_DEFINITIONS), (
        f"subagent definitions under .claude/agents/ changed.\n"
        f"  approved: {sorted(APPROVED_AGENT_DEFINITIONS)}\n"
        f"  found:    {sorted(found)}\n"
        "A subagent definition carries its own system prompt and tool list."
    )


def test_skills_are_the_approved_set():
    found = _tracked_under(".claude/skills/", dirs=True)
    assert found == set(APPROVED_SKILLS), (
        f"skills under .claude/skills/ changed.\n"
        f"  approved: {sorted(APPROVED_SKILLS)}\n"
        f"  found:    {sorted(found)}\n"
        "A skill is loaded as instructions when its trigger matches."
    )


def test_no_unapproved_shell_script_under_claude():
    """A new .sh anywhere under .claude/ is a new execution vector."""
    found = {
        path[len(".claude/") :]
        for path in _tracked()
        if path.startswith(".claude/") and path.endswith(".sh")
    }
    assert found == set(APPROVED_CLAUDE_SHELL_SCRIPTS), (
        f"shell scripts under .claude/ changed.\n"
        f"  approved: {sorted(APPROVED_CLAUDE_SHELL_SCRIPTS)}\n"
        f"  found:    {sorted(found)}"
    )


def test_claude_shell_scripts_make_no_network_calls():
    """None of these needs the network; a hook that gained one could exfiltrate."""
    offenders = []
    scripts = [
        REPO_ROOT / path
        for path in _tracked()
        if path.startswith(".claude/") and path.endswith(".sh")
    ]
    for script in sorted(scripts):
        text = script.read_text(encoding="utf-8", errors="replace")
        for line_no, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for verb in NETWORK_VERBS:
                if verb in stripped:
                    offenders.append(f"{_rel(script)}:{line_no}: {verb.strip()}")
    assert offenders == [], (
        "network egress in a .claude/ shell script: "
        + repr(offenders)
        + ". These scripts audit local git state and must not reach the network."
    )


def test_no_instruction_file_carries_injection_markers():
    """Lint for the crude form of the attack. Not a boundary -- see the module docstring.

    This file names the markers, so it exempts itself; every other instruction
    file is scanned.
    """
    offenders = []
    for path in _instruction_files():
        rel = _rel(path)
        if rel == _SELF:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        lowered = text.lower()
        hits = [marker for marker in INJECTION_MARKERS if marker in lowered]
        if hits:
            offenders.append(f"{rel}: {hits}")

    assert offenders == [], (
        "instruction-override phrasing in an agent-instruction file: "
        + repr(offenders)
        + ". Confirm who added it and why before touching INJECTION_MARKERS."
    )


def test_the_injection_scan_actually_covers_the_published_surface():
    """Guards the guard: an empty or CLAUDE.md-only file list would pass vacuously."""
    scanned = {_rel(p) for p in _instruction_files()}

    assert "CLAUDE.md" in scanned, "CLAUDE.md is not being scanned"
    assert ".claude/settings.json" in scanned, "settings.json is not being scanned"
    assert any(p.startswith(".claude/skills/") for p in scanned), (
        "no skill file is being scanned"
    )
    assert any(p.startswith(".claude/agents/") for p in scanned), (
        "no agent definition is being scanned"
    )
    assert len(scanned) >= 8, (
        f"only {len(scanned)} instruction files found; the scan has probably "
        "lost its target directory"
    )
