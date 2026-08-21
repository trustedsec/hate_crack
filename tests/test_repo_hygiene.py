"""Guards against committing cracked-plaintext artifacts to a public repo.

hate_crack writes hashcat `--debug-mode 5` logs for every rule-based attack
without being asked (`_add_debug_mode_for_rules`), and each line pairs a rule
with the plaintext it produced. `hcatDebugLogPath` used to default to the
relative `./hashcat_debug`, so a session launched from a checkout dropped them
straight into the working tree. One such log was tracked on `main` before these
guards existed; it happened to be zero bytes, so nothing leaked.

These run real git commands rather than mocking subprocess: the thing under test
is what git actually tracks and ignores, which a mocked call cannot observe.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# Artifacts that can carry cracked plaintext or hashes.
SECRET_ARTIFACT_PATTERNS = (
    "hashcat_debug*.log",
    "*.pot",
    "*.potfile",
    # `.out` is a hash:plaintext list, `.passwords` is pure plaintext, and the
    # rest carry hashes or intermediate cracks.
    "*.out",
    "*.passwords",
    "*.working",
    "*.combined",
    "*.nt",
    "*.lm",
    "*.cracked",
    "*.xlsx",
)

# Per-attack scratch directories that hold basewords and candidate lists.
SECRET_ARTIFACT_DIR_SUFFIXES = (".rosetta/", ".spoonman/", ".llm_patterns/")


def _git(*args):
    return subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


pytestmark = pytest.mark.skipif(
    shutil.which("git") is None or not (REPO_ROOT / ".git").exists(),
    reason="not a git checkout",
)


def test_default_debug_log_path_is_absolute_and_outside_any_checkout():
    """The shipped default must not resolve relative to the launch directory.

    A relative default put the logs wherever the operator happened to `cd`,
    which for anyone running hate_crack from a clone meant inside the repo. It
    also split the logs across directories, so the Rosetta picker showed a
    different set depending on where the tool was started.
    """
    example = json.loads((REPO_ROOT / "config.json.example").read_text())
    raw = example["hcatDebugLogPath"]
    resolved = Path(os.path.expanduser(raw))

    assert not raw.startswith("."), f"debug log default is checkout-relative: {raw}"
    assert resolved.is_absolute(), f"debug log default is not absolute: {raw}"
    assert REPO_ROOT not in resolved.parents and resolved != REPO_ROOT, (
        f"debug log default resolves inside the checkout: {resolved}"
    )


def test_no_secret_artifacts_are_tracked():
    tracked = _git("ls-files", "--", *SECRET_ARTIFACT_PATTERNS).stdout.split()
    assert tracked == [], (
        f"tracked files may contain cracked plaintext: {tracked}. "
        "Remove with `git rm --cached` and confirm .gitignore covers them."
    )


def test_no_env_file_is_tracked():
    """`.env` holds the API keys and Pushover credentials that config.json used
    to, and hate_crack creates it at first startup rather than waiting to be
    asked -- so a populated one exists in the checkout of anyone who has run the
    tool. `detect-private-key` is this repo's only secret-scanning hook and CI
    has none at all, so a tracked `.env` would not be caught anywhere else.
    `.env.example` is tracked on purpose and must not trip this.
    """
    tracked = _git("ls-files", "--", ".env", ".env.*", "**/.env").stdout.split()
    offenders = [p for p in tracked if not p.endswith(".example")]
    assert offenders == [], (
        f"tracked files may contain API keys: {offenders}. "
        "Remove with `git rm --cached` and confirm .gitignore covers them."
    )


def test_no_tracked_file_lives_in_a_debug_log_directory():
    tracked = _git("ls-files").stdout.splitlines()
    offenders = [p for p in tracked if "hashcat_debug/" in p]
    assert offenders == [], f"debug-log directory has tracked contents: {offenders}"


def test_no_tracked_file_lives_in_an_attack_scratch_directory():
    tracked = _git("ls-files").stdout.splitlines()
    offenders = [
        p for p in tracked if any(s in p for s in SECRET_ARTIFACT_DIR_SUFFIXES)
    ]
    assert offenders == [], (
        f"attack scratch directory has tracked contents: {offenders}"
    )


# --- begin guard constants: these must name the forbidden paths ---
# Unpublished local development aids (see the Publication Boundary section of
# CLAUDE.md): these paths are gitignored, so a shipped file must not cite them —
# an outside contributor following such a pointer finds nothing.
#
# CLAUDE.md and .claude/ were removed from this tuple on 2026-08-21: both are
# now published, so citing them is not a dead-end pointer any more. That is also
# why this comment can name CLAUDE.md directly where it used to say "the
# project's local dev-notes file".
UNPUBLISHED_PATH_REFERENCES = (
    ".claude/settings.local.json",
    ".claude/plans/",
    ".claude/specs/",
    "docs/plans/",
    "docs/superpowers/",
)

# Unpublished *tooling*, referenced by name rather than by path. The skill
# library lives in docs/superpowers/, which is not published, so a tracked file
# telling a reader to "use superpowers:brainstorming" sends them after something
# this repo does not ship — the same dead end as citing the directory, in a shape
# the path check above cannot see, because the namespace contains no path.
#
# Found by review on 2026-08-21: two .claude/plans/ files carried a "REQUIRED
# SUB-SKILL: Use superpowers:subagent-driven-development" directive and would
# have been published with it.
UNPUBLISHED_TOOLING_REFERENCES = ("superpowers:",)

# Deliberately a *separate*, shorter list than the path exemptions below.
# CLAUDE.md is exempt from the path guard because it defines the boundary and has
# to name it — but it is exactly the kind of file this tooling guard exists to
# police, so exempting it from both would leave the main target unguarded. It
# therefore describes the skill library in prose without spelling the namespace.
UNPUBLISHED_TOOLING_REFERENCE_EXEMPTIONS = (
    # Has to name what it changed, same as for the path guard.
    "CHANGELOG.md",
)

# Narrow, explicit exemptions. Do not widen these (e.g. to all of tests/) —
# that would defeat the point of the guard.
UNPUBLISHED_PATH_REFERENCE_EXEMPTIONS = (
    # Documents the 2026-07-25 removal of these very paths, and the 2026-08-21
    # republication of two of them; a changelog that cannot name what it changed
    # is useless.
    "CHANGELOG.md",
    # Became tracked on 2026-08-21, and its Publication Boundary section is the
    # prose definition of this very list. It has to name the paths it forbids —
    # the same reasoning that exempts .gitignore and the guard script. This is
    # an exemption from *citing* the paths, not a licence to add content that
    # belongs in them.
    "CLAUDE.md",
    # Lists these paths so git ignores them; that's the mechanism that keeps
    # them unpublished, not a dead-end pointer for a reader.
    ".gitignore",
    # Same reasoning as .gitignore: this script's whole job is to refuse a
    # commit that touches these paths, so it has to name them. It is the
    # enforcement mechanism, not a pointer at missing content.
    ".github/scripts/check-publication-boundary.sh",
    # Executes that script against throwaway repos and asserts the refusal, so
    # it must name the paths it stages. Confined to its own guard-constants
    # block, mirroring this file's convention.
    "tests/test_commit_guards.py",
)
# --- end guard constants ---

# This test file legitimately names the forbidden strings, but only inside the
# marker block above. Everywhere else in this file is scanned like any other
# tracked file, so a stray citation added elsewhere (a new test's docstring, a
# new fixture) is still caught.
_SELF_PATH = "tests/test_repo_hygiene.py"
_GUARD_BLOCK_START = (
    "# --- begin guard constants: these must name the forbidden paths ---"
)
_GUARD_BLOCK_END = "# --- end guard constants ---"


def _strip_self_exemption_block(text: str) -> str:
    """Remove the marked constants block from this file's own text.

    Matches markers by whole-line equality, not substring, so the constant
    definitions below (``_GUARD_BLOCK_START = "..."`` /
    ``_GUARD_BLOCK_END = "..."``) — which contain the marker text but are not
    equal to it as a line — cannot be mistaken for the real markers.

    Requires exactly one start line and exactly one end line, with the end
    strictly after the start, and raises a marker-specific ``ValueError``
    otherwise. That makes a renamed/deleted/duplicated marker fail this test
    loudly instead of silently stripping the wrong range (too little, too
    much, or nothing).
    """
    lines = text.splitlines(keepends=True)
    start_idxs = [
        i for i, line in enumerate(lines) if line.strip() == _GUARD_BLOCK_START
    ]
    end_idxs = [i for i, line in enumerate(lines) if line.strip() == _GUARD_BLOCK_END]

    if len(start_idxs) != 1:
        raise ValueError(
            f"expected exactly one guard-block start marker, found {len(start_idxs)}"
        )
    if len(end_idxs) != 1:
        raise ValueError(
            f"expected exactly one guard-block end marker, found {len(end_idxs)}"
        )
    start_idx, end_idx = start_idxs[0], end_idxs[0]
    if end_idx <= start_idx:
        raise ValueError("guard-block end marker does not follow start marker")

    return "".join(lines[:start_idx] + lines[end_idx + 1 :])


def _tracked_files_referencing(
    needles: tuple[str, ...], exemptions: tuple[str, ...]
) -> list[str]:
    """Tracked files whose text contains any of ``needles``.

    Shared by the path and tooling guards so both apply the same exemption list
    and the same self-exemption stripping. A second hand-rolled copy of this
    scan would be free to drift out of step with the first.
    """
    tracked = _git("ls-files").stdout.splitlines()
    candidates = [p for p in tracked if p not in exemptions]

    offenders = []
    for path in candidates:
        full = REPO_ROOT / path
        if not full.is_file():
            continue
        try:
            text = full.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if path == _SELF_PATH:
            # Markers are required, exactly-once, and ordered: see
            # _strip_self_exemption_block's docstring for why a missing,
            # duplicated, or reordered marker must fail this test loudly.
            text = _strip_self_exemption_block(text)
        if any(ref in text for ref in needles):
            offenders.append(path)
    return offenders


def test_no_tracked_file_references_unpublished_tooling():
    """A shipped file must not send the reader after tooling this repo lacks.

    Distinct from the path guard below: the forbidden strings here are skill
    *namespaces*, which contain no path and so are invisible to a path-substring
    check. They are spelled only inside the guard-constants block above, per
    this file's convention -- naming one in this docstring would make the test
    flag itself, as it did when this guard was first written.
    """
    offenders = _tracked_files_referencing(
        UNPUBLISHED_TOOLING_REFERENCES, UNPUBLISHED_TOOLING_REFERENCE_EXEMPTIONS
    )

    assert offenders == [], (
        "tracked files reference unpublished tooling: "
        + repr(offenders)
        + ". See UNPUBLISHED_TOOLING_REFERENCES in this file. Either drop the "
        "reference or describe the step in prose a contributor can follow "
        "without the skill library."
    )


def test_no_tracked_file_references_unpublished_dev_paths():
    offenders = _tracked_files_referencing(
        UNPUBLISHED_PATH_REFERENCES, UNPUBLISHED_PATH_REFERENCE_EXEMPTIONS
    )

    assert offenders == [], (
        "tracked files reference unpublished dev-only paths: "
        + repr(offenders)
        + ". See UNPUBLISHED_PATH_REFERENCES in this file for what is forbidden "
        "and why."
    )


@pytest.fixture(scope="module")
def pristine_checkout(tmp_path_factory):
    """An empty repo holding only the tracked .gitignore.

    check-ignore run against this checkout would also honour .git/info/exclude,
    which is local-only and does not clone. This repo's exclude file happens to
    carry a broad `*.log`, which would mask a missing .gitignore rule here while
    leaving every other contributor unprotected. Isolating to a fresh repo tests
    what an outside clone actually gets.
    """
    root = tmp_path_factory.mktemp("pristine")
    subprocess.run(
        ["git", "init", "-q"], cwd=root, check=True, capture_output=True, text=True
    )
    shutil.copyfile(REPO_ROOT / ".gitignore", root / ".gitignore")
    return root


@pytest.mark.parametrize(
    "path",
    [
        "hashcat_debug/hashcat_debug_example.log",
        "hashcat_debug/anything_at_all",
        "hashcat_debug_example.log",
        "some/nested/dir/hashcat_debug_example.log",
        # Cracked-plaintext session artifacts. These were covered only by
        # .git/info/exclude, which does not clone, so every other contributor's
        # checkout would stage them on `git add -A`.
        "hashes.txt.out",
        "hashes.txt.passwords",
        "hashes.txt.working",
        "hashes.txt.combined",
        "hashes.txt.nt",
        "hashes.txt.lm",
        "hashes.txt.lm.cracked",
        "hashes.txt.nt.out",
        "cracked.xlsx",
        "hashcat.potfile",
        "hashcat.pot",
        # The .env that replaced config.json, and its backup spellings.
        ".env",
        ".env.bak",
        ".env.bak.20260730",
        ".env.20260730.bak",
        ".env.orig",
        ".env.save",
        ".env~",
        "hate_crack/.env",
        "some/nested/dir/.env",
        "some/nested/dir/hashes.txt.out",
        # Scratch directories, matched by their contents.
        "hashes.txt.rosetta/basewords.txt",
        "hashes.txt.spoonman/candidates.txt",
        "hashes.txt.llm_patterns/patterns.rule",
    ],
)
def test_gitignore_covers_cracked_plaintext_artifacts(pristine_checkout, path):
    # check-ignore exits 0 only when a rule matches.
    result = subprocess.run(
        ["git", "check-ignore", "-q", "--no-index", "--", path],
        cwd=pristine_checkout,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"{path} is not covered by the tracked .gitignore"


def test_gitignore_does_not_swallow_the_tracked_env_example(pristine_checkout):
    """`.env.example` is generated from schema defaults, holds no values, and is
    meant to be tracked. A broad `.env*` rule would silently un-track it.
    """
    result = subprocess.run(
        ["git", "check-ignore", "-q", "--no-index", "--", ".env.example"],
        cwd=pristine_checkout,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0, ".env.example must not be gitignored"
