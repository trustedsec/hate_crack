"""Guards against committing cracked-plaintext artifacts to a public repo.

hate_crack writes hashcat `--debug-mode 4` logs for every rule-based attack
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
# the project's local dev-notes file): these paths were purged from git
# history on 2026-07-25 and are gitignored. Shipped files must not cite
# them — an outside contributor following such a pointer finds nothing.
UNPUBLISHED_PATH_REFERENCES = (
    "CLAUDE.md",
    ".claude/",
    "docs/plans/",
    "docs/superpowers/",
)

# Narrow, explicit exemptions. Do not widen these (e.g. to all of tests/) —
# that would defeat the point of the guard.
UNPUBLISHED_PATH_REFERENCE_EXEMPTIONS = (
    # Documents the 2026-07-25 removal of these very paths; a changelog that
    # cannot name what it removed is useless.
    "CHANGELOG.md",
    # Builds a fixture git repo containing a literal CLAUDE.md to reproduce the
    # 2026-07-25 history purge and assert the upgrade path survives it.
    "tests/test_upgrade_real_git.py",
    # Lists these paths so git ignores them; that's the mechanism that keeps
    # them unpublished, not a dead-end pointer for a reader.
    ".gitignore",
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


def test_no_tracked_file_references_unpublished_dev_paths():
    tracked = _git("ls-files").stdout.splitlines()
    candidates = [p for p in tracked if p not in UNPUBLISHED_PATH_REFERENCE_EXEMPTIONS]

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
        if any(ref in text for ref in UNPUBLISHED_PATH_REFERENCES):
            offenders.append(path)

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
