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
