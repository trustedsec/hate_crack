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
SECRET_ARTIFACT_PATTERNS = ("hashcat_debug*.log", "*.pot", "*.potfile")


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
    ],
)
def test_gitignore_covers_debug_logs(pristine_checkout, path):
    # check-ignore exits 0 only when a rule matches.
    result = subprocess.run(
        ["git", "check-ignore", "-q", "--no-index", "--", path],
        cwd=pristine_checkout,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"{path} is not covered by the tracked .gitignore"
