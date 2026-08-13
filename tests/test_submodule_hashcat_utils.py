import os
import shutil

import pytest


def _is_hashcat_utils_empty(path):
    if not os.path.isdir(path):
        return True
    entries = [e for e in os.listdir(path) if e not in (".git", ".gitignore")]
    return len(entries) == 0


def test_hashcat_utils_submodule_populated():
    """Assert hashcat-utils submodule is populated after pytest_configure's init.

    conftest.py's pytest_configure hook initializes submodules before collection
    (see issue #266), so by the time a test runs, HashcatRosetta and hashcat-utils
    should always be populated. This test serves as a regression check: if this
    fails, it means the pytest_configure guard logic broke (e.g., reintroduced
    the isdir-vs-exists bug, or the opt-out env var is unexpectedly set).

    Only skip when there's genuinely no repo to work with (git unavailable, or
    no .git/.gitmodules at all — e.g., a tarball/non-git install).
    """
    if shutil.which("git") is None:
        pytest.skip("git not available")

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))

    # Skip only if not in a git repo at all (tarball install, etc.)
    has_git = os.path.exists(os.path.join(repo_root, ".git"))
    has_gitmodules = os.path.isfile(os.path.join(repo_root, ".gitmodules"))
    if not (has_git and has_gitmodules):
        pytest.skip("Not in a git repo with .gitmodules (non-repo install)")

    submodule_path = os.path.join(repo_root, "hashcat-utils")

    # If pytest_configure's guard is working, this submodule should be populated.
    # If it's empty, that's a regression of the guard logic.
    assert not _is_hashcat_utils_empty(submodule_path), (
        "hashcat-utils submodule is empty after pytest_configure ran. "
        "Check that the guard logic in conftest.py._ensure_submodules_initialized() "
        "is working correctly (e.g., os.path.exists check for .git, status check, etc.)"
    )
