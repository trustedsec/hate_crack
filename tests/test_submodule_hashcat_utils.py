import os
import shutil

import pytest


def _is_hashcat_utils_empty(path):
    if not os.path.isdir(path):
        return True
    entries = [e for e in os.listdir(path) if e not in (".git", ".gitignore")]
    return len(entries) == 0


def test_hashcat_utils_submodule_populated():
    """Assert hashcat-utils submodule is populated.

    conftest.py's pytest_configure hook ensures this is initialized before
    collection (see issue #266). This test serves as a runtime check that
    the initialization was successful.

    In a git worktree, submodule directories might remain empty (expected
    behavior), so we skip the test in that case.
    """
    if shutil.which("git") is None:
        pytest.skip("git not available")

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    submodule_path = os.path.join(repo_root, "hashcat-utils")

    # In a git worktree, submodule directories might remain empty (expected
    # behavior — conftest already attempted to init them). Skip in that case.
    if _is_hashcat_utils_empty(submodule_path):
        pytest.skip(
            "hashcat-utils submodule not populated (likely a git worktree); "
            "run `git submodule update --init --recursive` in the main checkout"
        )

    # If we get here, submodule should be populated
    assert not _is_hashcat_utils_empty(submodule_path)
