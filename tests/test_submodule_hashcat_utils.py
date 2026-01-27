import os
import subprocess
import shutil


def _is_hashcat_utils_empty(path):
    if not os.path.isdir(path):
        return True
    entries = [e for e in os.listdir(path) if e not in (".git", ".gitignore")]
    return len(entries) == 0


def test_hashcat_utils_submodule_initialized():
    if shutil.which("git") is None:
        import pytest

        pytest.skip("git not available")

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    submodule_path = os.path.join(repo_root, "hashcat-utils")

    if _is_hashcat_utils_empty(submodule_path):
        result = subprocess.run(
            ["git", "submodule", "update", "--init", "--recursive"],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            "git submodule update failed: "
            f"stdout={result.stdout} stderr={result.stderr}"
        )

    assert not _is_hashcat_utils_empty(submodule_path), (
        "hashcat-utils submodule is empty. "
        "Run: git submodule update --init --recursive"
    )
