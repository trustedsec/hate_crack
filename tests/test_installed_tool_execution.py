"""
Tests for hate_crack execution when installed as a uv tool.
Verifies that the tool can find assets from any working directory.
"""

import subprocess
import os
import sys
import tempfile
import pytest


# Resolve the console script belonging to the interpreter running the tests
# rather than taking whatever "hate_crack" is first on PATH: an unrelated
# install elsewhere on the system would otherwise be the thing under test.
ENTRY_POINT = os.path.join(os.path.dirname(sys.executable), "hate_crack")


@pytest.mark.skipif(
    not os.path.exists(ENTRY_POINT),
    reason=f"hate_crack console script not present at {ENTRY_POINT} "
    "(run 'make install' first)",
)
class TestInstalledToolExecution:
    """Test suite for execution of installed hate_crack tool."""

    def test_help_from_home_directory(self):
        """Test that --help works when run from home directory."""
        home_dir = os.path.expanduser("~")
        result = subprocess.run(
            [ENTRY_POINT, "--help"],
            cwd=home_dir,
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert result.returncode == 0
        assert "usage: hate_crack" in result.stdout
        assert "Hashcat automation and wordlist management tool" in result.stdout

    def test_help_from_tmp_directory(self):
        """Test that --help works when run from /tmp directory."""
        result = subprocess.run(
            [ENTRY_POINT, "--help"],
            cwd="/tmp",
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert result.returncode == 0
        assert "usage: hate_crack" in result.stdout

    def test_help_from_temporary_directory(self):
        """Test that --help works when run from a temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [ENTRY_POINT, "--help"],
                cwd=tmpdir,
                capture_output=True,
                text=True,
                timeout=5,
            )
            assert result.returncode == 0
            assert "usage: hate_crack" in result.stdout

    def test_help_from_root_directory(self):
        """Test that --help works when run from root directory."""
        result = subprocess.run(
            [ENTRY_POINT, "--help"], cwd="/", capture_output=True, text=True, timeout=5
        )
        assert result.returncode == 0
        assert "usage: hate_crack" in result.stdout

    def test_debug_flag_from_home_directory(self):
        """Test that --debug flag works from home directory."""
        home_dir = os.path.expanduser("~")
        result = subprocess.run(
            [ENTRY_POINT, "--debug", "--help"],
            cwd=home_dir,
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert result.returncode == 0
        assert "usage: hate_crack" in result.stdout

    def test_no_errors_on_startup_from_home(self):
        """Test that there are no error messages on startup from home."""
        home_dir = os.path.expanduser("~")
        result = subprocess.run(
            [ENTRY_POINT, "--help"],
            cwd=home_dir,
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert result.returncode == 0
        # Check that there are no error-related messages
        assert "Error" not in result.stderr
        assert (
            "error" not in result.stdout.lower() or "error" in "usage"
        )  # "usage" might contain substring
        assert "not found" not in result.stderr.lower()
        assert "No such file" not in result.stderr

    def test_tool_creates_config_on_first_run(self):
        """Test that tool can run from non-repo directory (config already exists)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Run from temp directory (not a repo)
            result = subprocess.run(
                [ENTRY_POINT, "--help"],
                cwd=tmpdir,
                capture_output=True,
                text=True,
                timeout=5,
            )
            assert result.returncode == 0
            # Should successfully show help without errors
            assert "usage: hate_crack" in result.stdout

    def test_consecutive_runs_from_different_directories(self):
        """Test that tool works when called from multiple different directories."""
        directories = [
            os.path.expanduser("~"),
            "/tmp",
            "/",
        ]

        for directory in directories:
            result = subprocess.run(
                [ENTRY_POINT, "--help"],
                cwd=directory,
                capture_output=True,
                text=True,
                timeout=5,
            )
            assert result.returncode == 0, f"Failed when running from {directory}"
            assert "usage: hate_crack" in result.stdout

    def test_asset_resolution_from_various_locations(self):
        """Test that assets are correctly resolved from various working directories."""
        directories = [
            os.path.expanduser("~"),
            os.path.expanduser("~/Desktop")
            if os.path.exists(os.path.expanduser("~/Desktop"))
            else "/tmp",
            "/tmp",
        ]

        for directory in directories:
            if not os.path.exists(directory):
                continue

            result = subprocess.run(
                [ENTRY_POINT, "--help"],
                cwd=directory,
                capture_output=True,
                text=True,
                timeout=5,
            )
            # Should succeed from any directory
            assert result.returncode == 0, (
                f"Tool failed from {directory}. "
                f"stdout: {result.stdout}, stderr: {result.stderr}"
            )


def test_module_invocation_reports_tool_name_in_usage():
    """`python -m hate_crack` must not advertise itself as `__main__.py`.

    The console script gets the right name for free, because argparse derives
    it from the script basename; only module invocation needs an explicit
    prog=, so only this path guards against regressing it.
    """
    result = subprocess.run(
        [sys.executable, "-m", "hate_crack", "--help"],
        cwd=os.path.expanduser("~"),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert "usage: hate_crack" in result.stdout
    assert "__main__.py" not in result.stdout
