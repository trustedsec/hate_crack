"""
Tests for tests._hashcat_oracle helper module.

Tests use fake executables (small shell scripts in tmp_path) to avoid depending
on a real hashcat installation.
"""

import pytest

from tests import _hashcat_oracle as oracle


class TestIsBackendFailure:
    """Test is_backend_failure detection of GPU/OpenCL kernel-build failures."""

    def test_clCreateProgramWithBinary_detected(self):
        """True when stderr contains clCreateProgramWithBinary."""
        stderr = "Some error\nclCreateProgramWithBinary: failed\n"
        assert oracle.is_backend_failure(stderr) is True

    def test_Kernel_and_build_failed_detected(self):
        """True when stderr contains both 'Kernel' and 'build failed'."""
        stderr = "Kernel compilation error: build failed\n"
        assert oracle.is_backend_failure(stderr) is True

    def test_Kernel_alone_not_detected(self):
        """False when only Kernel is present without 'build failed'."""
        stderr = "Kernel error occurred\n"
        assert oracle.is_backend_failure(stderr) is False

    def test_build_failed_alone_not_detected(self):
        """False when only 'build failed' is present without 'Kernel'."""
        stderr = "Something build failed\n"
        assert oracle.is_backend_failure(stderr) is False

    def test_empty_stderr(self):
        """False on empty stderr."""
        assert oracle.is_backend_failure("") is False

    def test_unrelated_stderr(self):
        """False on unrelated stderr."""
        assert oracle.is_backend_failure("Some unrelated error\n") is False

    def test_case_sensitive_Kernel(self):
        """The 'Kernel' check is case-sensitive (capital K)."""
        stderr = "kernel build failed\n"  # lowercase 'kernel'
        assert oracle.is_backend_failure(stderr) is False


class TestRunHashcat:
    """Test run_hashcat with fake executables."""

    def test_exit_0_with_stdout_returns_result(self, tmp_path):
        """Exit 0 with stdout returns the CompletedProcess."""
        fake_hashcat = tmp_path / "hashcat"
        fake_hashcat.write_text("#!/bin/sh\necho 'output here'\nexit 0\n")
        fake_hashcat.chmod(0o755)

        result = oracle.run_hashcat([str(fake_hashcat)])

        assert result.returncode == 0
        assert "output here" in result.stdout

    def test_exit_1_with_stdout_returns_result(self, tmp_path):
        """Exit 1 with stdout returns the CompletedProcess (ok_returncodes default)."""
        fake_hashcat = tmp_path / "hashcat"
        fake_hashcat.write_text("#!/bin/sh\necho 'cracked something'\nexit 1\n")
        fake_hashcat.chmod(0o755)

        result = oracle.run_hashcat([str(fake_hashcat)])

        assert result.returncode == 1
        assert "cracked something" in result.stdout

    def test_exit_0_with_non_empty_unrelated_stderr_returns_result(self, tmp_path):
        """Exit 0 with non-empty unrelated stderr still returns result (not fail)."""
        fake_hashcat = tmp_path / "hashcat"
        fake_hashcat.write_text(
            "#!/bin/sh\necho 'some warning' >&2\necho 'output'\nexit 0\n"
        )
        fake_hashcat.chmod(0o755)

        result = oracle.run_hashcat([str(fake_hashcat)])

        assert result.returncode == 0
        assert "some warning" in result.stderr

    def test_exit_255_with_backend_failure_stderr_skips(self, tmp_path):
        """Backend failure stderr + exit 255 raises pytest.skip.Exception."""
        fake_hashcat = tmp_path / "hashcat"
        fake_hashcat.write_text(
            "#!/bin/sh\necho 'clCreateProgramWithBinary error' >&2\nexit 255\n"
        )
        fake_hashcat.chmod(0o755)

        with pytest.raises(pytest.skip.Exception) as exc_info:
            oracle.run_hashcat([str(fake_hashcat)])

        assert "backend could not build kernels" in str(exc_info.value)

    def test_exit_255_with_unrelated_stderr_fails(self, tmp_path):
        """Exit 255 with unrelated stderr raises pytest.fail.Exception."""
        fake_hashcat = tmp_path / "hashcat"
        fake_hashcat.write_text("#!/bin/sh\necho 'unrelated error' >&2\nexit 255\n")
        fake_hashcat.chmod(0o755)

        with pytest.raises(pytest.fail.Exception) as exc_info:
            oracle.run_hashcat([str(fake_hashcat)])

        msg = str(exc_info.value)
        assert "255" in msg
        assert "unrelated error" in msg

    def test_exit_2_with_unrelated_stderr_fails(self, tmp_path):
        """Any non-ok exit code with unrelated stderr fails."""
        fake_hashcat = tmp_path / "hashcat"
        fake_hashcat.write_text("#!/bin/sh\necho 'error output' >&2\nexit 2\n")
        fake_hashcat.chmod(0o755)

        with pytest.raises(pytest.fail.Exception) as exc_info:
            oracle.run_hashcat([str(fake_hashcat)])

        msg = str(exc_info.value)
        assert "2" in msg
        assert "error output" in msg

    def test_nonexistent_path_skips(self):
        """FileNotFoundError raises pytest.skip.Exception."""
        with pytest.raises(pytest.skip.Exception) as exc_info:
            oracle.run_hashcat(["/nonexistent/path/to/hashcat"])

        assert "no executable hashcat" in str(exc_info.value)

    def test_custom_ok_returncodes(self, tmp_path):
        """Custom ok_returncodes parameter works."""
        fake_hashcat = tmp_path / "hashcat"
        fake_hashcat.write_text("#!/bin/sh\nexit 42\n")
        fake_hashcat.chmod(0o755)

        result = oracle.run_hashcat([str(fake_hashcat)], ok_returncodes=(0, 1, 42))

        assert result.returncode == 42

    def test_ok_returncodes_excludes_255_still_fails(self, tmp_path):
        """Exit 255 outside ok_returncodes still fails even with custom ok_returncodes."""
        fake_hashcat = tmp_path / "hashcat"
        fake_hashcat.write_text("#!/bin/sh\necho 'error' >&2\nexit 255\n")
        fake_hashcat.chmod(0o755)

        with pytest.raises(pytest.fail.Exception):
            oracle.run_hashcat([str(fake_hashcat)], ok_returncodes=(0, 1))

    def test_kernel_and_build_failed_stderr_skips(self, tmp_path):
        """Kernel + build failed backend failure stderr skips."""
        fake_hashcat = tmp_path / "hashcat"
        fake_hashcat.write_text(
            "#!/bin/sh\necho 'Kernel compilation: build failed' >&2\nexit 255\n"
        )
        fake_hashcat.chmod(0o755)

        with pytest.raises(pytest.skip.Exception) as exc_info:
            oracle.run_hashcat([str(fake_hashcat)])

        assert "backend could not build kernels" in str(exc_info.value)

    def test_timeout_parameter_respected(self, tmp_path):
        """timeout parameter is passed to subprocess.run."""
        fake_hashcat = tmp_path / "hashcat"
        fake_hashcat.write_text("#!/bin/sh\necho 'quick'\nexit 0\n")
        fake_hashcat.chmod(0o755)

        # This should not timeout (command is instant)
        result = oracle.run_hashcat([str(fake_hashcat)], timeout=10)

        assert result.returncode == 0

    def test_kwargs_passed_to_subprocess_run(self, tmp_path):
        """Additional kwargs are passed to subprocess.run."""
        fake_hashcat = tmp_path / "hashcat"
        fake_hashcat.write_text("#!/bin/sh\necho 'test'\nexit 0\n")
        fake_hashcat.chmod(0o755)

        # Pass cwd as a kwarg
        result = oracle.run_hashcat([str(fake_hashcat)], cwd=str(tmp_path))

        assert result.returncode == 0


class TestHashcatBinConstant:
    """Test HASHCAT_BIN constant."""

    def test_hashcat_bin_is_string(self):
        """HASHCAT_BIN is a string constant."""
        assert isinstance(oracle.HASHCAT_BIN, str)

    def test_hashcat_bin_value(self):
        """HASHCAT_BIN points to the expected location."""
        assert oracle.HASHCAT_BIN == "/opt/hashcat/hashcat"


class TestRequiresHashcatMarker:
    """Test requires_hashcat pytest marker."""

    def test_requires_hashcat_is_pytest_marker(self):
        """requires_hashcat is a pytest mark.skipif."""
        assert hasattr(oracle.requires_hashcat, "mark")

    def test_requires_hashcat_callable(self):
        """requires_hashcat can be called as a decorator."""

        # This is just checking it's a pytest marker object that can decorate
        @oracle.requires_hashcat
        def dummy_test():
            pass

        assert dummy_test is not None
