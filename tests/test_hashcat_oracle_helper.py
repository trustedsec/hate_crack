"""
Tests for tests._hashcat_oracle helper module.

Tests use fake executables (small shell scripts in tmp_path) to avoid depending
on a real hashcat installation.
"""

import subprocess

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

    def test_exact_clCreateProgramWithBinary_line(self):
        """True for the exact clCreateProgramWithBinary error line from hashcat."""
        stderr = "clCreateProgramWithBinary(): CL_INVALID_VALUE\n"
        assert oracle.is_backend_failure(stderr) is True

    def test_exact_Kernel_build_failed_line(self):
        """True for the exact Kernel build failed line from hashcat."""
        stderr = "* Device #2: Kernel /opt/hashcat/OpenCL/shared.cl build failed.\n"
        assert oracle.is_backend_failure(stderr) is True

    def test_both_exact_backend_failure_lines(self):
        """True when both exact backend failure lines appear together."""
        stderr = (
            "clCreateProgramWithBinary(): CL_INVALID_VALUE\n"
            "* Device #2: Kernel /opt/hashcat/OpenCL/shared.cl build failed.\n"
        )
        assert oracle.is_backend_failure(stderr) is True


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
        assert "code 2" in msg
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

    def test_exact_backend_failure_lines_exit_255_skips(self, tmp_path):
        """Exact backend failure lines with exit 255 causes skip."""
        fake_hashcat = tmp_path / "hashcat"
        fake_hashcat.write_text(
            "#!/bin/sh\necho 'clCreateProgramWithBinary(): CL_INVALID_VALUE' >&2\n"
            "echo '* Device #2: Kernel /opt/hashcat/OpenCL/shared.cl build failed.' >&2\nexit 255\n"
        )
        fake_hashcat.chmod(0o755)

        with pytest.raises(pytest.skip.Exception) as exc_info:
            oracle.run_hashcat([str(fake_hashcat)])

        assert "backend could not build kernels" in str(exc_info.value)

    def test_timeout_parameter_respected(self, tmp_path):
        """timeout parameter causes subprocess.TimeoutExpired when elapsed."""
        fake_hashcat = tmp_path / "hashcat"
        # Script that sleeps longer than the timeout
        fake_hashcat.write_text("#!/bin/sh\nsleep 5\n")
        fake_hashcat.chmod(0o755)

        # Should timeout after 1 second and raise TimeoutExpired
        with pytest.raises(subprocess.TimeoutExpired):
            oracle.run_hashcat([str(fake_hashcat)], timeout=1)

    def test_kwargs_passed_to_subprocess_run(self, tmp_path):
        """Additional kwargs (like cwd) are passed to subprocess.run."""
        from pathlib import Path

        # Create a subdirectory
        subdir = tmp_path / "subdir"
        subdir.mkdir()

        # Fake hashcat that prints its working directory
        fake_hashcat = subdir / "hashcat"
        fake_hashcat.write_text("#!/bin/sh\npwd\n")
        fake_hashcat.chmod(0o755)

        # Run with cwd set to subdir
        result = oracle.run_hashcat([str(fake_hashcat)], cwd=str(subdir))

        assert result.returncode == 0
        # Compare resolved paths (handles macOS /private/tmp symlinks)
        output_dir = Path(result.stdout.strip()).resolve()
        expected_dir = subdir.resolve()
        assert output_dir == expected_dir

    def test_text_false_preserves_cr_in_stdout(self, tmp_path):
        """With text=False, a CR in the output is preserved as bytes b'\\r'."""
        fake_hashcat = tmp_path / "hashcat"
        # printf emits a literal CR without newline translation
        fake_hashcat.write_text("#!/bin/sh\nprintf 'a\\rb'\n")
        fake_hashcat.chmod(0o755)

        result = oracle.run_hashcat([str(fake_hashcat)], text=False)

        assert result.returncode == 0
        assert result.stdout == b"a\rb", (
            f"CR should be preserved as bytes, got {result.stdout!r}. "
            f"With text=True, universal newline translation would convert CR to LF."
        )

    def test_text_false_backend_failure_still_skips(self, tmp_path):
        """With text=False, backend failure stderr + exit 255 still raises pytest.skip."""
        fake_hashcat = tmp_path / "hashcat"
        fake_hashcat.write_text(
            "#!/bin/sh\necho 'clCreateProgramWithBinary error' >&2\nexit 255\n"
        )
        fake_hashcat.chmod(0o755)

        with pytest.raises(pytest.skip.Exception) as exc_info:
            oracle.run_hashcat([str(fake_hashcat)], text=False)

        assert "backend could not build kernels" in str(exc_info.value)

    def test_text_false_unrelated_stderr_fails_with_message(self, tmp_path):
        """With text=False, exit 255 + unrelated stderr fails with decoded stderr."""
        fake_hashcat = tmp_path / "hashcat"
        fake_hashcat.write_text(
            "#!/bin/sh\necho 'something went wrong' >&2\nexit 255\n"
        )
        fake_hashcat.chmod(0o755)

        with pytest.raises(pytest.fail.Exception) as exc_info:
            oracle.run_hashcat([str(fake_hashcat)], text=False)

        msg = str(exc_info.value)
        assert "255" in msg
        # The stderr should be decoded and present in the message
        assert "something went wrong" in msg


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
        """requires_hashcat has correct marker properties."""
        marker = oracle.requires_hashcat
        # Check it's a skipif marker
        assert marker.mark.name == "skipif"
        # Check reason mentions HASHCAT_BIN
        assert oracle.HASHCAT_BIN in marker.mark.kwargs["reason"]

        # Check it can be used as a decorator
        @marker
        def dummy_test():
            pass

        assert dummy_test is not None
