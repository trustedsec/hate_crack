"""
Shared hashcat oracle helper for tests.

This module provides common utilities for tests that need to run hashcat,
with robust handling of environment-specific failures (GPU/OpenCL issues).
"""

import os
import subprocess

import pytest


#: Hashcat binary path. Tests pin this binary (hate_crack's hcatBin) rather than
#: searching PATH, because a different hashcat on PATH can answer differently.
#: Tests that require hashcat skip if nothing executable is found at this path.
HASHCAT_BIN = "/opt/hashcat/hashcat"


requires_hashcat = pytest.mark.skipif(
    not os.access(HASHCAT_BIN, os.X_OK),
    reason=f"no executable hashcat at {HASHCAT_BIN}",
)
"""
Pytest marker to skip tests requiring a working hashcat binary.
Use as @requires_hashcat on test functions.
"""


def is_backend_failure(stderr: str) -> bool:
    """
    Detect GPU/OpenCL kernel-build failures in hashcat stderr.

    Returns True if stderr contains evidence of a backend-specific failure:
    - A line containing 'clCreateProgramWithBinary', OR
    - A line containing both 'Kernel' and 'build failed'

    These failures are environment-specific (GPU availability, driver issues)
    and should be skipped, not treated as test failures.

    Args:
        stderr: The stderr output from hashcat.

    Returns:
        True if stderr indicates a backend failure, False otherwise.
    """
    for line in stderr.splitlines():
        if "clCreateProgramWithBinary" in line:
            return True
        if "Kernel" in line and "build failed" in line:
            return True
    return False


def run_hashcat(
    cmd, *, ok_returncodes=(0, 1), timeout=300, text=True, **kwargs
) -> subprocess.CompletedProcess:
    """
    Run hashcat with robust error handling for environment-specific failures.

    Handles common issues:
    - Missing hashcat binary (skip)
    - GPU/OpenCL kernel-build failures (skip)
    - Unexpected exit codes (fail with details)

    Args:
        cmd: Command list to run (subprocess.run format).
        ok_returncodes: Tuple of acceptable exit codes (default: (0, 1)).
        timeout: Timeout in seconds (default: 300).
        text: If True, return stdout/stderr as str; if False, as bytes (default: True).
        **kwargs: Additional arguments passed to subprocess.run.

    Returns:
        subprocess.CompletedProcess if successful. With text=True, stdout/stderr
        are str; with text=False, they are bytes.

    Raises:
        pytest.skip.Exception: If hashcat is missing or backend fails.
        pytest.fail.Exception: If exit code is not in ok_returncodes.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=text,
            timeout=timeout,
            **kwargs,
        )
    except FileNotFoundError as e:
        pytest.skip(f"no executable hashcat at {cmd[0]} ({e})")

    # Get stderr in string form for is_backend_failure check
    if text:
        stderr_str = result.stderr or ""
    else:
        stderr_str = (result.stderr or b"").decode("utf-8", errors="replace")

    # Backend failures (GPU/OpenCL issues) are environment-specific, not test bugs
    if is_backend_failure(stderr_str):
        pytest.skip(
            f"hashcat backend could not build kernels (environment issue): {stderr_str}"
        )

    # Non-ok exit codes are failures (but only after checking for backend issues)
    if result.returncode not in ok_returncodes:
        # Prepare stderr for error message
        if text:
            stderr_msg = result.stderr or ""
        else:
            stderr_msg = (result.stderr or b"").decode("utf-8", errors="replace")
        pytest.fail(
            f"hashcat exited with code {result.returncode}. "
            f"cmd={cmd!r} stderr={stderr_msg!r}"
        )

    return result
