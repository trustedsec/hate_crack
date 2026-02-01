import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest


def _require_docker():
    if os.environ.get("HATE_CRACK_RUN_DOCKER_TESTS") != "1":
        pytest.skip("Set HATE_CRACK_RUN_DOCKER_TESTS=1 to run Docker-based tests.")
    if shutil.which("docker") is None:
        pytest.skip("docker not available")


@pytest.fixture(scope="session")
def docker_image():
    _require_docker()
    repo_root = Path(__file__).resolve().parents[1]
    # Use a unique tag per test run to avoid conflicts
    image_tag = f"hate-crack-e2e-{uuid.uuid4().hex[:8]}"

    try:
        build = subprocess.run(
            ["docker", "build", "-f", "Dockerfile.test", "-t", image_tag, str(repo_root)],
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"Docker build timed out after {exc.timeout}s")

    assert build.returncode == 0, (
        "Docker build failed. "
        f"stdout={build.stdout} stderr={build.stderr}"
    )
    
    yield image_tag
    
    # Cleanup: remove the Docker image after tests complete
    try:
        result = subprocess.run(
            ["docker", "image", "rm", image_tag],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            print(
                f"Warning: Failed to remove Docker image {image_tag}. "
                f"stderr={result.stderr}",
                file=sys.stderr
            )
    except Exception as e:
        # Don't fail the test if cleanup fails, but log the issue
        print(f"Warning: Exception while removing Docker image {image_tag}: {e}", file=sys.stderr)


def _run_container(image_tag, command, timeout=180):
    try:
        run = subprocess.run(
            ["docker", "run", "--rm", image_tag, "bash", "-lc", command],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"Docker run timed out after {exc.timeout}s")
    return run


def test_docker_script_install_and_run(docker_image):
    run = _run_container(
        docker_image,
        "/root/.local/bin/hate_crack --help >/tmp/hc_help.txt && ./hate_crack.py --help >/tmp/hc_script_help.txt",
        timeout=120,
    )
    assert run.returncode == 0, (
        "Docker script install/run failed. "
        f"stdout={run.stdout} stderr={run.stderr}"
    )


def test_docker_hashcat_cracks_simple_password(docker_image):
    command = (
        "set -euo pipefail; "
        "curl -fsSL -o /tmp/rockyou.txt.gz https://weakpass.com/download/90/rockyou.txt.gz; "
        "gzip -d /tmp/rockyou.txt.gz; "
        "head -n 5000 /tmp/rockyou.txt > /tmp/rockyou.small.txt; "
        "echo 5f4dcc3b5aa765d61d8327deb882cf99 > /tmp/hash.txt; "
        "hashcat -m 0 -a 0 --potfile-disable -o /tmp/out.txt /tmp/hash.txt /tmp/rockyou.small.txt --quiet; "
        "grep -q ':password' /tmp/out.txt"
    )
    run = _run_container(docker_image, command, timeout=180)
    assert run.returncode == 0, (
        "Docker hashcat crack failed. "
        f"stdout={run.stdout} stderr={run.stderr}"
    )
