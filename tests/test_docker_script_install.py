import os
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.skipif(
    os.environ.get("HATE_CRACK_RUN_DOCKER_TESTS") != "1",
    reason="Set HATE_CRACK_RUN_DOCKER_TESTS=1 to run Docker-based tests.",
)
def test_docker_script_install_and_run():
    if shutil.which("docker") is None:
        pytest.skip("docker not available")

    repo_root = Path(__file__).resolve().parents[1]
    image_tag = "hate-crack-e2e"

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

    try:
        run = subprocess.run(
            ["docker", "run", "--rm", image_tag],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"Docker run timed out after {exc.timeout}s")

    assert run.returncode == 0, (
        "Docker script install/run failed. "
        f"stdout={run.stdout} stderr={run.stderr}"
    )
