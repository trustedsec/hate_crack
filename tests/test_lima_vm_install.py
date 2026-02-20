import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest


def _require_lima():
    if os.environ.get("HATE_CRACK_RUN_LIMA_TESTS") != "1":
        pytest.skip("Set HATE_CRACK_RUN_LIMA_TESTS=1 to run Lima VM tests.")
    if shutil.which("limactl") is None:
        pytest.skip("limactl not available")


@pytest.fixture(scope="session")
def lima_vm():
    _require_lima()
    repo_root = Path(__file__).resolve().parents[1]
    vm_name = f"hate-crack-e2e-{uuid.uuid4().hex[:8]}"
    yaml_path = str(repo_root / "lima" / "hate-crack-test.yaml")

    try:
        start = subprocess.run(
            ["limactl", "start", "--name", vm_name, yaml_path],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"limactl start timed out after {exc.timeout}s")

    assert start.returncode == 0, (
        f"limactl start failed. stdout={start.stdout} stderr={start.stderr}"
    )

    ssh_config = Path.home() / ".lima" / vm_name / "ssh.config"
    # Use rsync directly to exclude large runtime-only directories that aren't
    # needed for installation (wordlists, crack results, the hashcat binary -
    # the VM has hashcat installed via apt).
    rsync_cmd = [
        "rsync", "-a", "--delete",
        "--exclude=wordlists/",
        "--exclude=hashcat/",
        "--exclude=results/",
        "--exclude=*.pot",
        "--exclude=*.ntds",
        "--exclude=*.ntds.*",
        # Exclude host-compiled binaries so the VM always builds from source.
        # Keep the bin/ dir itself (empty is fine); make clean recreates it anyway.
        "--exclude=princeprocessor/*.bin",
        "--exclude=princeprocessor/src/*.bin",
        "--exclude=hashcat-utils/bin/*.bin",
        "--exclude=hashcat-utils/bin/*.exe",
        "--exclude=hashcat-utils/bin/*.app",
        "-e", f"ssh -F {ssh_config}",
        f"{repo_root}/",
        f"lima-{vm_name}:/tmp/hate_crack/",
    ]
    try:
        copy = subprocess.run(
            rsync_cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"rsync copy timed out after {exc.timeout}s")

    assert copy.returncode == 0, (
        f"rsync copy failed. stdout={copy.stdout} stderr={copy.stderr}"
    )

    install_cmd = (
        "cd /tmp/hate_crack && "
        "make submodules vendor-assets && "
        # Build the wheel directly (skips sdist) so freshly-compiled binaries
        # in hate_crack/hashcat-utils/bin/ are included via package-data.
        "rm -rf dist && "
        "$HOME/.local/bin/uv build --wheel && "
        "$HOME/.local/bin/uv tool install dist/hate_crack-*.whl && "
        "make clean-vendor"
    )
    try:
        install = subprocess.run(
            ["limactl", "shell", vm_name, "--", "bash", "-lc", install_cmd],
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"Installation timed out after {exc.timeout}s")

    assert install.returncode == 0, (
        f"Installation failed. stdout={install.stdout} stderr={install.stderr}"
    )

    yield vm_name

    try:
        result = subprocess.run(
            ["limactl", "delete", "--force", vm_name],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            print(
                f"Warning: Failed to delete Lima VM {vm_name}. stderr={result.stderr}",
                file=sys.stderr,
            )
    except Exception as e:
        print(
            f"Warning: Exception while deleting Lima VM {vm_name}: {e}",
            file=sys.stderr,
        )


def _run_vm(vm_name, command, timeout=180):
    try:
        run = subprocess.run(
            ["limactl", "shell", vm_name, "--", "bash", "-lc", command],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"Lima VM command timed out after {exc.timeout}s")
    return run


def test_lima_vm_install_and_run(lima_vm):
    run = _run_vm(
        lima_vm,
        "cd /tmp/hate_crack && $HOME/.local/bin/hate_crack --help && ./hate_crack.py --help",
        timeout=120,
    )
    assert run.returncode == 0, (
        f"Lima VM install/run failed. stdout={run.stdout} stderr={run.stderr}"
    )


def test_lima_hashcat_cracks_simple_password(lima_vm):
    command = (
        "set -euo pipefail; "
        "printf 'password\\nletmein\\n123456\\n' > /tmp/wordlist.txt; "
        "echo 5f4dcc3b5aa765d61d8327deb882cf99 > /tmp/hash.txt; "
        "hashcat -m 0 -a 0 --potfile-disable -o /tmp/out.txt /tmp/hash.txt /tmp/wordlist.txt --quiet; "
        "grep -q ':password' /tmp/out.txt"
    )
    run = _run_vm(lima_vm, command, timeout=180)
    assert run.returncode == 0, (
        f"Lima VM hashcat crack failed. stdout={run.stdout} stderr={run.stderr}"
    )
