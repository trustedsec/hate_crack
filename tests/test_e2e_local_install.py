import os
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.skipif(
    os.environ.get("HATE_CRACK_RUN_E2E") != "1",
    reason="Set HATE_CRACK_RUN_E2E=1 to run local end-to-end install tests.",
)
def test_local_uv_tool_install_and_help(tmp_path):
    if shutil.which("uv") is None:
        pytest.skip("uv not available")

    repo_root = Path(__file__).resolve().parents[1]
    home_dir = tmp_path / "home"
    home_dir.mkdir()

    env = os.environ.copy()
    env.update(
        {
            "HOME": str(home_dir),
            "PATH": f"{home_dir / '.local' / 'bin'}:{env.get('PATH', '')}",
            "HATE_CRACK_SKIP_INIT": "1",
            "HATE_CRACK_HOME": str(repo_root),
            "XDG_CACHE_HOME": str(tmp_path / "cache"),
            "XDG_CONFIG_HOME": str(tmp_path / "config"),
            "XDG_DATA_HOME": str(tmp_path / "data"),
        }
    )

    install = subprocess.run(
        ["uv", "tool", "install", "."],
        cwd=repo_root,
        env=env,
        capture_output=True,
        text=True,
    )
    assert install.returncode == 0, (
        "uv tool install failed. "
        f"stdout={install.stdout} stderr={install.stderr}"
    )

    tool_help = subprocess.run(
        ["hate_crack", "--help"],
        cwd=repo_root,
        env=env,
        capture_output=True,
        text=True,
    )
    assert tool_help.returncode == 0, (
        "hate_crack --help failed. "
        f"stdout={tool_help.stdout} stderr={tool_help.stderr}"
    )

    script_help = subprocess.run(
        ["./hate_crack.py", "--help"],
        cwd=repo_root,
        env=env,
        capture_output=True,
        text=True,
    )
    assert script_help.returncode == 0, (
        "./hate_crack.py --help failed. "
        f"stdout={script_help.stdout} stderr={script_help.stderr}"
    )

    output = tool_help.stdout + tool_help.stderr
    expected_flags = [
        "--download-hashview",
        "--hashview",
        "--download-torrent",
        "--download-all-torrents",
        "--weakpass",
        "--rank",
        "--hashmob",
        "--rules",
        "--cleanup",
        "--debug",
    ]
    for flag in expected_flags:
        assert flag in output, f"Missing {flag} in help output"
