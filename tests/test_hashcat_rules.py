import os
import json
import shutil
import subprocess
import shlex
from pathlib import Path

import pytest


_TEST_HASH = "994a24ad0d9ac6f1fd7d4d75adffeda2"


def _format_hashcat_cmd(cmd: list[str]) -> str:
    # Mirror hate_crack's debug printing: safe shell-style quoting.
    return " ".join(shlex.quote(part) for part in cmd)


def _get_hcat_tuning_args(repo_root: Path) -> list[str]:
    config_path = repo_root / "config.json"
    if not config_path.is_file():
        return []
    try:
        config = json.loads(config_path.read_text())
    except Exception:
        return []

    tuning = (config.get("hcatTuning") or "").strip()
    if not tuning:
        return []
    return shlex.split(tuning)


def _hashcat_sessions_writable() -> bool:
    """
    Hashcat writes session files under ~/.hashcat/sessions on macOS/homebrew builds.
    If that location is not writable (sandbox/MDM), running hashcat will emit stderr.
    """
    sessions_dir = Path.home() / ".hashcat" / "sessions"
    try:
        sessions_dir.mkdir(parents=True, exist_ok=True)
        probe = sessions_dir / f"pytest_write_probe_{os.getpid()}"
        probe.write_text("probe")
        probe.unlink(missing_ok=True)
        return True
    except Exception:
        return False


def _run_hashcat(
    cmd: list[str],
    cwd: Path,
    *,
    timeout_s: int = 60,
    capsys=None,
    show_output: bool = False,
    show_cmd: bool = False,
) -> subprocess.CompletedProcess:
    """
    Run hashcat and skip (not fail) on common local-environment issues.

    This repo's normal test suite is offline/mocked; this test is opt-in and
    depends on a local hashcat installation that can write its session files.
    """
    if show_cmd and capsys is not None:
        with capsys.disabled():
            print("\n[DEBUG] hashcat cmd: " + _format_hashcat_cmd(cmd))

    try:
        result = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except FileNotFoundError:
        pytest.skip("hashcat not available in PATH")
    except subprocess.TimeoutExpired:
        pytest.fail(f"hashcat timed out after {timeout_s}s: {cmd!r}")

    combined = (result.stdout or "") + (result.stderr or "")

    if show_output and capsys is not None:
        with capsys.disabled():
            print("\n[hashcat stdout]\n" + (result.stdout or ""))
            print("\n[hashcat stderr]\n" + (result.stderr or ""))

    # If hashcat crashed, subprocess uses a negative return code (signal).
    if result.returncode < 0:
        pytest.fail(
            f"hashcat terminated by signal {-result.returncode}. stdout={result.stdout!r} stderr={result.stderr!r}"
        )

    # Per request: fail on any stderr output (warnings/errors are treated as failure).
    if (result.stderr or "").strip():
        pytest.fail(
            f"hashcat wrote to stderr (treated as failure). cmd={_format_hashcat_cmd(cmd)!r} stderr={result.stderr!r}"
        )

    assert "Segmentation fault" not in combined
    assert "core dumped" not in combined.lower()

    return result


def test_toggle_rule_parses_with_and_without_loopback(tmp_path: Path, capsys):
    """
    Execute the two hashcat command-lines requested (with an empty wordlist),
    primarily to ensure hashcat does not crash while parsing/using the rule file.
    """
    if shutil.which("hashcat") is None:
        pytest.skip("hashcat not available in PATH")
    if not _hashcat_sessions_writable():
        pytest.skip("hashcat session directory (~/.hashcat/sessions) is not writable")

    show_output = os.environ.get("HATE_CRACK_SHOW_HASHCAT_OUTPUT") == "1"
    show_cmd = (
        os.environ.get("HATE_CRACK_SHOW_HASHCAT_CMD") == "1"
        or os.environ.get("HATE_CRACK_SHOW_HASHCAT_OUTPUT") == "1"
    )

    repo_root = Path(__file__).resolve().parents[1]
    tuning_args = _get_hcat_tuning_args(repo_root)
    src_rule = repo_root / "rules" / "toggles-lm-ntlm.rule"
    if not src_rule.is_file():
        pytest.skip("rules/toggles-lm-ntlm.rule not found")

    # Mirror the requested relative `rules/...` path in a temp working dir.
    (tmp_path / "rules").mkdir(parents=True, exist_ok=True)
    rule_path = tmp_path / "rules" / "toggles-lm-ntlm.rule"
    shutil.copy2(src_rule, rule_path)

    # Equivalent to: `echo > empty.txt`
    (tmp_path / "empty.txt").write_text("")

    cmd_with_loopback = [
        "hashcat",
        *tuning_args,
        "-m",
        "1000",
        "empty.txt",
        "--loopback",
        "-r",
        "rules/toggles-lm-ntlm.rule",
        _TEST_HASH,
    ]
    cmd_without_loopback = [
        "hashcat",
        *tuning_args,
        "-m",
        "1000",
        "empty.txt",
        "-r",
        "rules/toggles-lm-ntlm.rule",
        _TEST_HASH,
    ]

    _run_hashcat(
        cmd_with_loopback,
        cwd=tmp_path,
        capsys=capsys,
        show_output=show_output,
        show_cmd=show_cmd,
    )
    _run_hashcat(
        cmd_without_loopback,
        cwd=tmp_path,
        capsys=capsys,
        show_output=show_output,
        show_cmd=show_cmd,
    )
