"""Subprocess harness for hate_crack.py's non-interactive CLI subcommands
(quick, dict, brute, topmask). See
docs/superpowers/specs/2026-07-28-cli-e2e-testing-design.md.
"""
import os
import signal
import subprocess
import sys


HATE_CRACK_SCRIPT = os.path.join(
    os.path.dirname(__file__), "..", "..", "hate_crack.py"
)


def run_noninteractive(args, home_dir, timeout=90):
    """Run hate_crack.py <args> as a real subprocess. Returns CompletedProcess.

    Runs the child in its own process group (``start_new_session=True``) and,
    on timeout, kills the whole group instead of just the direct child.
    hate_crack.py's ``args`` (quick/dict/brute/topmask) launch ``hashcat`` as
    a *grandchild* via their own internal ``subprocess.Popen`` +
    ``.wait()``; plain ``subprocess.run(..., timeout=...)`` only kills the
    immediate ``hate_crack.py`` process on timeout, leaving that hashcat
    grandchild running indefinitely as an orphan that keeps the GPU busy and
    starves every subsequent test. Observed live: a too-tight timeout left 3
    orphaned hashcat processes running well after their tests had already
    been reported as failed/timed-out by pytest.
    """
    cmd = [sys.executable, HATE_CRACK_SCRIPT] + args
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "PYTHONUNBUFFERED": "1", "HOME": str(home_dir)},
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        stdout, stderr = proc.communicate()
        raise subprocess.TimeoutExpired(cmd, timeout, output=stdout, stderr=stderr)
    return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)
