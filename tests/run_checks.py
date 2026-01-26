#!/usr/bin/env python3
import subprocess
import sys


def run(cmd, label):
    print(f"\n==> {label}: {' '.join(cmd)}")
    return subprocess.call(cmd)


def main():
    # Lint first so we fail fast on style issues.
    rc = run([sys.executable, "-m", "ruff", "check", "."], "lint")
    if rc != 0:
        return rc
    return run([sys.executable, "-m", "pytest"], "pytest")


if __name__ == "__main__":
    sys.exit(main())
