#!/usr/bin/env python3
"""Refuse to publish anything but the intended 0.0.0 placeholder sdist.

Run against the build output directory. This is the last gate before an upload
to a public index, so it checks the artifact itself rather than trusting that
pyproject.toml still says what it said when it was written: exactly one sdist,
version 0.0.0, no wheel, and nothing importable or executable inside.
"""

from __future__ import annotations

import sys
import tarfile
from pathlib import Path


def _fail(message: str) -> None:
    print(f"verify_placeholder: {message}", file=sys.stderr)
    sys.exit(1)


def main(argv: list[str]) -> None:
    if len(argv) != 2:
        _fail("usage: verify_placeholder.py <dist-dir>")

    dist = Path(argv[1])
    if not dist.is_dir():
        _fail(f"{dist} is not a directory")

    wheels = sorted(dist.glob("*.whl"))
    if wheels:
        _fail(f"wheel(s) present, placeholder must ship sdist only: {wheels}")

    sdists = sorted(dist.glob("*.tar.gz"))
    if len(sdists) != 1:
        _fail(f"expected exactly one sdist, found {len(sdists)}: {sdists}")

    sdist = sdists[0]
    if sdist.name not in {"hate_crack-0.0.0.tar.gz", "hate-crack-0.0.0.tar.gz"}:
        _fail(f"unexpected sdist name {sdist.name!r}, expected version 0.0.0")

    with tarfile.open(sdist) as tar:
        names = tar.getnames()
        metadata = next((n for n in names if n.endswith("PKG-INFO")), None)
        if metadata is None:
            _fail("sdist has no PKG-INFO")
        raw = tar.extractfile(metadata)
        if raw is None:
            _fail("PKG-INFO is not a regular file")
        text = raw.read().decode("utf-8", "replace")

    if "Version: 0.0.0" not in text:
        _fail("PKG-INFO version is not 0.0.0")
    if "Development Status :: 7 - Inactive" not in text:
        _fail("PKG-INFO is missing the Inactive classifier")
    if "placeholder" not in text.lower():
        _fail("PKG-INFO description does not identify itself as a placeholder")

    # An entry point or a bundled module would give a user something that looks
    # like a working install.
    offenders = [
        n
        for n in names
        if n.endswith(("entry_points.txt", ".py")) and "verify_placeholder" not in n
    ]
    offenders = [n for n in offenders if not n.endswith("placeholder_backend.py")]
    if offenders:
        _fail(f"sdist contains executable or importable content: {offenders}")

    print(f"verify_placeholder: {sdist.name} is a valid 0.0.0 placeholder")


if __name__ == "__main__":
    main(sys.argv)
