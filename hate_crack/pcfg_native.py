"""Helpers for hashcat's built-in PCFG attack (``-a 4``).

Pure functions only: nothing here talks to the UI or owns hashcat globals, so
the probe, discovery and settings rules are testable without a hashcat build.
"""

import os
import re
import subprocess  # nosec B404 - hashcat is an expected local binary
from functools import lru_cache

_MODE4_LINE = re.compile(r"^\s*4 \| PCFG\b", re.MULTILINE)
_ARCHIVE_SUFFIX = ".tar.xz"


@lru_cache(maxsize=8)
def supports_pcfg(hcat_bin: str) -> bool:
    """True when *hcat_bin* lists attack mode 4 (PCFG) in ``--help``.

    Any failure to ask (missing binary, timeout) is False: an unknown build
    takes the legacy pipe path rather than a hashcat error.
    """
    try:
        proc = subprocess.run(  # nosec B603 - hcat_bin is the configured hashcat
            [hcat_bin, "--help"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return bool(_MODE4_LINE.search(proc.stdout or ""))


def ruleset_search_dirs() -> list[str]:
    """Where hashcat looks up a ruleset by name, user location first."""
    data_home = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return [
        os.path.join(data_home, "hashcat", "pcfg"),
        "/usr/local/share/hashcat/pcfg",
        "/usr/share/hashcat/pcfg",
    ]


def list_rulesets(dirs: list[str] | None = None) -> list[str]:
    """Ruleset names found in *dirs*, user dir first, without duplicates."""
    seen: list[str] = []
    for directory in dirs if dirs is not None else ruleset_search_dirs():
        if not os.path.isdir(directory):
            continue
        for entry in sorted(os.listdir(directory)):
            path = os.path.join(directory, entry)
            if os.path.isdir(path):
                name = entry
            elif entry.endswith(_ARCHIVE_SUFFIX):
                name = entry[: -len(_ARCHIVE_SUFFIX)]
            else:
                continue
            if name not in seen:
                seen.append(name)
    return seen


def build_settings(*, costmax: int | None = None) -> list[str]:
    """``key=value`` settings positionals for ``hashcat -a 4``.

    Raises ValueError for a value hashcat would reject, so the user sees the
    reason before a GPU context is created.
    """
    settings: list[str] = []
    if costmax is not None:
        if costmax < 1:
            raise ValueError("costmax must be at least 1")
        settings.append(f"costmax={costmax}")
    return settings
