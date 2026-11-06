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
        try:
            entries = sorted(os.listdir(directory))
        except OSError:
            # An unreadable shared directory must not break menu discovery.
            continue
        for entry in entries:
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


_HINT_RANKS = ("zipf", "linear", "flat")


def _check_hint_word(word: str) -> str:
    word = word.strip()
    if not word or "," in word or any(ch.isspace() for ch in word):
        raise ValueError(
            f"hint words must be non-empty with no comma or whitespace: {word!r}"
        )
    return word


def build_settings(
    *,
    costmax: int | None = None,
    pwmin: int | None = None,
    pwmax: int | None = None,
    mask: str | None = None,
    contains: list[str] | None = None,
    hintwords: list[str] | None = None,
    hintfile: str | None = None,
    hintrank: str | None = None,
    hintrepeat: bool = False,
    weights: list[int] | None = None,
    ruleset_count: int = 1,
    omen: bool | None = None,
) -> list[str]:
    """``key=value`` settings positionals for ``hashcat -a 4``.

    Raises ValueError for any combination hashcat would refuse, so the user
    sees the reason before a GPU context is created.
    """
    if mask and contains:
        raise ValueError(
            "mask and contains cannot be combined; write the piece into the mask"
        )
    if omen and (mask or contains):
        raise ValueError(
            "omen=1 cannot be combined with mask or contains (the escape has no terminals to filter)"
        )
    if hintwords and hintfile:
        raise ValueError("hintwords and hintfile are exclusive")
    if pwmin is not None and pwmax is not None and pwmin > pwmax:
        raise ValueError("pwmin must not exceed pwmax")
    if costmax is not None and costmax < 1:
        raise ValueError("costmax must be at least 1")
    if hintrank is not None and hintrank not in _HINT_RANKS:
        raise ValueError(f"hintrank must be one of {', '.join(_HINT_RANKS)}")

    settings: list[str] = []
    if weights is not None:
        if (
            len(weights) != ruleset_count
            or any(w < 0 for w in weights)
            or sum(weights) == 0
        ):
            raise ValueError(
                f"weights needs {ruleset_count} non-negative values that are not all zero"
            )
        settings.append("weights=" + ":".join(str(w) for w in weights))
    if costmax is not None:
        settings.append(f"costmax={costmax}")
    if pwmin is not None:
        settings.append(f"pwmin={pwmin}")
    if pwmax is not None:
        settings.append(f"pwmax={pwmax}")
    if mask:
        settings.append(f"mask={mask}")
    if contains:
        if any(not piece.strip() for piece in contains):
            raise ValueError("a contains piece cannot be empty")
        if any("," in piece for piece in contains):
            raise ValueError("a contains piece cannot hold a comma")
        if len(set(contains)) != len(contains):
            raise ValueError("a contains piece cannot be named twice")
        settings.append("contains=" + ",".join(contains))
    if hintwords:
        settings.append("hintwords=" + ",".join(_check_hint_word(w) for w in hintwords))
    if hintfile:
        settings.append(f"hintfile={hintfile}")
    if hintrank:
        settings.append(f"hintrank={hintrank}")
    if hintrepeat:
        settings.append("hintrepeat=1")
    if omen is not None:
        settings.append(f"omen={1 if omen else 0}")
    return settings
