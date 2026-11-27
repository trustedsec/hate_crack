"""Helpers for hashcat's built-in Token Mask attack (``-a 13``).

Pure functions only: nothing here talks to the UI or owns hashcat globals, so
the probe, discovery and charset rules are testable without a hashcat build.
"""

import os
import shutil

from hate_crack import hashcat_paths

_MODE13_PATTERN = r"^\s*13 \| Token Mask\b"
TOKENSET_SUFFIX = ".tokenset"

# The accent-only Latin tokensets; they carry no ASCII letters, so a mask that
# should also reach plain letters needs the widening recipe below.
LATIN_ACCENT_SETS: frozenset[str] = frozenset(
    {
        "czech",
        "danish-norwegian",
        "french",
        "german",
        "hungarian",
        "icelandic",
        "italian",
        "polish",
        "portuguese",
        "romanian",
        "spanish",
        "swedish",
        "turkish",
    }
)


def supports_tokenmask(hcat_bin: str) -> bool:
    """True when *hcat_bin* lists attack mode 13 (Token Mask) in ``--help``.

    Any failure to ask (missing binary, timeout) is False.
    """
    return hashcat_paths.help_mentions(hcat_bin, _MODE13_PATTERN)


# Same lru_cache-style interface pcfg_native keeps; the cache lives in
# hashcat_paths.
setattr(supports_tokenmask, "cache_clear", hashcat_paths.reset_help_cache)


def tokenset_search_dirs(hcat_bin: str = "", hcat_path: str = "") -> list[str]:
    """Candidate tokenset directories, highest priority first.

    Existence is not checked. Duplicates (by realpath) are dropped.
    """
    candidates: list[str] = []
    if hcat_path:
        candidates.append(os.path.join(hcat_path, "tokensets"))
    if hcat_bin:
        resolved = shutil.which(hcat_bin) or hcat_bin
        if os.path.exists(resolved):
            candidates.append(
                os.path.join(os.path.dirname(os.path.realpath(resolved)), "tokensets")
            )
    data_home = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    candidates += [
        os.path.join(data_home, "hashcat", "tokensets"),
        "/usr/local/share/hashcat/tokensets",
        "/usr/share/hashcat/tokensets",
    ]
    seen: set[str] = set()
    out: list[str] = []
    for directory in candidates:
        real = os.path.realpath(directory)
        if real in seen:
            continue
        seen.add(real)
        out.append(directory)
    return out


def list_tokensets(dirs: list[str]) -> list[tuple[str, str]]:
    """``(name, absolute_path)`` for each tokenset file in *dirs*, by name.

    The first directory carrying a name wins. Missing or unreadable
    directories are skipped silently.
    """
    found: dict[str, str] = {}
    for directory in dirs:
        try:
            entries = sorted(os.listdir(directory))
        except OSError:
            continue
        for entry in entries:
            if not entry.endswith(TOKENSET_SUFFIX):
                continue
            path = os.path.join(directory, entry)
            if not os.path.isfile(path):
                continue
            name = entry[: -len(TOKENSET_SUFFIX)]
            found.setdefault(name, os.path.abspath(path))
    return sorted(found.items())


def resolve_charset(value: str, tokensets: list[tuple[str, str]]) -> str:
    """Turn a user-typed charset value into the ``-N`` argument."""
    value = value.strip()
    if not value:
        raise ValueError("empty charset")
    expanded = os.path.expanduser(value)
    if os.path.isfile(expanded):
        return os.path.abspath(expanded)
    bare = value.removesuffix(TOKENSET_SUFFIX)
    for name, path in tokensets:
        if name in (value, bare):
            return path
    return value


def widen_with_ascii(
    charsets: dict[int, str], slot: int, path: str, mask_slots: list[int]
) -> dict[int, str]:
    """Return a copy of *charsets* where *slot* also covers ASCII letters.

    The tokenset file moves to the lowest free slot ``j`` and *slot* becomes
    ``?l?u?<j>``.
    """
    for j in range(1, 9):
        if j == slot or j in mask_slots or j in charsets:
            continue
        widened = dict(charsets)
        widened[j] = path
        widened[slot] = f"?l?u?{j}"
        return widened
    raise ValueError("no free charset slot")


def build_charset_args(charsets: dict[int, str]) -> list[str]:
    """``["-1", v1, "-3", v3, ...]`` in ascending slot order."""
    args: list[str] = []
    for slot in sorted(charsets):
        if not 1 <= slot <= 8:
            raise ValueError(f"charset slot out of range 1..8: {slot}")
        args += [f"-{slot}", charsets[slot]]
    return args
