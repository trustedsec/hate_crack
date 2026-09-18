"""hashcat brain policy and local server lifecycle.

Brain de-duplicates individual password candidates, which is the dimension
``hate_crack.attack_coverage`` structurally cannot see: coverage keys a rule
line to the wordlist fingerprint it ran against, so two different
(wordlist, rule) pairs that generate the same candidate are invisible to it.

Brain is not free. ``--brain-client`` forces ``-S`` and the server holds
roughly 12 bytes of RAM per candidate, so it is worth paying for only where
the hash itself, not the lookup, is the bottleneck. That is why every entry
point here is gated on hashcat's own ``slow_hash`` verdict rather than on a
hand-maintained mode list that would drift as hashcat adds modes.

Every failure returns "no brain" rather than raising. A missing optimization
costs time; an attack that refuses to start costs the operator their session.
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404 - hashcat is an expected local binary
from pathlib import Path

CACHE_FILENAME = "slow_modes.json"

# Process-local memo so repeated attacks in one session skip even the file read.
_MEMO: dict[str, frozenset[int] | None] = {}

_QUERY_TIMEOUT = 60


def brain_dir() -> Path:
    """Where the slow-mode cache and the server's .ldmp dumps live."""
    return Path(os.path.expanduser("~")) / ".hate_crack" / "brain"


def _run_hashcat(args: list[str]) -> tuple[int, str]:
    """Run hashcat and return (returncode, stdout). Seam for tests."""
    try:
        completed = subprocess.run(  # nosec B603 - fixed argv, no shell
            args,
            capture_output=True,
            text=True,
            timeout=_QUERY_TIMEOUT,
            errors="replace",
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return 1, ""
    return completed.returncode, completed.stdout


def _hashcat_version(hcat_bin: str) -> str:
    rc, out = _run_hashcat([hcat_bin, "--version"])
    return out.strip() if rc == 0 else ""


def _parse_slow_modes(payload: str) -> frozenset[int] | None:
    try:
        data = json.loads(payload)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    modes = set()
    for key, entry in data.items():
        if isinstance(entry, dict) and entry.get("slow_hash") is True:
            try:
                modes.add(int(key))
            except (TypeError, ValueError):
                continue
    return frozenset(modes)


def slow_modes(
    hcat_bin: str, *, cache_dir: Path | None = None
) -> frozenset[int] | None:
    """Modes hashcat reports as slow, or None when that cannot be determined.

    Cached on disk keyed by the hashcat version string, so upgrading hashcat
    re-queries instead of serving a map that predates new modes.
    """
    version = _hashcat_version(hcat_bin)
    if not version:
        return None
    if version in _MEMO:
        return _MEMO[version]

    directory = cache_dir if cache_dir is not None else brain_dir()
    cache_path = directory / CACHE_FILENAME
    try:
        cached = json.loads(cache_path.read_text())
        if cached.get("version") == version:
            result = frozenset(int(m) for m in cached["modes"])
            _MEMO[version] = result
            return result
    except (OSError, ValueError, KeyError, TypeError):
        pass

    rc, out = _run_hashcat([hcat_bin, "--hash-info", "--machine-readable"])
    # hashcat prints a banner line before the JSON; start at the first brace.
    brace = out.find("{")
    parsed = _parse_slow_modes(out[brace:]) if brace >= 0 and rc == 0 else None
    # Don't cache empty results; treat them as unknown for future queries.
    if parsed is None or len(parsed) == 0:
        _MEMO[version] = None
        return None

    _MEMO[version] = parsed
    try:
        directory.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps({"version": version, "modes": sorted(parsed)}))
    except OSError:
        pass
    return parsed
