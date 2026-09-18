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

The local server (``ensure_server``/``shutdown`` below) is spawned only for a
loopback host: hate_crack manages its own process on 127.0.0.1, and for any
configured remote host it only ever connects, never spawns. The server writes
its ``.ldmp``/``.admp`` dumps into its own working directory (verified against
hashcat v7.1.2 source, ``src/brain.c``, which passes the literal path ``"."``
to the dump writers) -- confirmed empirically on 2026-09-18 by running a real
server with ``cwd`` set to a scratch directory and a real ``--brain-client``
attack against it: the resulting ``brain.<attack>.admp`` landed in that
directory, not in the client's cwd or any hashcat profile directory. That is
why ``_spawn_server`` below passes ``cwd=str(brain_dir())``.
"""

from __future__ import annotations

import atexit
import json
import os
import secrets
import socket
import subprocess  # nosec B404 - hashcat is an expected local binary
import time
from dataclasses import dataclass
from pathlib import Path

from hate_crack import attack_coverage as _coverage

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
            if result:  # Only use non-empty results; empty is unknown
                _MEMO[version] = result
                return result
            # Empty result from cache: fall through to fresh query
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


def _mode_set(raw) -> set[int]:
    """Coerce a csv_list config value to a set of mode numbers, ignoring junk."""
    # Reject strings: they iterate character-by-character and produce silent misreads.
    # A bare string like "3200" would walk each character, returning {0, 2, 3}
    # instead of {3200}. Reject it entirely rather than silently misreading.
    if isinstance(raw, str):
        return set()
    modes = set()
    try:
        # Protect the iteration itself, not just each item. A scalar config value
        # like 3200 instead of [3200] raises TypeError: 'int' object is not iterable.
        for item in raw or ():
            try:
                modes.add(int(str(item).strip()))
            except (TypeError, ValueError):
                continue
    except TypeError:
        # raw is not iterable and not a string (those are handled above).
        # Return an empty set and let the attack proceed without this override.
        return set()
    return modes


def is_slow(mode: int, config: dict, *, hcat_bin: str) -> bool:
    """Whether brain should apply to this hash mode.

    Order is exclude, then force, then hashcat's own verdict. Exclude wins
    outright: it is the operator saying "not on this rig", and a rig fast
    enough to make brain the bottleneck is something no oracle can know.
    """
    # Coerce mode to int defensively. A string mode would silently fail
    # the membership tests and disable brain unintentionally.
    try:
        mode = int(mode)
    except (TypeError, ValueError):
        return False
    if mode in _mode_set(config.get("brain_modes_exclude")):
        return False
    if mode in _mode_set(config.get("brain_modes_force")):
        return True
    known = slow_modes(hcat_bin)
    if known is None:
        return False
    return mode in known


_VALID_FEATURES = (1, 2, 3)


def session_id(hash_file: str) -> str | None:
    """A stable brain session for this target, or None if it cannot be read.

    hashcat computes its own session from the hash list and would reach an
    equivalent answer, so this is not about correctness. Deriving it from
    ``attack_coverage.target_id`` means the brain session is the same
    identifier the coverage store already reports, and it is what makes
    ``--brain-session-whitelist`` usable on a shared server.
    """
    target = _coverage.target_id(hash_file)
    if not target:
        return None
    return "0x" + target[:8]


def client_flags(
    *, host: str, port: int, password: str, features: int, session: str
) -> list[str]:
    """The `-z` client flag block for one hashcat invocation."""
    if features not in _VALID_FEATURES:
        features = 3
    return [
        "-z",
        "--brain-host",
        str(host),
        "--brain-port",
        str(port),
        "--brain-password",
        str(password),
        "--brain-client-features",
        str(features),
        "--brain-session",
        str(session),
    ]


_LOOPBACK = frozenset({"", "localhost", "127.0.0.1", "::1"})
_SPAWN_SETTLE_SECONDS = 2.0


@dataclass(frozen=True)
class BrainServer:
    host: str
    port: int
    password: str
    spawned: bool


_SERVER: BrainServer | None = None
_PROC = None


def _port_is_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host or "127.0.0.1", port), timeout=1.0):
            return True
    except OSError:
        return False


def _spawn_server(hcat_bin: str, port: int, password: str, timer: int):
    """Start `hashcat --brain-server`, or return None if it will not start."""
    directory = brain_dir()
    try:
        directory.mkdir(parents=True, exist_ok=True)
        proc = subprocess.Popen(  # nosec B603 - fixed argv, no shell
            [
                hcat_bin,
                "--brain-server",
                "--brain-port",
                str(port),
                "--brain-password",
                password,
                "--brain-server-timer",
                str(max(60, int(timer))),
            ],
            cwd=str(directory),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, ValueError):
        return None
    time.sleep(_SPAWN_SETTLE_SECONDS)
    if proc.poll() is not None:
        return None
    return proc


def ensure_server(config: dict, *, hcat_bin: str = "hashcat") -> BrainServer | None:
    """Reach a brain server, spawning a local one only when we own the host.

    A configured non-loopback host is somebody else's server: we connect or we
    do without. Spawning there would be hate_crack starting a process on a box
    the operator pointed at for a reason.
    """
    global _SERVER, _PROC
    if _SERVER is not None:
        return _SERVER

    host = str(config.get("brain_host") or "").strip()
    port = int(config.get("brain_port") or 6863)
    password = str(config.get("brain_password") or "")

    if host not in _LOOPBACK:
        if not _port_is_open(host, port):
            return None
        _SERVER = BrainServer(host=host, port=port, password=password, spawned=False)
        return _SERVER

    resolved_host = host or "127.0.0.1"
    if _port_is_open(resolved_host, port):
        # Something is already listening -- an operator's own server, or a
        # second hate_crack. Either way it holds the password we cannot see,
        # so the configured one has to be right.
        _SERVER = BrainServer(
            host=resolved_host, port=port, password=password, spawned=False
        )
        return _SERVER

    if not password:
        # Ephemeral, so the value visible in `ps` dies with the session.
        password = secrets.token_urlsafe(18)

    proc = _spawn_server(
        hcat_bin, port, password, int(config.get("brain_server_timer") or 300)
    )
    if proc is None:
        return None

    _PROC = proc
    _SERVER = BrainServer(
        host=resolved_host, port=port, password=password, spawned=True
    )
    atexit.register(shutdown)
    return _SERVER


def shutdown() -> None:
    """Stop a server this process started. Safe to call repeatedly."""
    global _SERVER, _PROC
    proc, _PROC = _PROC, None
    _SERVER = None
    if proc is None:
        return
    try:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
    except (OSError, subprocess.SubprocessError):
        pass
