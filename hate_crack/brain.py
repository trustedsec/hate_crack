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

The local server (``ensure_server``/``shutdown`` below) is spawned only when
the configured host is loopback, and for any configured remote host it only
ever connects, never spawns. Those are the spawn-decision rules; they say
nothing about what a spawned process exposes on the network, which is a
separate control. Without an explicit bind flag hashcat's brain server binds
``INADDR_ANY`` -- every interface -- regardless of how hate_crack decided to
start it. So ``_spawn_server`` always passes ``--brain-host 127.0.0.1``
itself: the spawned server binds loopback only, never reachable off the
machine, which is what "hate_crack manages its own process on 127.0.0.1"
actually requires. The server writes its ``.ldmp``/``.admp`` dumps into its
own working directory (verified against hashcat v7.1.2 source, ``src/brain.c``,
which passes the literal path ``"."`` to the dump writers) -- confirmed
empirically on 2026-09-18 by running a real server with ``cwd`` set to a
scratch directory and a real ``--brain-client`` attack against it: the
resulting ``brain.<attack>.admp`` landed in that directory, not in the
client's cwd or any hashcat profile directory. That is why ``_spawn_server``
below passes ``cwd=str(brain_dir())``.
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
    # Coerce before the membership test, not after: `True in (1, 2, 3)` and
    # `3.0 in (1, 2, 3)` are both True (bool is an int subclass, and 3.0 == 3),
    # so a membership check alone lets them through and str() would then emit
    # "True" or "3.0" -- an invalid --brain-client-features value that kills
    # the attack outright rather than degrading it.
    try:
        features = int(features)
    except (TypeError, ValueError):
        features = 3
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
# Bounded poll for the spawned process to actually bind the port, replacing a
# flat sleep: a flat sleep proves only that the process hasn't exited yet, not
# that it's listening, and on a loaded machine that gap reports success for a
# server the next connection can't reach.
_SPAWN_TIMEOUT_SECONDS = 5.0
_SPAWN_POLL_INTERVAL_SECONDS = 0.1


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
    """Start `hashcat --brain-server`, or return None if it will not start.

    ``--brain-host 127.0.0.1`` is not optional here: without it hashcat binds
    every interface (``INADDR_ANY``), and the ``_LOOPBACK`` check in
    ``ensure_server`` only gates whether we *spawn* -- it has no say over what
    the spawned process listens on. This is what actually keeps the auto
    server off the network.

    ``start_new_session=True`` keeps the server out of hate_crack's own
    foreground process group. A terminal Ctrl-C delivers SIGINT to the whole
    group; hate_crack catches its own ``KeyboardInterrupt`` and carries on,
    but without this the server would receive the same signal and die with
    no such handling, taking brain down for the rest of the session.
    """
    directory = brain_dir()
    try:
        directory.mkdir(parents=True, exist_ok=True)
        proc = subprocess.Popen(  # nosec B603 - fixed argv, no shell
            [
                hcat_bin,
                "--brain-server",
                "--brain-host",
                "127.0.0.1",
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
            start_new_session=True,
        )
    except (OSError, ValueError):
        return None

    attempts = max(1, int(_SPAWN_TIMEOUT_SECONDS / _SPAWN_POLL_INTERVAL_SECONDS))
    try:
        for _ in range(attempts):
            if proc.poll() is not None:
                # Exited already: nothing to wait for.
                return None
            if _port_is_open("127.0.0.1", port):
                return proc
            time.sleep(_SPAWN_POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        # A Ctrl-C mid-spawn must not orphan the child: nothing else holds a
        # reference to it (we haven't set _PROC yet), so shutdown() could
        # never reach it once this exception propagated past ensure_server.
        _kill_quietly(proc)
        return None

    # Never came up within the window -- give up rather than hand back a
    # process nothing is actually listening on.
    _kill_quietly(proc)
    return None


def _kill_quietly(proc) -> None:
    try:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
    except (OSError, subprocess.SubprocessError):
        pass


def ensure_server(config: dict, *, hcat_bin: str = "hashcat") -> BrainServer | None:
    """Reach a brain server, spawning a local one only when we own the host.

    A configured non-loopback host is somebody else's server: we connect or we
    do without. Spawning there would be hate_crack starting a process on a box
    the operator pointed at for a reason.

    The memo is revalidated on every call, not just trusted: a brain server
    that dies mid-session (crash, an operator killing it directly, the box
    running out of RAM) must not leave every later attack in the session
    silently pointed at a corpse. The cost is one extra loopback connect per
    invocation, which is cheap next to spawning a whole hashcat process.
    """
    global _SERVER, _PROC
    if _SERVER is not None:
        if _port_is_open(_SERVER.host, _SERVER.port):
            return _SERVER
        # Stale: whatever we were using is no longer there. shutdown() both
        # clears the globals and kills the process we hold a handle to --
        # a bare `_SERVER = None` would drop that handle instead. If the
        # probe failed for a reason other than the process actually being
        # dead (a saturated listen backlog, a stopped process, a transient
        # timeout), the discarded Popen becomes unkillable: atexit's
        # shutdown() then has nothing left to act on, and -- now that
        # _spawn_server uses start_new_session=True -- the orphan survives
        # terminal signals too, sitting on the port for every later run.
        # shutdown() is a no-op when the process is genuinely already dead.
        shutdown()

    host = str(config.get("brain_host") or "").strip()
    port = int(config.get("brain_port") or 6863)
    password = str(config.get("brain_password") or "")

    if host not in _LOOPBACK:
        if not _port_is_open(host, port):
            return None
        _SERVER = BrainServer(host=host, port=port, password=password, spawned=False)
        return _SERVER

    resolved_host = host or "127.0.0.1"
    # Whether the port is already open when checked here (before spawning)
    # or only after losing the spawn race below, the question is the same:
    # is the configured password trustworthy for whatever is listening? An
    # *empty* configured password is never trustworthy -- an orphan of a
    # prior auto-spawn used an ephemeral password that died with that
    # process, so there is nothing to verify against. A *non-empty*
    # configured password is the operator's own signal, and the most
    # plausible source of an already-open port under auto-manage is another
    # hate_crack process reading that same config file -- true regardless of
    # which side of the spawn attempt the probe happens to land on. So both
    # sites adopt on the same condition: a password is configured. (This
    # also covers an *explicit* loopback host, e.g. "127.0.0.1" typed by the
    # operator, since that always carries a password when the operator wants
    # one -- see the non-loopback-equivalent case above.)
    if _port_is_open(resolved_host, port):
        if password:
            _SERVER = BrainServer(
                host=resolved_host, port=port, password=password, spawned=False
            )
            return _SERVER
        return None

    if not password:
        # Ephemeral, so the value visible in `ps` dies with the session.
        spawn_password = secrets.token_urlsafe(18)
    else:
        spawn_password = password

    proc = _spawn_server(
        hcat_bin, port, spawn_password, int(config.get("brain_server_timer") or 300)
    )
    if proc is None:
        # Possibly lost a spawn race: another process may have bound the
        # port between our check above and the Popen call. Re-probe once
        # before giving up, using the same adoption rule as the pre-spawn
        # probe above (see its comment) -- only a *configured* password
        # counts; the ephemeral one generated above was ours alone and
        # cannot be assumed to match whatever the race winner used.
        if password and _port_is_open(resolved_host, port):
            _SERVER = BrainServer(
                host=resolved_host, port=port, password=password, spawned=False
            )
            return _SERVER
        return None

    _PROC = proc
    _SERVER = BrainServer(
        host=resolved_host, port=port, password=spawn_password, spawned=True
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
    _kill_quietly(proc)
