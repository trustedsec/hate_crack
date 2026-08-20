"""Per-target record of which rule lines, mask lines and wordlists were tried.

Across a long engagement the same hash file is attacked in many sessions with a
rotating set of wordlists, rule files and mask lists, and there is otherwise no
way to know whether a given rule or mask has already been run against it. This
module is the store that answers that question, plus the planner that turns an
answer into a skip-or-filter decision.

Three identity decisions carry the design:

- **The target is content-addressed** (sha256 of the hash file), so coverage
  survives the file being renamed or moved between sessions. hate_crack does
  not use hashcat's ``--left``, so the hash file's content is stable for the
  life of an engagement.
- **Rules and masks are tracked per entry, not per file.** The same rule line
  routinely appears in more than one rule file, so a file-level record would
  fail to recognise that a later custom file re-runs ground ``best64.rule``
  already covered.
- **Wordlists are tracked per file**, because per-word tracking is not viable
  at wordlist scale. The fingerprint is a content sha256 memoized on
  ``(size, mtime)``, so a multi-gigabyte corpus is hashed once rather than on
  every attack.

A key combines all of those dimensions: a rule counts as covered only for the
specific wordlist it ran against, because ``best64.rule`` over one corpus tries
entirely different candidates than the same rules over another.

**Why SQLite rather than a flat key file** (the shape
``hate_crack.hashview_cache`` uses): that cache is bounded by the size of a
hash list, in the thousands. This one is bounded by rules times wordlists.
``d3ad0ne.rule`` and ``T0XlC.rule`` together are ~38k rules, and
``hcatDictionary`` runs the pair once per wordlist -- so a single Dictionary
attack over five wordlists produces ~191k keys. An append-only file would grow
by that much on every repeat run even when coverage did not change, and
membership testing would mean loading the whole thing into a set before every
attack. A primary key gives deduplication for free, membership becomes a query
over just the entries this run cares about, and there is somewhere to put the
run history the issue asks for. ``sqlite3`` is in the standard library, so none
of this costs a dependency.
"""

import hashlib
import json
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Sequence

COVERAGE_DIRNAME = "coverage"
DB_FILENAME = "attack_coverage.sqlite3"

_READ_CHUNK = 1024 * 1024

# Membership test for an arbitrarily large key set, as one static statement
# with a single bound parameter. json_each sidesteps SQLite's 999-parameter
# limit without interpolating anything into the SQL.
_COVERED_IN_JSON = (
    "SELECT key FROM covered WHERE key IN (SELECT value FROM json_each(?))"
)

# Schema notes, all measured at the realistic scale of ~191k keys (the
# d3ad0ne+T0XlC pair over five wordlists, which is one Dictionary attack):
#
# - `covered` is normalized down to (key, run_id) rather than carrying the
#   target/attack/timestamp on every row. Denormalized it cost 39.6 MB for one
#   run; normalized it is 27.5 MB, because "Dictionary" and a timestamp were
#   being stored 191,000 times instead of once.
# - `covered` is WITHOUT ROWID *because* it is now narrow. A wide WITHOUT ROWID
#   table is a pessimization -- it puts the whole row in the key B-tree and
#   measured slower to insert with no size win. Narrow, it earns its keep.
# - Lookup speed was never the deciding factor: a 38k-key membership test runs
#   in ~57 ms, and every schema variant tried landed within 10 ms of that,
#   because the primary key index serves them all. What the primary key really
#   buys is INSERT OR IGNORE deduplication, which is why the store stays at
#   27.5 MB after ten identical runs where an append-only file reached 124 MB.
_SCHEMA = """
-- One row per hashcat invocation. This is also the run history: a dynamic
-- candidate generator (PRINCE, PCFG, OMEN, Markov, LLM) has no fixed set to
-- diff, so it is never filtered -- it just lands here with no linked keys,
-- which is what lets an operator answer "did I already run PRINCE on this?".
CREATE TABLE IF NOT EXISTS runs (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    target  TEXT NOT NULL,
    kind    TEXT NOT NULL DEFAULT '',
    attack  TEXT NOT NULL DEFAULT '',
    detail  TEXT NOT NULL DEFAULT '',
    ran_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS runs_target ON runs (target);

CREATE TABLE IF NOT EXISTS covered (
    key    TEXT PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES runs (id)
) WITHOUT ROWID;

-- Justified by forget_target(), which otherwise full-scans every engagement's
-- keys. It is the only secondary index here: each one is write amplification
-- on a bulk insert of ~191k rows.
CREATE INDEX IF NOT EXISTS covered_run ON covered (run_id);

CREATE TABLE IF NOT EXISTS wordlist_fingerprints (
    path     TEXT PRIMARY KEY,
    size     INTEGER NOT NULL,
    mtime_ns INTEGER NOT NULL,
    sha256   TEXT NOT NULL
) WITHOUT ROWID;
"""


def _coverage_dir() -> Path:
    # Mirrors hashview_cache._cache_path()'s ~/.hate_crack construction, with
    # its own subdirectory so the store sits beside the potfile and
    # hashcat_debug rather than among them.
    return Path(os.path.expanduser("~")) / ".hate_crack" / COVERAGE_DIRNAME


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(_READ_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


# --- store -----------------------------------------------------------------


class CoverageStore:
    """SQLite-backed coverage store.

    Every method swallows :class:`sqlite3.Error` and degrades to "we know
    nothing", because a broken or read-only store must never take an attack
    down with it. Losing a record costs one redundant run later; raising here
    costs the operator their session.
    """

    def __init__(self, path: Path | str | None = None):
        self._path = Path(path) if path is not None else _coverage_dir() / DB_FILENAME
        self._conn: sqlite3.Connection | None = None
        # In-process fingerprint memo, so repeated attacks in one session skip
        # even the database round trip.
        self._fingerprints: dict[str, tuple[int, int, str]] = {}

    # -- connection --------------------------------------------------------

    def _connect(self) -> sqlite3.Connection | None:
        if self._conn is not None:
            return self._conn
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self._path), timeout=30.0)
            # WAL plus a busy timeout so two hate_crack instances in the same
            # engagement directory do not lock each other out.
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(_SCHEMA)
            conn.commit()
        except (sqlite3.Error, OSError):
            return None
        self._conn = conn
        return conn

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass
            self._conn = None

    # -- coverage ----------------------------------------------------------

    def covered(self, keys: Sequence[str]) -> set[str]:
        """Return the subset of ``keys`` already recorded.

        Queried rather than loaded wholesale: a Dictionary attack asks about
        ~191k keys, and only those matter.

        The whole key set goes over as one JSON parameter. The obvious
        alternative -- an ``IN (?,?,?...)`` clause -- would have to be built by
        string interpolation and chunked under SQLite's 999-parameter limit;
        this is a single static statement with one bound value, and measured
        slightly faster besides (57 ms against 65 ms for the chunked form).
        """
        if not keys:
            return set()
        conn = self._connect()
        if conn is None:
            return set()
        payload = json.dumps(list(keys))
        try:
            rows = conn.execute(_COVERED_IN_JSON, (payload,)).fetchall()
        except sqlite3.Error:
            return self._covered_via_temp_table(conn, keys)
        return {row[0] for row in rows}

    def _covered_via_temp_table(
        self, conn: sqlite3.Connection, keys: Sequence[str]
    ) -> set[str]:
        """Fallback for a SQLite built without the JSON1 extension.

        Correct but slower: the planner joins from ``covered``, so this scales
        with the size of the store rather than the size of the probe. Still
        static SQL, which is the point -- the alternative fallback would mean
        interpolating placeholders after all.
        """
        try:
            conn.execute(
                "CREATE TEMP TABLE IF NOT EXISTS coverage_probe "
                "(key TEXT PRIMARY KEY) WITHOUT ROWID"
            )
            conn.execute("DELETE FROM coverage_probe")
            conn.executemany(
                "INSERT OR IGNORE INTO coverage_probe (key) VALUES (?)",
                [(key,) for key in keys],
            )
            rows = conn.execute(
                "SELECT covered.key FROM covered "
                "JOIN coverage_probe ON covered.key = coverage_probe.key"
            ).fetchall()
        except sqlite3.Error:
            return set()
        return {row[0] for row in rows}

    def covered_lookup(self) -> Callable[[Sequence[str]], set[str]]:
        return self.covered

    def log_run(
        self,
        target: str,
        attack: str = "",
        kind: str = "",
        detail: str = "",
    ) -> int | None:
        """Record that an attack ran. Returns its run id, or None on failure.

        Every invocation gets a row, filterable or not -- that is what makes
        this table the run history as well as the parent of ``covered``.
        """
        conn = self._connect()
        if conn is None:
            return None
        try:
            cursor = conn.execute(
                "INSERT INTO runs (target, kind, attack, detail, ran_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (target, kind, attack, detail, _now()),
            )
            conn.commit()
        except sqlite3.Error:
            return None
        return cursor.lastrowid

    def record(
        self,
        keys: Iterable[str],
        target: str = "",
        kind: str = "",
        attack: str = "",
        detail: str = "",
    ) -> int:
        """Log a run and link its coverage. Returns newly-inserted key count.

        ``INSERT OR IGNORE`` means a repeat adds no keys and leaves the original
        run's link in place, so a key records when it was *first* covered and
        the store does not grow on repeats.
        """
        keys = list(keys)
        conn = self._connect()
        if conn is None:
            return 0
        run_id = self.log_run(target, attack=attack, kind=kind, detail=detail)
        if run_id is None or not keys:
            return 0
        try:
            cursor = conn.executemany(
                "INSERT OR IGNORE INTO covered (key, run_id) VALUES (?, ?)",
                [(key, run_id) for key in keys],
            )
            conn.commit()
        except sqlite3.Error:
            return 0
        return cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0

    def forget_target(self, target: str) -> int:
        """Drop all coverage and history for one target, so it can be re-attacked.

        The ``covered_run`` index is what keeps this from full-scanning every
        engagement's keys.
        """
        conn = self._connect()
        if conn is None:
            return 0
        try:
            cursor = conn.execute(
                "DELETE FROM covered WHERE run_id IN "
                "(SELECT id FROM runs WHERE target = ?)",
                (target,),
            )
            conn.execute("DELETE FROM runs WHERE target = ?", (target,))
            conn.commit()
        except sqlite3.Error:
            return 0
        return cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0

    # -- history -----------------------------------------------------------

    def history(self, target: str) -> list[tuple[str, str, str]]:
        """(attack, detail, ran_at) rows for a target, oldest first."""
        conn = self._connect()
        if conn is None:
            return []
        try:
            return [
                (row[0], row[1], row[2])
                for row in conn.execute(
                    "SELECT attack, detail, ran_at FROM runs "
                    "WHERE target = ? ORDER BY id",
                    (target,),
                ).fetchall()
            ]
        except sqlite3.Error:
            return []

    # -- wordlist fingerprints --------------------------------------------

    def clear_fingerprint_memo(self) -> None:
        """Drop the in-process memo. The persisted memo is untouched."""
        self._fingerprints.clear()

    def wordlist_fingerprint(self, path: str) -> str | None:
        """Content sha256 of a wordlist, memoized on (size, mtime).

        The memo is what makes a content hash affordable: rehashing a 31 GB
        corpus on every attack would cost minutes of I/O per run, so the digest
        is recomputed only when size or mtime says the file actually changed.
        """
        try:
            real = os.path.realpath(path)
            stat = os.stat(real)
        except OSError:
            return None

        stamp = (stat.st_size, stat.st_mtime_ns)

        cached = self._fingerprints.get(real)
        if cached is not None and cached[:2] == stamp:
            return cached[2]

        conn = self._connect()
        if conn is not None:
            try:
                row = conn.execute(
                    "SELECT size, mtime_ns, sha256 FROM wordlist_fingerprints "
                    "WHERE path = ?",
                    (real,),
                ).fetchone()
            except sqlite3.Error:
                row = None
            if row is not None and (row[0], row[1]) == stamp:
                self._fingerprints[real] = (stamp[0], stamp[1], row[2])
                return row[2]

        try:
            digest = _sha256_file(real)
        except OSError:
            return None

        self._fingerprints[real] = (stamp[0], stamp[1], digest)
        if conn is not None:
            try:
                conn.execute(
                    "INSERT INTO wordlist_fingerprints "
                    "(path, size, mtime_ns, sha256) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(path) DO UPDATE SET "
                    "size=excluded.size, mtime_ns=excluded.mtime_ns, "
                    "sha256=excluded.sha256",
                    (real, stat.st_size, stat.st_mtime_ns, digest),
                )
                conn.commit()
            except sqlite3.Error:
                pass
        return digest


_default_store: CoverageStore | None = None


def get_store() -> CoverageStore:
    """The process-wide store. Created lazily so importing costs no I/O."""
    global _default_store
    if _default_store is None:
        _default_store = CoverageStore()
    return _default_store


def reset_store() -> None:
    """Drop the process-wide store (used by tests and by config reloads)."""
    global _default_store
    if _default_store is not None:
        _default_store.close()
    _default_store = None


# --- target identity -------------------------------------------------------


def target_id(hash_file: str) -> str | None:
    """Content hash of the hash file, or None if it cannot be read.

    Returning None rather than raising lets every caller treat "we cannot
    identify this target" as "do not filter", which is the safe direction: an
    unfiltered run wastes time, a wrongly filtered one silently skips work.
    """
    try:
        return _sha256_file(hash_file)
    except OSError:
        return None


# --- rule / mask entry parsing --------------------------------------------


def read_entries(path: str) -> list[str]:
    """Read a rule or .hcmask file into its individual entries.

    Only the line terminator is removed. Rule lines are whitespace-significant
    -- ``$ `` appends a space, and stripping it would silently rewrite the rule
    as ``$`` -- so no other trimming happens. Blank lines and ``#`` comments are
    dropped, and duplicates are collapsed while preserving first-seen order so
    a filtered file we later write keeps the author's ordering.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return []

    entries: list[str] = []
    seen: set[str] = set()
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line in seen:
            continue
        seen.add(line)
        entries.append(line)
    return entries


# --- keys ------------------------------------------------------------------


def entry_key(
    target: str,
    kind: str,
    wordlist_fp: str,
    entry: str,
    variant: str = "",
) -> str:
    """Key one (target, kind, wordlist, entry, variant) tuple.

    ``variant`` carries the run modifiers that change what an entry actually
    tries -- an ``--increment 1-8`` mask run covers different candidates than
    the same mask without it -- so the two are never conflated.
    """
    payload = f"{target}\x00{kind}\x00{wordlist_fp}\x00{variant}\x00{entry}"
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()


# --- planning --------------------------------------------------------------


@dataclass(frozen=True)
class CoverageSpec:
    """What an about-to-run hashcat invocation actually covers.

    Attack functions build this alongside the command they assemble, because
    the assembled ``cmd`` list alone cannot say which argument is a wordlist and
    which is a mask. Only the dimensions a run genuinely enumerates are filled
    in; dynamic candidate generators pass no spec at all.
    """

    hash_file: str
    wordlists: tuple[str, ...] = ()
    rule_files: tuple[str, ...] = ()
    mask_files: tuple[str, ...] = ()
    masks: tuple[str, ...] = ()
    # Run modifiers that change what an entry tries (e.g. "inc:1-8").
    variant: str = ""


@dataclass(frozen=True)
class RunPlan:
    """The filtering decision for one run.

    ``kind`` names the dimension that was diffed, which tells the caller how to
    apply ``filtered_entries``: rewrite ``source_path``'s file for ``"rule"``
    and ``"mask"``, or drop positional arguments for ``"wordlist"``. An inert
    plan (``kind == ""``) means coverage could not be established, so the run
    must proceed untouched.
    """

    kind: str = ""
    skip: bool = False
    covered_count: int = 0
    total_count: int = 0
    filtered_entries: list[str] | None = None
    source_path: str | None = None
    record_keys: list[str] = field(default_factory=list)
    target: str = ""

    @property
    def has_overlap(self) -> bool:
        return self.covered_count > 0

    @property
    def is_inert(self) -> bool:
        return not self.kind


_INERT = RunPlan()


def set_lookup(covered: set) -> Callable[[Sequence[str]], set[str]]:
    """Adapt a plain set to the lookup callable ``plan_run`` expects."""
    return lambda keys: {key for key in keys if key in covered}


def _chain_entry(rule_files: tuple[str, ...]) -> str | None:
    """Collapse chained rule files into one opaque, order-sensitive entry.

    ``-r a -r b`` makes hashcat apply the *cartesian product* of both files, so
    dropping an individual line from either file would silently remove every
    combination it participated in. Such a run is therefore tracked as a single
    all-or-nothing unit rather than filtered per entry.
    """
    parts = []
    for path in rule_files:
        entries = read_entries(path)
        if not entries:
            return None
        parts.append(hashlib.sha256("\n".join(entries).encode()).hexdigest())
    return "chain:" + ":".join(parts)


def plan_run(
    spec: CoverageSpec,
    lookup: Callable[[Sequence[str]], set[str]],
    store: CoverageStore | None = None,
) -> RunPlan:
    """Decide what of ``spec`` still needs running, given what is covered.

    Every failure to establish identity returns an inert plan, so the run
    proceeds in full. That bias is deliberate: an unfiltered run costs time,
    while a wrongly filtered one silently skips untried candidates.
    """
    target = target_id(spec.hash_file)
    if target is None:
        return _INERT

    store = store if store is not None else get_store()

    wordlist_fps: list[str] = []
    for path in spec.wordlists:
        fingerprint = store.wordlist_fingerprint(path)
        if fingerprint is None:
            # A glob that matched nothing, or a list that vanished. Either way
            # we cannot say what this run covers.
            return _INERT
        wordlist_fps.append(fingerprint)

    if spec.rule_files:
        if len(spec.rule_files) > 1:
            entry = _chain_entry(spec.rule_files)
            if entry is None:
                return _INERT
            return _plan_entries(
                kind="rule",
                entries=[entry],
                wordlist_fps=wordlist_fps,
                target=target,
                variant=spec.variant,
                lookup=lookup,
                source_path=None,
                filterable=False,
            )
        entries = read_entries(spec.rule_files[0])
        if not entries:
            return _INERT
        return _plan_entries(
            kind="rule",
            entries=entries,
            wordlist_fps=wordlist_fps,
            target=target,
            variant=spec.variant,
            lookup=lookup,
            source_path=spec.rule_files[0],
            filterable=True,
        )

    if spec.mask_files or spec.masks:
        mask_entries: list[str] = []
        for path in spec.mask_files:
            mask_entries.extend(read_entries(path))
        mask_entries.extend(spec.masks)
        # Preserve order while dropping duplicates across the combined sources.
        mask_entries = list(dict.fromkeys(mask_entries))
        if not mask_entries:
            return _INERT
        single_file = (
            spec.mask_files[0] if len(spec.mask_files) == 1 and not spec.masks else None
        )
        return _plan_entries(
            kind="mask",
            entries=mask_entries,
            wordlist_fps=wordlist_fps,
            target=target,
            variant=spec.variant,
            lookup=lookup,
            source_path=single_file,
            filterable=single_file is not None,
        )

    if spec.wordlists:
        # A rule-less dictionary attack: the wordlist itself is the unit.
        return _plan_entries(
            kind="wordlist",
            entries=wordlist_fps,
            wordlist_fps=[""],
            target=target,
            variant=spec.variant,
            lookup=lookup,
            source_path=None,
            filterable=True,
            display=list(spec.wordlists),
        )

    return _INERT


def _plan_entries(
    *,
    kind: str,
    entries: list[str],
    wordlist_fps: list[str],
    target: str,
    variant: str,
    lookup: Callable[[Sequence[str]], set[str]],
    source_path: str | None,
    filterable: bool,
    display: list[str] | None = None,
) -> RunPlan:
    # A mask run has no wordlist, but still needs one slot to key against.
    slots = wordlist_fps or [""]

    keys_by_entry = [
        [entry_key(target, kind, fp, entry, variant) for fp in slots]
        for entry in entries
    ]
    all_keys = [key for keys in keys_by_entry for key in keys]
    already = lookup(all_keys)

    novel: list[str] = []
    novel_display: list[str] = []
    record_keys: list[str] = []

    for index, keys in enumerate(keys_by_entry):
        # Only fully-covered entries are dropped. An entry already tried
        # against one wordlist but not another must still run.
        if all(key in already for key in keys):
            continue
        novel.append(entries[index])
        novel_display.append(display[index] if display else entries[index])
        record_keys.extend(keys)

    covered_count = len(entries) - len(novel)

    if not novel:
        return RunPlan(
            kind=kind,
            skip=True,
            covered_count=covered_count,
            total_count=len(entries),
            source_path=source_path,
            target=target,
        )

    return RunPlan(
        kind=kind,
        skip=False,
        covered_count=covered_count,
        total_count=len(entries),
        filtered_entries=novel_display if (filterable and covered_count) else None,
        source_path=source_path,
        record_keys=record_keys,
        target=target,
    )
