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
  at wordlist scale. A wordlist is identified by ``(realpath, size,
  mtime_ns)`` from one ``stat()`` and is never read, so a 40 GB corpus costs
  nothing to identify. Any rewrite changes size or mtime and so starts fresh.

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
attack. The store itself lives in :mod:`hate_crack.coverage_store`, one file beside each
hash file.
"""

import hashlib
import os
import sys
from dataclasses import dataclass
from typing import Callable

from hate_crack.coverage_store import (
    NO_WORDLIST,
    CoverageStore,
    remove_legacy_store,
    store_path_for,
)

# Import HashcatRosetta for mask canonicalization. Like hate_crack.llm, this
# module needs its own path setup rather than relying on main.py's: main.py
# imports attack_coverage (~line 86) *before* its own sys.path insertion
# (~line 99), so a bare `import hashcat_rosetta` here would always fail. See
# hate_crack.llm's identical guard for why these are kept separate per module.
_ROSETTA_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "HashcatRosetta")
)
# Holds the ImportError when HashcatRosetta could not be imported, else None.
ROSETTA_MASK_IMPORT_ERROR = None
try:
    if _ROSETTA_DIR not in sys.path:
        sys.path.insert(0, _ROSETTA_DIR)
    from hashcat_rosetta.mask import expand_custom_charsets as _rosetta_expand_charsets
    from hashcat_rosetta.mask import parse_hcmask_line as _rosetta_parse_hcmask_line
except ImportError as _rosetta_mask_import_error:
    ROSETTA_MASK_IMPORT_ERROR = _rosetta_mask_import_error
    _rosetta_expand_charsets = None
    _rosetta_parse_hcmask_line = None


__all__ = [
    "CoverageSpec",
    "CoverageStore",
    "RunPlan",
    "canonical_mask_entry",
    "clear_target_memo",
    "entry_hash",
    "get_store",
    "plan_run",
    "read_entries",
    "remove_legacy_store",
    "reset_store",
    "target_id",
]

_READ_CHUNK = 1024 * 1024


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(_READ_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


_stores: dict[str, CoverageStore] = {}


def get_store(hash_file: str) -> CoverageStore:
    """The store for one hash file, shared for the life of the process.

    Cached by resolved store path, so a symlink and its target share one
    connection and one disable-and-warn state.
    """
    path = store_path_for(hash_file)
    key = str(path)
    if key not in _stores:
        _stores[key] = CoverageStore(path)
    return _stores[key]


def reset_store() -> None:
    """Close and forget every open store (tests, config reloads)."""
    for store in _stores.values():
        store.close()
    _stores.clear()


# --- target identity -------------------------------------------------------


_target_memo: dict[str, tuple[int, int, str]] = {}


def clear_target_memo() -> None:
    _target_memo.clear()


def target_id(hash_file: str) -> str | None:
    """Content hash of the hash file, or None if it cannot be read.

    Returning None rather than raising lets every caller treat "we cannot
    identify this target" as "do not filter", which is the safe direction: an
    unfiltered run wastes time, a wrongly filtered one silently skips work.

    Memoized on ``(size, mtime_ns)`` for the life of the process. Hash files are
    usually small, but not always -- a large NTLM dump runs to hundreds of
    megabytes, and ``hcatCorporateMasks`` asks once per mask length, so an
    unmemoized read multiplied that by eight.
    """
    try:
        stat = os.stat(hash_file)
    except OSError:
        return None

    stamp = (stat.st_size, stat.st_mtime_ns)
    cached = _target_memo.get(hash_file)
    if cached is not None and cached[:2] == stamp:
        return cached[2]

    try:
        digest = _sha256_file(hash_file)
    except OSError:
        return None
    _target_memo[hash_file] = (stamp[0], stamp[1], digest)
    return digest


# --- rule / mask entry parsing --------------------------------------------


def read_entries(path: str) -> list[str]:
    """Read a rule or .hcmask file into its individual entries.

    Only the line terminator is removed. Rule lines are whitespace-significant
    -- ``$ `` appends a space, and stripping it would silently rewrite the rule
    as ``$`` -- so no other trimming happens. Blank lines and ``#`` comments are
    dropped, and duplicates are collapsed while preserving first-seen order so
    a filtered file we later write keeps the author's ordering.

    Read as bytes and decoded with ``surrogateescape`` so the round trip is
    lossless. Two reasons this matters rather than being pedantry: rule files in
    this project are not all UTF-8 (``rulegen.py`` writes latin-1), and
    ``errors="replace"`` would turn an undecodable byte into U+FFFD -- so the
    filtered file we hand back to hashcat would contain a *different rule*, and
    the store would record the mangled entry as covered permanently. Splitting
    is on ``\\n``/``\\r\\n`` only, unlike ``str.splitlines()``, which also
    breaks on ``\\x0b``, ``\\x0c``, ``\\x1c``-``\\x1e`` and U+2028/2029/0085 --
    every one of which a rule can legitimately append.

    Entries stay verbatim here even for .hcmask files, because the return value
    is also what gets written back out as a filtered file for hashcat to run.
    Mask normalization belongs in the key, not the content:
    :func:`canonical_mask_entry` does it at :func:`entry_hash` time.
    """
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError:
        return []

    text = raw.decode("utf-8", errors="surrogateescape")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    lines = [line[:-1] if line.endswith("\r") else line for line in lines]

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


def canonical_mask_entry(entry: str) -> str:
    """Reduce a mask entry to the candidate set it enumerates.

    Two hcmask lines with different text can try exactly the same candidates,
    and keying on raw text records the second one as uncovered. Only the custom
    charset fields cause this, in three ways HashcatRosetta's expansion
    resolves: a charset can be spelled as a token (``?d`` and ``0123456789``
    expand identically), hashcat deduplicates it (``aa`` is the charset ``a``),
    and its character order changes only the enumeration order, not the set.

    Whitespace is *not* normalized, deliberately. A mask is
    whitespace-significant in the same way a rule is -- a trailing space in
    ``?d?d `` is a literal space position, and a mask with one genuinely
    enumerates different candidates than a mask without it.

    Returns the entry unchanged when it has no custom charsets (so the
    overwhelmingly common plain-mask key is bit-identical to what earlier
    versions recorded), when the mask does not parse, or when the Rosetta
    submodule is unavailable. An unparseable mask is hashcat's problem to
    report, not this function's -- it must still get a stable key.
    """
    if _rosetta_parse_hcmask_line is None or _rosetta_expand_charsets is None:
        return entry
    if "," not in entry:
        # Fast path: no field separator means no custom charsets, so the
        # canonical form is the raw text. Avoids a parse per mask per key.
        return entry
    try:
        parsed = _rosetta_parse_hcmask_line(entry)
        if not parsed.custom:
            return entry
        expanded = _rosetta_expand_charsets(parsed.custom)
    except Exception:
        # Includes MaskError; a bad mask keys on its raw text.
        return entry

    # Sort within each charset (order is enumeration order only), but keep the
    # charsets in slot order -- ?1 and ?2 are not interchangeable.
    normalized = ["".join(sorted(set(charset))) for charset in expanded]
    return "\x00".join(normalized) + "\x00" + parsed.mask


def entry_hash(kind: str, entry: str) -> int:
    """64-bit identity of one rule line, mask line, or chained-rule unit.

    Masks are hashed in canonical form (see :func:`canonical_mask_entry`), so
    two spellings of one charset are one entry. Rules are hashed verbatim:
    their whitespace is significant and they have no normalization.

    The encode must be injective. ``surrogatepass`` keeps rules that differ
    only in non-UTF-8 bytes distinct -- ``errors="replace"`` once collapsed 154
    distinct Spoonman rules into shared keys -- and cannot raise on a lone
    surrogate the way ``surrogateescape`` can.

    Signed, because SQLite integers are signed 64-bit. A collision inside one
    (target, wordlist, variant, kind) scope would mark an untried entry
    covered; at 10M rows in a scope that is about 5e-13 per entry, accepted.
    """
    if kind == "mask":
        entry = canonical_mask_entry(entry)
    digest = hashlib.blake2b(
        entry.encode("utf-8", errors="surrogatepass"), digest_size=8
    ).digest()
    return int.from_bytes(digest, "big", signed=True)


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
    # Record what this run covers, but never filter it against what is already
    # covered. The two directions are not symmetric for a run that enumerates a
    # *superset* of its declared entries -- ``--loopback`` being the case that
    # motivates this. Such a run really does try every declared entry, so
    # recording it is sound and lets a later ordinary run of the same wordlist
    # and rules be recognised as a repeat. Filtering it would be unsound,
    # because the extra candidates differ every time.
    record_only: bool = False


@dataclass(frozen=True)
class RunPlan:
    """The filtering decision for one run.

    ``kind`` names the dimension that was diffed, which tells the caller how to
    apply ``filtered_entries``: rewrite ``source_path``'s file for ``"rule"``
    and ``"mask"``, or drop positional arguments for ``"wordlist"``. An inert
    plan (``kind == ""``) means coverage could not be established, so the run
    must proceed untouched and nothing is recorded.

    ``record_rows`` are the ``(wl_id, entry_h)`` pairs to record if the run
    completes; ``wordlist_ids`` are linked to the run row for
    ``has_prior_run``. Both are ids in the store for ``target``'s hash file.
    """

    kind: str = ""
    skip: bool = False
    covered_count: int = 0
    total_count: int = 0
    filtered_entries: list[str] | None = None
    source_path: str | None = None
    target: str = ""
    variant: str = ""
    record_rows: tuple[tuple[int, int], ...] = ()
    wordlist_ids: tuple[int, ...] = ()

    @property
    def has_overlap(self) -> bool:
        return self.covered_count > 0

    @property
    def is_inert(self) -> bool:
        return not self.kind


_INERT = RunPlan()


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


def plan_run(spec: CoverageSpec, store: CoverageStore | None = None) -> RunPlan:
    """Decide what of ``spec`` still needs running, given what is covered.

    Every failure to establish identity returns an inert plan, so the run
    proceeds in full. That bias is deliberate: an unfiltered run costs time,
    while a wrongly filtered one silently skips untried candidates.
    """
    target = target_id(spec.hash_file)
    if target is None:
        return _INERT

    store = store if store is not None else get_store(spec.hash_file)
    if not store.available():
        return _INERT

    wordlist_ids: list[int] = []
    for path in spec.wordlists:
        wl_id = store.wordlist_id(path)
        if wl_id is None:
            # Vanished, not a regular file, or the store just failed.
            return _INERT
        wordlist_ids.append(wl_id)

    def lookup(kind: str, wl_id: int, hashes: list[int]) -> set[int]:
        if spec.record_only:
            # A record-only run (loopback) never filters: report no overlap,
            # so every entry is novel and the whole declared set is recorded.
            return set()
        return store.covered(target, wl_id, spec.variant, kind, hashes)

    common = {
        "target": target,
        "variant": spec.variant,
        "lookup": lookup,
        "wordlist_ids": tuple(wordlist_ids),
    }

    if spec.rule_files:
        if len(spec.rule_files) > 1:
            entry = _chain_entry(spec.rule_files)
            if entry is None:
                return _INERT
            return _plan_entries(
                kind="rule",
                entries=[entry],
                source_path=None,
                filterable=False,
                **common,
            )
        entries = read_entries(spec.rule_files[0])
        if not entries:
            return _INERT
        return _plan_entries(
            kind="rule",
            entries=entries,
            source_path=spec.rule_files[0],
            filterable=True,
            **common,
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
            source_path=single_file,
            filterable=single_file is not None,
            **common,
        )

    if spec.wordlists:
        return _plan_wordlists(spec, **common)

    return _INERT


def _plan_entries(
    *,
    kind: str,
    entries: list[str],
    source_path: str | None,
    filterable: bool,
    target: str,
    variant: str,
    lookup: Callable[[str, int, list[int]], set[int]],
    wordlist_ids: tuple[int, ...],
) -> RunPlan:
    # A mask run has no wordlist, but still needs one slot to key against.
    slots = list(wordlist_ids) or [NO_WORDLIST]
    hashes = [entry_hash(kind, entry) for entry in entries]
    distinct = list(dict.fromkeys(hashes))
    covered_by_slot = {wl_id: lookup(kind, wl_id, distinct) for wl_id in slots}

    novel: list[str] = []
    record_rows: list[tuple[int, int]] = []
    for entry, entry_h in zip(entries, hashes):
        # Only fully-covered entries are dropped. An entry already tried
        # against one wordlist but not another must still run.
        if all(entry_h in covered_by_slot[wl_id] for wl_id in slots):
            continue
        novel.append(entry)
        record_rows.extend((wl_id, entry_h) for wl_id in slots)

    return _finish_plan(
        kind=kind,
        total=len(entries),
        novel=novel,
        display=novel,
        record_rows=record_rows,
        source_path=source_path,
        filterable=filterable,
        target=target,
        variant=variant,
        wordlist_ids=wordlist_ids,
    )


def _plan_wordlists(
    spec: CoverageSpec,
    *,
    target: str,
    variant: str,
    lookup: Callable[[str, int, list[int]], set[int]],
    wordlist_ids: tuple[int, ...],
) -> RunPlan:
    """A rule-less dictionary attack: each wordlist is itself the unit.

    Its row is ``(wl_id=<that wordlist>, entry_h=0)``.
    """
    novel_display: list[str] = []
    record_rows: list[tuple[int, int]] = []
    for path, wl_id in zip(spec.wordlists, wordlist_ids):
        if 0 in lookup("wordlist", wl_id, [0]):
            continue
        novel_display.append(path)
        record_rows.append((wl_id, 0))
    return _finish_plan(
        kind="wordlist",
        total=len(spec.wordlists),
        novel=novel_display,
        display=novel_display,
        record_rows=record_rows,
        source_path=None,
        filterable=True,
        target=target,
        variant=variant,
        wordlist_ids=wordlist_ids,
    )


def _finish_plan(
    *,
    kind: str,
    total: int,
    novel: list[str],
    display: list[str],
    record_rows: list[tuple[int, int]],
    source_path: str | None,
    filterable: bool,
    target: str,
    variant: str,
    wordlist_ids: tuple[int, ...],
) -> RunPlan:
    covered_count = total - len(novel)
    if not novel:
        return RunPlan(
            kind=kind,
            skip=True,
            covered_count=covered_count,
            total_count=total,
            source_path=source_path,
            target=target,
            variant=variant,
            wordlist_ids=wordlist_ids,
        )
    return RunPlan(
        kind=kind,
        skip=False,
        covered_count=covered_count,
        total_count=total,
        filtered_entries=display if (filterable and covered_count) else None,
        source_path=source_path,
        target=target,
        variant=variant,
        record_rows=tuple(record_rows),
        wordlist_ids=wordlist_ids,
    )
