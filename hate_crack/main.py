# Methodology provided by Martin Bos (pure_hate) - https://www.trustedsec.com/team/martin-bos/
# Original script created by Larry Spohn (spoonman) - https://www.trustedsec.com/team/larry-spohn/
# Python refactoring and general fixing, Justin Bollinger (bandrel) - https://www.trustedsec.com/team/justin-bollinger/
# Hashview integration by Justin Bollinger (bandrel) and Claude Sonnet 4.5
#   special thanks to hans for all his hard work on hashview and creating APIs for us to use

# Load config before anything that needs hashview_url/hashview_api_key

import sys
import os
import json
import shutil
import logging
import binascii
import glob
import random
import re
import readline
import signal
import subprocess
import shlex
import time
import argparse
import contextlib
import dataclasses
import gzip
import lzma
import tempfile
from types import SimpleNamespace

#!/usr/bin/env python3

from typing import Any, NamedTuple

requests: Any = None
REQUESTS_AVAILABLE = False

try:
    import requests as requests  # type: ignore[import-untyped, no-redef] # noqa: F401

    REQUESTS_AVAILABLE = True
except Exception:
    pass

# Ensure project root is on sys.path so package imports work when loaded via spec.
_root_dir = os.path.dirname(os.path.realpath(__file__))
if _root_dir not in sys.path:
    sys.path.insert(0, _root_dir)

# Allow submodule imports (hate_crack.*) even when this file is imported as a module.
_pkg_dir = os.path.dirname(os.path.realpath(__file__))
if os.path.isdir(_pkg_dir):
    __path__ = [_pkg_dir]
    if "__spec__" in globals() and __spec__ is not None:
        __spec__.submodule_search_locations = __path__

from hate_crack.api import (  # noqa: E402
    fetch_all_weakpass_wordlists_multithreaded,
    download_torrent_file,
    fetch_torrent_metadata,
    weakpass_wordlist_menu,
)
from hate_crack.api import HashviewAPI  # noqa: E402
from hate_crack.api import (  # noqa: E402
    download_all_weakpass_torrents,
    download_hashmob_wordlists,
    download_hashmob_rules,
    download_weakpass_torrent,
    extract_with_7z,
)
from hate_crack.cli import (  # noqa: E402
    resolve_path,
    setup_logging,
)
from hate_crack import attacks as _attacks  # noqa: E402
from hate_crack import config_loader as _config_loader  # noqa: E402
from hate_crack import config_schema as _config_schema  # noqa: E402
from hate_crack import hashcat_paths as _hashcat_paths  # noqa: E402
from hate_crack import config_writer as _config_writer  # noqa: E402
from hate_crack import llm  # noqa: E402
from hate_crack import noninteractive as _noninteractive  # noqa: E402
from hate_crack.progress import spinner  # noqa: E402
from hate_crack import corpus_stats as _corpus_stats  # noqa: E402
from hate_crack import plaintext as _plaintext  # noqa: E402
from hate_crack import rulegen as _rulegen  # noqa: E402
from hate_crack import attack_coverage as _coverage  # noqa: E402
from hate_crack.menu import interactive_menu  # noqa: E402
from hate_crack.username_detect import detect_username_hash_format  # noqa: E402

# Import HashcatRosetta for rule analysis functionality
ROSETTA_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "HashcatRosetta")
)
# Holds the ImportError when HashcatRosetta could not be imported, else None.
# Discarding it turned one missing submodule into a wall of unrelated assertion
# failures (#231); keep the reason so it can be reported where it is noticed.
ROSETTA_IMPORT_ERROR = None
try:
    sys.path.insert(0, ROSETTA_DIR)
    from hashcat_rosetta.debug_analyzer import DebugAnalyzer
    from hashcat_rosetta.formatting import display_rule_opcodes_summary
    from hashcat_rosetta.mask import MaskError as RosettaMaskError
    from hashcat_rosetta.mask import format_hcmask_line as rosetta_format_hcmask_line
    from hashcat_rosetta.mask import keyspace as rosetta_keyspace
    from hashcat_rosetta.mask import parse_hcmask_line as rosetta_parse_hcmask_line
except ImportError as rosetta_import_error:
    ROSETTA_IMPORT_ERROR = rosetta_import_error
    display_rule_opcodes_summary = None
    DebugAnalyzer = None
    RosettaMaskError = None
    rosetta_format_hcmask_line = None
    rosetta_keyspace = None
    rosetta_parse_hcmask_line = None


def rosetta_unavailable_reason():
    """Return a human-readable explanation for HashcatRosetta being missing."""
    message = (
        "HashcatRosetta is unavailable. Run: git submodule update --init HashcatRosetta"
    )
    if ROSETTA_IMPORT_ERROR is not None:
        message += f" (import failed: {ROSETTA_IMPORT_ERROR!r})"
    return message


EXCLUDED_WORDLIST_EXTENSIONS = frozenset({".7z", ".torrent", ".out"})


@dataclasses.dataclass(frozen=True)
class DirEntry:
    """One listing entry, with enough type information for the caller to decide.

    Pickers need to render directories differently and callers need to know
    whether a name can be handed to hashcat as a file, so the type travels with
    the name instead of every call site re-running os.path.isdir.
    """

    name: str
    is_dir: bool


def _visible_entries(directory):
    """Sorted ``DirEntry`` list for *directory*, dot-files excluded.

    Dot-files are dropped wholesale rather than by name: the previous code
    special-cased ``.DS_Store`` and so still offered ``.gitkeep`` and ``.keep``
    as wordlists. Nothing hate_crack reads is a dot-file.

    A missing path, or a path that is a file, yields ``[]``. Both happen in the
    field -- a wordlists directory that has not been created yet, and a
    ``hcatWordlists`` pointed at a single file -- and neither should crash a
    picker with a traceback.
    """
    try:
        names = os.listdir(directory)
    except PermissionError:
        print(f"[!] Cannot list {directory}: permission denied")
        return []
    except (FileNotFoundError, NotADirectoryError):
        return []
    entries = []
    for name in sorted(names):
        if name.startswith("."):
            continue
        entries.append(DirEntry(name, os.path.isdir(os.path.join(directory, name))))
    return entries


def list_wordlist_entries(directory):
    """Wordlist-directory listing including subdirectories.

    For pickers that can offer a directory: hashcat accepts one and consumes
    every file in it, so a directory is a legitimate selection -- it just has to
    be labelled as one. See :func:`list_wordlist_files` for callers that need
    files only.
    """
    return [
        entry
        for entry in _visible_entries(directory)
        if entry.is_dir
        or not any(entry.name.endswith(ext) for ext in EXCLUDED_WORDLIST_EXTENSIONS)
    ]


def list_wordlist_files(directory):
    """Wordlist filenames in *directory* -- files only, no directories.

    Do not reach for this just because a wordlist listing is wanted: a caller
    that hands the names to hashcat in the *dictionary position* of a straight
    (``-a 0``) command wants :func:`list_wordlist_entries`, because hashcat
    accepts a directory there and walks it -- and a wordlist collection
    unpacked into subdirectories is the normal shape, so filtering them out
    silently drops most of what the operator has. hcatDictionary and the
    Spoonman attack's baseword-source menu both use the sibling for that
    reason.

    Its two callers need files specifically, and neither is that case:
    hcatYoloCombination builds an ``-a 1`` command, where hashcat rejects a
    directory operand; and attacks.wordlist_optimize expands an
    operator-supplied directory into paths that main.wordlist_optimize opens
    itself (``os.path.isfile``/``open()``), which needs a real file rather than
    hashcat's own directory handling.
    """
    return [
        entry.name for entry in list_wordlist_entries(directory) if not entry.is_dir
    ]


def list_rule_files(directory):
    """Rule filenames in *directory* -- files only, no directories.

    A rules directory grows subdirectories as soon as someone unpacks a rules
    collection into it. ``-r <directory>`` is rejected by hashcat, and the LLM
    attack loops over every entry without a human watching.
    """
    return [entry.name for entry in _visible_entries(directory) if not entry.is_dir]


# Single source of truth is _config_schema.DEFAULT_OPTIMIZED_ATTACKS -- this
# used to be a hand-synced literal copy of that list, which is exactly the
# kind of drift that let hcatRosettaMask ship without -O for eleven days
# (#270) before anyone noticed.
DEFAULT_OPTIMIZED_ATTACKS = frozenset(_config_schema.DEFAULT_OPTIMIZED_ATTACKS)

# Every attack that consults the setting, whether or not it is optimized by
# default. The four names below honour optimizedKernelAttacks but are absent
# from the default set, so -O is opt-in for them: each pipes or feeds
# candidates that may exceed the length ceiling -O imposes, and turning them
# on by default would silently shrink the keyspace of an attack a user had
# already tuned.
#
# Nothing at runtime reads this set -- an unknown name in config.json is
# ignored by the membership test in _should_use_optimized_kernel. It exists so
# tests/test_config_json_example.py can enforce that the documented names and
# the names actually checked stay the same set: a name here that is never
# passed to _should_use_optimized_kernel is an inert config knob
# (hcatPrinceLing was one for several releases, because PRINCE-LING delegates
# to hcatPrince and that function checks its own name), and a name checked but
# missing here is one the docs never told the user about.
KNOWN_OPTIMIZABLE_ATTACKS = DEFAULT_OPTIMIZED_ATTACKS | {
    "hcatNgramX",
    "hcatOllama",
    "hcatOmen",
    "hcatLMtoNT",
}

_optimized_kernel_attacks = DEFAULT_OPTIMIZED_ATTACKS

# Set by --no-optimized-kernel for the lifetime of one run. A separate switch
# rather than an emptied _optimized_kernel_attacks so config.json keeps its
# meaning for the next run, and so the override is visible to anything that
# needs to explain why an attack is not optimized.
_optimized_kernel_disabled = False

# Whether the loaded hash file is pwdump format (user:rid:lm:nt:::). Set by
# main()'s detection block; defaulted here because cleanup() and the analysis
# menu entries read it, and a run that never reached detection used to raise
# NameError on exit (issue #211). False is the conservative default: it makes
# the pwdump-only merge a no-op rather than a data-loss risk.
pwdump_format = False


def _should_use_optimized_kernel(attack_name):
    """Return True if *attack_name* should use hashcat's -O (optimized kernels)."""
    if _optimized_kernel_disabled:
        return False
    return attack_name in _optimized_kernel_attacks


def _optimized_kernel_drift(configured):
    """Return the default-optimized attacks *configured* leaves out, sorted.

    ``optimizedKernelAttacks`` is a whole-list opt-in and
    :data:`DEFAULT_OPTIMIZED_ATTACKS` is only the fallback, so once a
    config.json exists it supplies the entire list. An attack added after that
    file was written is therefore absent from it forever and never gets ``-O``
    (#270). Nothing surfaced this: the attack still runs and still cracks, and
    the only symptom is reduced speed, which is indistinguishable from the
    attack simply being expensive. hcatRosettaMask shipped degraded for eleven
    days before anyone noticed.

    A name the user deliberately removed is indistinguishable from one that
    never existed when the file was written, so this only reports -- the caller
    warns and the user decides.
    """
    return sorted(DEFAULT_OPTIMIZED_ATTACKS - set(configured))


def _warn_optimized_kernel_drift(missing, config_path=None):
    """Name each attack in *missing* that will silently run without ``-O``.

    Silent under ``SKIP_INIT``, matching :func:`_print_discovery_warnings`: the
    test suite imports this module constantly.
    """
    if SKIP_INIT or not missing:
        return
    where = f" in {config_path}" if config_path else ""
    print(
        f"[!] optimizedKernelAttacks{where} is missing "
        f"{len(missing)} attack(s) that use -O by default. "
        "They will run unoptimized:"
    )
    for name in missing:
        print(f"[!]   {name}")
    print("[!] Add them to optimizedKernelAttacks to enable -O for those attacks.")


def _strip_optimized_flags(tuning):
    """Return *tuning* with any hand-written -O removed.

    ``hcatTuning`` is passed through verbatim to every hashcat invocation, so an
    ``-O`` living there would survive --no-optimized-kernel and make the flag a
    lie. Split and rejoin with shlex so quoting in the rest of the string is
    preserved.
    """
    kept = [
        token
        for token in shlex.split(tuning or "")
        if token not in ("-O", "--optimized-kernel-enable")
    ]
    return " ".join(shlex.quote(token) for token in kept)


def disable_optimized_kernel():
    """Turn off hashcat's -O for every attack in this run.

    Covers both routes it can reach the command line: the per-attack
    ``optimizedKernelAttacks`` config list, and a literal ``-O`` in
    ``hcatTuning``.
    """
    global _optimized_kernel_disabled, hcatTuning
    _optimized_kernel_disabled = True
    hcatTuning = _strip_optimized_flags(hcatTuning)


class FlagOverrides(NamedTuple):
    """The per-run effective value of every schema-backed preference flag."""

    debug: bool
    update_channel: str
    weakpass_min_rank: int
    restore_potfile: bool
    optimized_kernel_disabled: bool
    potfile_path: str
    rule_debug_mode_enabled: bool
    coverage_enabled: bool


def _flag_or_config(flag_value, config_value):
    """Resolve one tri-state flag against its config-supplied default.

    ``None`` means the flag was absent, so the config value (which the loader
    already resolved from the key's own home file, the schema default and the
    real environment) wins. Anything else -- including ``False`` and ``0`` -- is an
    explicit per-run statement and outranks the config.

    This tri-state is why none of the promoted booleans may use
    ``action="store_true"``: that action makes "absent" and "explicitly false"
    both ``False``, so the flag could never turn a config-enabled setting off.
    Each one uses ``argparse.BooleanOptionalAction`` with ``default=None``.
    """
    if flag_value is None:
        return config_value
    return flag_value


def resolve_flag_overrides(
    args,
    config,
    *,
    base_dir,
    current_potfile_path=None,
    hcat_bin="hashcat",
):
    """Resolve the seven promoted preference flags against loaded ``config``.

    ``args`` is anything with the argparse attribute names (a
    ``SimpleNamespace`` is fine); ``config`` is a ``config_parser``-shaped
    mapping of legacy key names to coerced values; ``base_dir`` is the
    directory a relative ``--potfile-path`` is resolved against.

    ``hcat_bin`` is the binary a ``"auto"`` potfile setting is resolved
    against. It matters: probing whatever ``hashcat`` is on ``$PATH`` when
    ``hcatBin`` points at a different install (a vendored build, or an
    explicit path in ``config.json``) can resolve to the *other* version's
    data directory -- which on a hashcat 7 box means handing it the legacy
    ``~/.hashcat`` path and recreating the directory all over again.

    Precedence for each key is CLI flag > os.environ > that key's own home file
    > schema default. There is no cross-file fallthrough: each key lives in
    exactly one of ``.env`` or ``config.json`` (all seven resolved here are
    ``config.json`` keys) and an entry in the other file is ignored with a
    warning. The loader owns the bottom three and has already collapsed
    them into ``config``; this function only layers the flag on top. It is
    deliberately pure so it can be unit tested without building the parser.
    """
    nightly = getattr(args, "nightly", None)
    if nightly is None:
        update_channel = config.get("update_channel", "main")
    else:
        update_channel = "nightly-dev" if nightly else "main"

    # --potfile-path is checked before --no-potfile-path: when both are passed
    # the explicit path wins, matching the pre-existing dispatch order (see
    # tests/test_cli_flags.py::test_potfile_path_and_no_potfile_path_conflict).
    if getattr(args, "potfile_path", None) is not None:
        # Empty string means: revert to hashcat's default behavior. "auto"
        # resolves to hashcat's own per-user potfile.
        potfile_path = _hashcat_paths.resolve_potfile_setting(
            args.potfile_path, base_dir=base_dir, hcat_bin=hcat_bin
        )
    elif getattr(args, "no_potfile_path", False):
        potfile_path = ""
    elif current_potfile_path is not None:
        # Module import time already normalized hcatPotfilePath (expanduser and
        # relative-to-hate_path); re-deriving it from ``config`` here would
        # drop that work, so the
        # no-flag case keeps the value main() hands in.
        potfile_path = current_potfile_path
    else:
        potfile_path = _hashcat_paths.resolve_potfile_setting(
            config.get("hcatPotfilePath", ""), base_dir=base_dir, hcat_bin=hcat_bin
        )

    return FlagOverrides(
        debug=bool(_flag_or_config(getattr(args, "debug", None), config.get("debug"))),
        update_channel=update_channel,
        weakpass_min_rank=int(
            _flag_or_config(
                getattr(args, "rank", None), config.get("weakpass_min_rank", -1)
            )
        ),
        restore_potfile=bool(
            _flag_or_config(
                getattr(args, "restore_potfile", None),
                config.get("restore_potfile_on_start", False),
            )
        ),
        # --no-optimized-kernel is a blanket override that empties the
        # optimizedKernelAttacks list for this run; there is no affirmative
        # form to re-enable a config that disabled it, because the key is a
        # list of attack names, not a bool -- `"optimizedKernelAttacks": []` in
        # config.json is how you turn it off persistently. Note that route is not
        # folded in here: an empty list means "no attack gets -O", whereas the
        # flag additionally strips a hand-written -O out of hcatTuning, and
        # quietly extending that to the config list would change behavior for
        # existing configs.
        optimized_kernel_disabled=bool(getattr(args, "no_optimized_kernel", False)),
        potfile_path=potfile_path,
        rule_debug_mode_enabled=bool(
            _flag_or_config(
                getattr(args, "rule_debug_mode", None),
                config.get("rule_debug_mode_enabled", True),
            )
        ),
        coverage_enabled=bool(
            _flag_or_config(
                getattr(args, "coverage", None),
                config.get("coverage_enabled", True),
            )
        ),
    )


def _insert_optimized_flag(cmd):
    """Insert -O into *cmd* if not already present (from hcatTuning or elsewhere)."""
    if "-O" not in cmd and "--optimized-kernel-enable" not in cmd:
        cmd.append("-O")


_DOUBLE_INTERRUPT_WINDOW = 2.0
_last_interrupt_time: float = 0.0


class DoubleInterrupt(Exception):
    """Raised when Ctrl+C is pressed twice within _DOUBLE_INTERRUPT_WINDOW seconds."""


def _sigint_handler(signum: int, frame: Any) -> None:
    global _last_interrupt_time
    now = time.time()
    if now - _last_interrupt_time <= _DOUBLE_INTERRUPT_WINDOW:
        raise DoubleInterrupt()
    _last_interrupt_time = now
    raise KeyboardInterrupt()


def _has_hate_crack_assets(path):
    if not path:
        return False
    return os.path.isfile(os.path.join(path, "config.json.example")) and os.path.isdir(
        os.path.join(path, "hashcat-utils")
    )


def _candidate_roots():
    """Directory search order for configuration files.

    Delegates to :func:`hate_crack.config_loader.candidate_roots`, which is
    the single definition of this order (``api.py`` uses it too). Kept as a
    thin wrapper because ``_resolve_config_destination()`` and the test suite
    both reference it by this name.
    """
    return _config_loader.candidate_roots()


def _resolve_config_destination():
    for candidate in _candidate_roots():
        if _has_hate_crack_assets(candidate):
            return candidate
    fallback = os.path.join(os.path.expanduser("~"), ".hate_crack")
    os.makedirs(fallback, exist_ok=True)
    return fallback


def _ensure_hashfile_in_cwd(hashfile_path):
    """Return hashfile path as-is.

    Output files (.out, .nt, etc.) are written next to the hashfile.
    ``resolve_path()`` already resolves relative paths against
    ``HATE_CRACK_ORIG_CWD`` so no relocation is needed.
    """
    return hashfile_path


# hate_path is where hate_crack assets live (hashcat-utils, princeprocessor, etc.)
# When installed via `make install`, assets are vendored into the package directory.
# During development, assets live in the repo root (parent of the package directory).
_package_path = os.path.dirname(os.path.realpath(__file__))
_repo_root = os.path.dirname(_package_path)
if os.path.isdir(os.path.join(_package_path, "hashcat-utils")):
    hate_path = _package_path
elif os.path.isdir(os.path.join(_repo_root, "hashcat-utils")):
    hate_path = _repo_root
else:
    hate_path = _package_path
# omen may not be vendored into hate_path (e.g. dev checkout with only some submodules built).
# Check hate_path first, then fall back to repo root.
_omen_dir = (
    os.path.join(hate_path, "omen")
    if os.path.isdir(os.path.join(hate_path, "omen"))
    else os.path.join(_repo_root, "omen")
)
# Corporate_Masks may not be vendored into hate_path (e.g. dev checkout with only some submodules built).
# Check hate_path first, then fall back to repo root.
_corporate_masks_dir = (
    os.path.join(hate_path, "Corporate_Masks")
    if os.path.isdir(os.path.join(hate_path, "Corporate_Masks"))
    else os.path.join(_repo_root, "Corporate_Masks")
)
SKIP_INIT = os.environ.get("HATE_CRACK_SKIP_INIT") == "1"

# The legacy names of the home="env" keys, derived from the schema so this
# cannot drift when a thirteenth integration key is added.
_INTEGRATION_LEGACY_KEYS = frozenset(entry.legacy for entry in _config_schema.ENV_KEYS)


# Sentinel for "config.json exists but could not be read or parsed", which is
# distinct from both "no integration keys" and "some integration keys".
_CONFIG_JSON_UNUSABLE = object()


def _read_config_json_for_bootstrap(legacy_json_path):
    """Parse ``legacy_json_path``, or return :data:`_CONFIG_JSON_UNUSABLE`.

    Deliberately does not raise and does not print: the loader reports a
    malformed or unreadable ``config.json`` fatally a few lines later, with the
    file-shaped diagnostic that names permissions and dangling symlinks, and a
    second guess from here would only compete with it.

    The three-way answer matters. Collapsing the failure case into "no
    integration keys" made the bootstrap create a ``.env`` from defaults for a
    startup that was about to exit(1) anyway -- and because the write target is
    ``_resolve_config_destination()`` rather than the directory the unreadable
    file was found in, that stray file landed somewhere the user was not even
    looking (typically ``~/.hate_crack/.env`` while they were staring at a
    ``config.json`` in the repo). See
    tests/test_config_startup_wiring.py::test_unusable_config_json_writes_nothing_at_all.
    """
    try:
        with open(legacy_json_path) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return _CONFIG_JSON_UNUSABLE


# How each config file came to exist, when this run created it. Filled in by
# the two _initialize_* helpers and read once, at startup, by
# _print_config_sources() -- keys "env" and "json". It exists so the bootstrap
# can stop printing its own near-duplicate path block (#227) without losing the
# one fact only it knows: which template or source file was used.
_config_bootstrap_detail: dict[str, str] = {}


def _bootstrap_config_files(env_path, legacy_json_path):
    """Ensure both config files exist (unless ``SKIP_INIT``); return their paths.

    Returns ``(env_path, legacy_json_path)``. Each file is created only if it
    is missing; neither is ever rewritten, and ``config.json`` is never
    modified.

    The cases, in order:

    0. ``SKIP_INIT`` -> write nothing at all, whatever is or isn't present.
       The test suite imports this module constantly; creating config files in
       the repo or in ``~/.hate_crack`` as a side effect of an import is not
       acceptable, so this branch comes first.
    1. ``config.json`` present, `.env` absent, ``config.json`` holds at least
       one integration key -> lift those keys into a new `.env` via
       :func:`hate_crack.config_writer.write_env_from_legacy` and print its
       notes, which name the keys the user must now delete from
       ``config.json`` themselves.
    2. ``config.json`` present, `.env` absent, no integration keys -> write a
       `.env` from schema defaults anyway, so the file exists to be edited.
       (Chosen over writing nothing: without it, a user who wants to set
       ``HASHMOB_API_KEY`` has to know both that `.env` is where it goes and
       that they must create it, and the post-condition "both files exist"
       matches case 4.)
    3. Both present -> nothing to do. Misplaced keys in either file are the
       loader's business, and it warns about each one on every run.
    4. Neither present -> create both, ``config.json`` from
       ``config.json.example`` exactly as this module did before the split.

    One cross-cutting rule: if ``config.json`` exists but cannot be read or
    parsed, **nothing is written at all**. Startup is about to exit(1) with the
    loader's file diagnostic, so creating a `.env` on the way out would leave a
    stray file behind (in the resolved config destination, not necessarily
    beside the file that failed) for a run that never got anywhere.
    """
    if SKIP_INIT:
        return env_path, legacy_json_path

    if legacy_json_path is None:
        legacy_json_path = _initialize_config_json()

    if env_path is None:
        env_path = _initialize_env(legacy_json_path)

    return env_path, legacy_json_path


def _initialize_config_json():
    """Copy ``config.json.example`` to the resolved config directory.

    Prints nothing on success: the destination, and the fact it was created
    this run, are reported once by :func:`_print_config_sources` via
    :data:`_config_bootstrap_detail` (#227). The bootstrap used to print a
    three-line "Initializing / source / destination" block immediately above
    those lines, saying the same thing in different words.
    """
    src_config = os.path.abspath(os.path.join(_package_path, "config.json.example"))
    destination = os.path.join(_resolve_config_destination(), "config.json")
    try:
        shutil.copy(src_config, destination)
    except OSError as exc:
        print(f"[!] Could not write {destination}: {exc}")
        return None
    _config_bootstrap_detail["json"] = f"from {os.path.basename(src_config)}"
    return destination


def _initialize_env(legacy_json_path):
    """Create the `.env`, migrating integration keys out of ``config.json``.

    Returns ``None`` without writing anything when ``config.json`` exists but is
    unusable -- see :func:`_read_config_json_for_bootstrap`.

    Like :func:`_initialize_config_json`, says nothing about paths itself; the
    migration's *source* (which the user does need -- it tells them their
    ``config.json`` was read) travels to the single startup line via
    :data:`_config_bootstrap_detail`. The per-key migration notes are unique
    information and are still printed here.
    """
    migrating = False
    if legacy_json_path is not None:
        data = _read_config_json_for_bootstrap(legacy_json_path)
        if data is _CONFIG_JSON_UNUSABLE:
            return None
        migrating = isinstance(data, dict) and any(
            key in data for key in _INTEGRATION_LEGACY_KEYS
        )
    destination = os.path.join(_resolve_config_destination(), ".env")
    if migrating:
        try:
            notes = _config_writer.write_env_from_legacy(legacy_json_path, destination)
        except OSError as exc:
            print(f"[!] Could not write {destination}: {exc}")
            return None
        for note in notes:
            print(f"[!] {note}")
        # "the config.json above" rather than the path again: that path is the
        # one _print_config_sources() prints on the immediately preceding line,
        # and it is always this migration's source, so repeating it in full
        # would reintroduce exactly the duplication #227 is about.
        _config_bootstrap_detail["env"] = (
            "third-party integration settings migrated from the config.json above"
        )
        return destination
    try:
        _config_writer.write_env(destination, {})
    except OSError as exc:
        print(f"[!] Could not write {destination}: {exc}")
        return None
    _config_bootstrap_detail["env"] = "from built-in defaults"
    return destination


def _finish_stale_migration(env_path, legacy_json_path):
    """Finish a migration stranded by a later schema change.

    The loader has just warned, once per key, that some ``config.json`` entries
    are ignored because they belong in the `.env`. Acting on those warnings meant
    hand-editing JSON, so in practice they printed on every start forever. This
    does the move instead.

    Unprompted, matching the first-stage migration in
    :func:`hate_crack.config_writer.write_env_from_legacy`, which also rewrites
    ``config.json`` without asking. There is nothing to weigh: the keys are
    already being ignored, so leaving them preserves only the warning. It also
    means scheduled and piped runs get repaired too -- gating this on a tty would
    leave exactly the automated runs nobody is watching printing the warnings
    forever.

    Skipped when ``SKIP_INIT`` is set -- the test suite imports this module
    constantly and rewriting config as an import side effect is not acceptable --
    or when either path is unresolved, in which case the bootstrap above owns the
    situation and has already done the right thing.

    Any failure is reported and swallowed: tidying config must never be the
    reason hate_crack fails to start.
    """
    if SKIP_INIT or not env_path or not legacy_json_path:
        return
    try:
        notes = _config_writer.finish_stale_migration(legacy_json_path, env_path)
    except Exception as exc:
        print(f"[!] Could not tidy {legacy_json_path}: {exc}")
        return
    for note in notes:
        print(f"[!] {note}")


def _describe_config_source(path, created, detail=None):
    """One right-hand side for :func:`_print_config_sources`."""
    if path is None:
        return "not found -- using built-in defaults"
    if not created:
        return path
    if detail:
        return f"{path} (created this run, {detail})"
    return f"{path} (created this run)"


def _print_config_sources(
    env_path,
    legacy_json_path,
    *,
    env_created,
    json_created,
    env_detail=None,
    json_detail=None,
):
    """Name the two config files this run actually loaded.

    Two lines, always the same two lines, printed before the loader's warnings
    so each warning reads against a file the user has just been shown.

    This is not decoration. ``config_loader.candidate_roots()`` searches the
    repo root *before* ``~/.hate_crack``, so a stray `.env` left in any
    checkout silently outranks the user's real one -- and running the tool from
    a checkout is exactly what creates such a file. Separately, a `.env` in the
    current working directory is never consulted at all: that is deliberate
    (engagement directories are full of files nobody intends as configuration)
    but it is invisible without this output. Printing the resolved paths
    answers all three questions -- which directory won, whether a file was just
    created, and whether the file being edited is even in the search order --
    in the two lines before anything else happens.

    Also the only place a just-created file's provenance is reported -- the
    ``detail`` arguments carry what the removed bootstrap prints used to say
    (#227).

    Silent under ``SKIP_INIT``: the test suite imports this module constantly.
    """
    if SKIP_INIT:
        return
    print(
        "[*] config.json: "
        f"{_describe_config_source(legacy_json_path, json_created, json_detail)}"
    )
    print(
        f"[*] .env:        {_describe_config_source(env_path, env_created, env_detail)}"
    )


def _print_discovery_warnings(warnings):
    """Print any :func:`hate_crack.config_loader.resolve_config_paths`
    shadowing warnings (#246), one per line.

    Printed after :func:`_print_config_sources` so each warning reads against
    the two paths just named. Silent under ``SKIP_INIT``, matching
    :func:`_print_config_sources`: the test suite imports this module
    constantly.
    """
    if SKIP_INIT:
        return
    for warning in warnings:
        print(f"[!] {warning}")


try:
    _env_path, _legacy_json_path, _discovery_warnings = (
        _config_loader.resolve_config_paths()
    )
except _config_loader.ConfigFileUnreadableError as _exc:
    # Discovery itself can fail now: a dangling `.env`/config.json symlink is
    # fatal rather than silently ignored (#227). Same diagnostic the loader
    # would have printed had the path been readable enough to reach it.
    _config_loader.exit_unreadable_config(_exc)
_env_missing_before_bootstrap = _env_path is None
_json_missing_before_bootstrap = _legacy_json_path is None
_env_path, _legacy_json_path = _bootstrap_config_files(_env_path, _legacy_json_path)
_print_config_sources(
    _env_path,
    _legacy_json_path,
    env_created=_env_missing_before_bootstrap,
    json_created=_json_missing_before_bootstrap,
    env_detail=_config_bootstrap_detail.get("env"),
    json_detail=_config_bootstrap_detail.get("json"),
)
_print_discovery_warnings(_discovery_warnings)

# The loader is the single definition of the precedence stack: for each key,
# schema default < that key's own home file < os.environ. config_parser stays
# a plain dict keyed by the legacy JSON key names, with values already coerced
# to their final Python types, because ~180 lines below here read it that way.
_config_result = _config_loader.load_config_or_exit(
    env_path=_env_path,
    legacy_json_path=_legacy_json_path,
)
config_parser = _config_result.config
for _warning in _config_result.warnings:
    print(f"[!] {_warning}")

_finish_stale_migration(_env_path, _legacy_json_path)

# The real environment already outranks both config files inside the loader
# (that is what
# lets HASHVIEW_URL / HASHVIEW_API_KEY point the CLI at a local docker
# stack without editing the persisted config), so these are read like every
# other key. Do not re-apply os.environ here: a second application would bypass the
# loader's coercion.
hashview_url = config_parser["hashview_url"]
hashview_api_key = config_parser["hashview_api_key"]

logger = logging.getLogger("hate_crack")
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


def _argv_requests_help_or_version(argv=None):
    """True if argv asks for help/version -- these don't need the toolchain."""
    if argv is None:
        argv = sys.argv[1:]
    return any(a in ("-h", "--help", "--version") for a in argv)


def ensure_binary(binary_path, build_dir=None, name=None):
    if not os.path.isfile(binary_path) or not os.access(binary_path, os.X_OK):
        if build_dir:
            if not os.path.isdir(build_dir):
                print(f"Error: Build directory {build_dir} does not exist.")
                print(f"Expected to find {name or 'binary'} at {binary_path}.")
                print(
                    "\nThe hate_crack assets (hashcat-utils, princeprocessor) could not be found."
                )
                print(
                    "\nRun 'make install' from the repository directory to install with assets:"
                )
                print("  cd /path/to/hate_crack && make install")
                sys.exit(1)

            # Binary missing - need to build
            print(f"Error: {name or 'binary'} not found at {binary_path}.")
            print("\nPlease build the utilities by running:")
            print(f"  cd {build_dir} && make")
            print("\nEnsure build tools (gcc, make) are installed on your system.")
            sys.exit(1)
        else:
            print(
                f"Error: {name or binary_path} not found or not executable at {binary_path}."
            )
            sys.exit(1)
    return binary_path


# NOTE: hcatPath is the hashcat install directory, NOT for hate_crack assets.
# hashcat-utils and princeprocessor should ALWAYS use hate_path.
hcatPath = os.path.expanduser(config_parser.get("hcatPath", ""))
hcatBin = config_parser["hcatBin"]
# If hcatBin is not absolute and hcatPath is set, construct full path from hcatPath + hcatBin
if not os.path.isabs(hcatBin) and hcatPath:
    _candidate = os.path.join(hcatPath, hcatBin)
    if os.path.isfile(_candidate):
        hcatBin = _candidate
# When hcatPath is not configured, discover it from the hashcat binary in PATH
if not hcatPath:
    _which = shutil.which(hcatBin)
    if _which:
        hcatPath = os.path.dirname(os.path.realpath(_which))
# Fall back to the vendored hashcat binary if not found via PATH or hcatPath
if shutil.which(hcatBin) is None and not os.path.isfile(hcatBin):
    _vendored_hcat = os.path.join(hate_path, "hashcat", "hashcat")
    if os.path.isfile(_vendored_hcat) and os.access(_vendored_hcat, os.X_OK):
        hcatBin = _vendored_hcat
        hcatPath = os.path.join(hate_path, "hashcat")
hcatTuning = config_parser["hcatTuning"]
hcatWordlists = config_parser["hcatWordlists"]
hcatRules: list[str] = []


# Optional: override hashcat's default potfile location.
# Default: `auto`, which resolves to whatever the installed hashcat uses --
# ~/.local/share/hashcat/hashcat.potfile on 7+, ~/.hashcat/hashcat.potfile on 6.
# Disable override with config `hcatPotfilePath: ""` or CLI `--no-potfile-path`.
# The loader seeds every schema key, so the key is always present and there is
# no "no key at all" discovery case to handle (the pre-split cwd-relative
# fallback is gone -- see CHANGELOG).
hcatPotfilePath = _hashcat_paths.resolve_potfile_setting(
    config_parser.get("hcatPotfilePath"),
    base_dir=hate_path,
    hcat_bin=hcatBin,
)


def _normalize_ollama_url(host: str) -> str:
    """Turn an ``OLLAMA_HOST`` value into a usable base URL.

    Ollama's own tooling accepts both a bare ``host:port`` and a full URL, so
    accept either.  Only prepend ``http://`` when no scheme is present;
    unconditionally prepending it produced URLs like
    ``http://https://ollama.example.com``.  Trailing slashes are stripped
    because callers append paths (``f"{ollamaUrl}/v1"``).
    """
    host = (host or "").strip()
    if not host:
        return "http://localhost:11434"
    if "://" not in host:
        host = "http://" + host
    return host.rstrip("/")


def _warn_stale_hashcat_home(*, hcat_bin=None):
    """Tell the operator when data is stranded in the pre-7 ``~/.hashcat``.

    hashcat prints its own notice whenever that directory merely exists; this
    one fires only when the directory still holds something, and says how to
    move it. Silent when there is nothing to act on.
    """
    try:
        message = _hashcat_paths.legacy_home_warning(hcat_bin or hcatBin)
    except OSError:
        return
    if message:
        print(message)


def _run_hashcat_home_migration(*, hcat_bin=None):
    """Back the ``--migrate-hashcat-home`` flag."""
    bin_name = hcat_bin or hcatBin
    try:
        result = _hashcat_paths.migrate_legacy_home(hcat_bin=bin_name)
    except OSError as exc:
        print(f"[!] Migration failed: {exc}")
        return

    if result.source == result.destination:
        print(f"[*] Nothing to do: this hashcat still uses {result.source}.")
        return
    if not result.copied and not result.skipped:
        print(f"[*] Nothing to migrate: {result.source} does not exist or is empty.")
        return

    print(f"[*] Copied from {result.source} to {result.destination}:")
    for name in result.copied:
        print(f"      {name}")
    for name in result.skipped:
        print(f"    [!] skipped (already present or unreadable): {name}")
    print(
        "[*] Nothing was deleted. Once you have checked the copies, "
        f"remove {result.source} yourself to silence hashcat's notice."
    )


def _maybe_append_username_flag(cmd):
    """Append --username if the active hash file has user:hash format and
    the flag isn't already present (from hcatTuning or elsewhere)."""
    if hcatUsernamePrefix and "--username" not in cmd:
        cmd.append("--username")


def _append_potfile_arg(cmd, *, use_potfile_path=True, potfile_path=None):
    if use_potfile_path:
        pot = potfile_path or hcatPotfilePath
        if pot:
            try:
                pot_dir = os.path.dirname(pot)
                if pot_dir:
                    os.makedirs(pot_dir, exist_ok=True)
                if not os.path.exists(pot):
                    open(pot, "a").close()
            except OSError:
                pass
            cmd.append(f"--potfile-path={pot}")
    _maybe_append_username_flag(cmd)
    _debug_cmd(cmd)


rulesDirectory = config_parser["rules_directory"]
if not rulesDirectory:
    rulesDirectory = (
        os.path.join(hcatPath, "rules")
        if hcatPath
        else os.path.join(hate_path, "rules")
    )
rulesDirectory = os.path.expanduser(rulesDirectory)
if not os.path.isabs(rulesDirectory):
    rulesDirectory = os.path.join(hate_path, rulesDirectory)

# Normalize wordlist directory
hcatWordlists = os.path.expanduser(hcatWordlists)
if not os.path.isabs(hcatWordlists):
    hcatWordlists = os.path.normpath(os.path.join(hate_path, hcatWordlists))
if not os.path.isdir(hcatWordlists):
    fallback_wordlists = os.path.join(hate_path, "wordlists")
    if os.path.isdir(fallback_wordlists):
        print(f"[!] hcatWordlists directory not found: {hcatWordlists}")
        print(f"[!] Falling back to {fallback_wordlists}")
        hcatWordlists = fallback_wordlists

hcatOptimizedWordlists = config_parser.get("hcatOptimizedWordlists", "")
if hcatOptimizedWordlists:
    hcatOptimizedWordlists = os.path.expanduser(hcatOptimizedWordlists)
    if not os.path.isabs(hcatOptimizedWordlists):
        hcatOptimizedWordlists = os.path.normpath(
            os.path.join(hate_path, hcatOptimizedWordlists)
        )
    if not os.path.isdir(hcatOptimizedWordlists):
        fallback_optimized = os.path.join(hate_path, "optimized_wordlists")
        if os.path.isdir(fallback_optimized):
            print(
                f"[!] hcatOptimizedWordlists directory not found: {hcatOptimizedWordlists}"
            )
            print(f"[!] Falling back to {fallback_optimized}")
            hcatOptimizedWordlists = fallback_optimized
        else:
            hcatOptimizedWordlists = hcatWordlists
else:
    hcatOptimizedWordlists = hcatWordlists

maxruntime = config_parser["bandrelmaxruntime"]
bandrelbasewords = config_parser["bandrel_common_basedwords"]
pipal_count = config_parser["pipal_count"]
pipalPath = config_parser["pipalPath"]

hcatDictionaryWordlist = config_parser["hcatDictionaryWordlist"]
hcatHybridlist = config_parser["hcatHybridlist"]
hcatCombinationWordlist = config_parser["hcatCombinationWordlist"]
hcatFingerprintWordlist = config_parser["hcatFingerprintWordlist"]
hcatMiddleCombinatorMasks = config_parser["hcatMiddleCombinatorMasks"]
hcatMiddleBaseList = config_parser["hcatMiddleBaseList"]
hcatThoroughCombinatorMasks = config_parser["hcatThoroughCombinatorMasks"]
hcatThoroughBaseList = config_parser["hcatThoroughBaseList"]
hcatPrinceBaseList = config_parser["hcatPrinceBaseList"]
hcatGoodMeasureBaseList = config_parser["hcatGoodMeasureBaseList"]

hcatDebugLogPath = os.path.expanduser(config_parser["hcatDebugLogPath"])

ollamaUrl = _normalize_ollama_url(config_parser.get("ollamaHost", "localhost:11434"))
ollamaModel = config_parser.get("ollamaModel", "qwen2.5:32b")
ollamaNoCloud = bool(config_parser.get("ollamaNoCloud", False))
ollamaNumCtx = int(config_parser.get("ollamaNumCtx", 8192))
ollamaTimeout = float(config_parser.get("ollamaTimeout", 300))
ollamaMaxSampleLines = int(config_parser.get("ollamaMaxSampleLines", 500))
ollamaAutoResearch = bool(config_parser.get("ollamaAutoResearch", True))
# Which OpenAI-compatible server the LLM attacks talk to (see llm.backend_extra_body
# for why "vllm" and "openai" each need a different request shape) and the
# credential it authenticates with. The ollama* settings above still supply
# the host, model, timeout, context and sampling for every backend.
llmBackend = config_parser.get("llmBackend", "ollama")
llmApiKey = config_parser.get("llmApiKey", "ollama")

hcatCorpusProfileMaxLines = int(config_parser.get("hcatCorpusProfileMaxLines", 5000000))
omenMaxCandidates = int(config_parser.get("omenMaxCandidates", 100000000))
pcfgRuleset = config_parser.get("pcfgRuleset", "Default")
pcfgMaxCandidates = int(config_parser.get("pcfgMaxCandidates", 50000000))
pcfgPrinceLingMaxCandidates = int(
    config_parser.get("pcfgPrinceLingMaxCandidates", 10000000)
)
hcatSmartMaskMinClusterSize = int(config_parser.get("hcatSmartMaskMinClusterSize", 3))

try:
    _cfg_optimized = config_parser["optimizedKernelAttacks"]
    if isinstance(_cfg_optimized, list):
        _optimized_kernel_attacks = frozenset(_cfg_optimized)
        # A config.json predating an attack pins the list without it, so the
        # attack silently loses -O (#270). Warn rather than repair: the list is
        # also how a user deliberately opts an attack out, and the two cases
        # are indistinguishable from here.
        _warn_optimized_kernel_drift(
            _optimized_kernel_drift(_optimized_kernel_attacks),
            _legacy_json_path,
        )
except KeyError:
    pass
check_for_updates_enabled = config_parser.get("check_for_updates", True)

# Notification subsystem bootstrap.  The notify module stores its own
# settings snapshot; we hand it the resolved `config.json` path so it can
# rewrite the notify_enabled / notify_per_crack_enabled / notify_attack_allowlist
# keys when the user toggles them or answers "always" at a prompt.  Those three
# are home="json"; the Pushover credentials in `.env` are never written from
# the menu.  ``None`` is legitimate under SKIP_INIT with no config file on
# disk: the toggles then stay in-memory rather than creating one as a side
# effect.
from hate_crack import notify as _notify  # noqa: E402  (kept close to config load)

_notify.init(_legacy_json_path, config_parser)

hcatExpanderBin = "expander.bin"
hcatCombinatorBin = "combinator.bin"
hcatPrinceBin = "pp64.bin"
hcatHcstat2genBin = "hcstat2gen.bin"
hcatOmenCreateBin = "createNG"
hcatOmenEnumBin = "enumNG"


def _resolve_wordlist_path(wordlist, base_dir):
    if not wordlist:
        return wordlist
    expanded = os.path.expanduser(wordlist)
    base_dirs = [base_dir]
    default_dir = os.path.join(hate_path, "wordlists")
    for candidate_dir in (default_dir, os.getcwd()):
        if candidate_dir and candidate_dir not in base_dirs:
            base_dirs.append(candidate_dir)
    if any(ch in expanded for ch in "*?[]"):
        if os.path.isabs(expanded):
            return expanded
        for base in base_dirs:
            candidate = os.path.abspath(os.path.join(base, expanded))
            return candidate
    if os.path.isabs(expanded):
        candidates = [expanded]
    else:
        candidates = []
        for base in base_dirs:
            candidates.append(os.path.join(base, expanded))
        candidates.append(os.path.abspath(expanded))
    for candidate in list(candidates):
        if candidate.endswith(".gz"):
            candidates.append(candidate[:-3])
        else:
            candidates.append(candidate + ".gz")
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return os.path.abspath(candidates[0])


def _make_abs_wordlist(base_dir, wordlist):
    return _resolve_wordlist_path(wordlist, base_dir)


def _normalize_wordlist_setting(setting, base_dir):
    if isinstance(setting, list):
        return [_make_abs_wordlist(base_dir, item) for item in setting]
    return _make_abs_wordlist(base_dir, setting)


def _resolve_wordlists_dir():
    wordlists_dir = hcatWordlists or os.path.join(hate_path, "wordlists")
    wordlists_dir = os.path.expanduser(wordlists_dir)
    if not os.path.isabs(wordlists_dir):
        wordlists_dir = os.path.join(hate_path, wordlists_dir)
    return wordlists_dir


def get_rule_path(rule_name, fallback_dir=None):
    candidates = []
    if rulesDirectory:
        candidates.append(os.path.join(rulesDirectory, rule_name))
    if fallback_dir:
        candidates.append(os.path.join(fallback_dir, rule_name))
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return candidates[0] if candidates else rule_name


def ensure_toggle_rule():
    """Ensure toggles-lm-ntlm.rule exists in the configured rules directory."""
    if not rulesDirectory:
        return None
    target_path = os.path.join(rulesDirectory, "toggles-lm-ntlm.rule")
    if os.path.isfile(target_path):
        return target_path
    source_path = os.path.join(hate_path, "rules", "toggles-lm-ntlm.rule")
    try:
        os.makedirs(rulesDirectory, exist_ok=True)
        if os.path.isfile(source_path):
            with open(source_path, "r") as src, open(target_path, "w") as dst:
                dst.write(src.read())
        else:
            with open(target_path, "w") as dst:
                dst.write("l\nu\n")
        print(f"[i] Created rule file: {target_path}")
    except Exception as e:
        print(f"[!] Failed to create toggles-lm-ntlm.rule: {e}")
    return target_path


def cleanup_wordlist_artifacts():
    wordlists_dir = hcatWordlists or os.path.join(hate_path, "wordlists")
    if not os.path.isabs(wordlists_dir):
        wordlists_dir = os.path.join(hate_path, wordlists_dir)
    targets = [hate_path, os.getcwd()]
    if wordlists_dir not in targets:
        targets.append(wordlists_dir)

    for base in targets:
        if not os.path.isdir(base):
            continue
        for name in os.listdir(base):
            path = os.path.join(base, name)
            if name.endswith(".out"):
                try:
                    os.remove(path)
                except Exception as e:
                    print(f"[!] Failed to remove output file {path}: {e}")
            if base == wordlists_dir and name.endswith(".torrent"):
                try:
                    os.remove(path)
                except Exception as e:
                    print(f"[!] Failed to remove torrent file {path}: {e}")
            if base == wordlists_dir and name.endswith(".7z"):
                ok = extract_with_7z(path)
                if not ok:
                    try:
                        os.remove(path)
                        print(f"[!] Removed failed archive: {path}")
                    except Exception as e:
                        print(f"[!] Failed to remove archive {path}: {e}")


wordlists_dir = _resolve_wordlists_dir()
hcatDictionaryWordlist = _normalize_wordlist_setting(
    hcatDictionaryWordlist, wordlists_dir
)
hcatCombinationWordlist = _normalize_wordlist_setting(
    hcatCombinationWordlist, wordlists_dir
)
hcatHybridlist = _normalize_wordlist_setting(hcatHybridlist, wordlists_dir)
hcatFingerprintWordlist = _normalize_wordlist_setting(
    hcatFingerprintWordlist, wordlists_dir
)
hcatMiddleBaseList = _normalize_wordlist_setting(hcatMiddleBaseList, wordlists_dir)
hcatThoroughBaseList = _normalize_wordlist_setting(hcatThoroughBaseList, wordlists_dir)
hcatGoodMeasureBaseList = _normalize_wordlist_setting(
    hcatGoodMeasureBaseList, wordlists_dir
)
hcatPrinceBaseList = _normalize_wordlist_setting(hcatPrinceBaseList, wordlists_dir)
if not SKIP_INIT and not _argv_requests_help_or_version():
    # Verify hashcat binary is available
    # hcatBin should be in PATH or be an absolute path (resolved from hcatPath + hcatBin if configured)
    try:
        if os.path.isabs(hcatBin):
            if not os.path.isfile(hcatBin):
                print(
                    f"Hashcat binary not found at {hcatBin}. Please check configuration and try again."
                )
                sys.exit(1)
        else:
            # hcatBin should be in PATH
            if shutil.which(hcatBin) is None:
                if hcatPath:
                    print(
                        f'Hashcat binary not found. Checked hcatPath "{hcatPath}" (no "{hcatBin}" there)'
                        f' and "{hcatBin}" is not in PATH. Please verify hcatPath in config.json.'
                    )
                else:
                    print(
                        f'Hashcat binary "{hcatBin}" not found in PATH. Please check configuration and try again.'
                    )
                sys.exit(1)

        # Verify hashcat-utils binaries exist and work
        # Note: hashcat-utils is part of hate_crack repo, not hashcat installation
        hashcat_utils_path = hate_path + "/hashcat-utils/bin"
        required_binaries = [
            (hcatExpanderBin, "expander"),
            (hcatCombinatorBin, "combinator"),
        ]

        for binary, name in required_binaries:
            binary_path = hashcat_utils_path + "/" + binary
            ensure_binary(
                binary_path,
                build_dir=os.path.join(hate_path, "hashcat-utils"),
                name=name,
            )
            # Test binary execution
            try:
                test_result = subprocess.run(
                    [binary_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=2,
                )
                # Binary should show usage and exit with error code (that's expected)
                # If we get here without exception, the binary is executable
            except subprocess.TimeoutExpired:
                # Timeout is fine - means binary is running
                pass
            except Exception as e:
                print(f"Error: {name} binary at {binary_path} failed to execute: {e}")
                print("The binary may be compiled for the wrong architecture.")
                print("Try recompiling hashcat-utils for your system.")
                sys.exit(1)

        # Verify princeprocessor binary
        # Note: princeprocessor is part of hate_crack repo, not hashcat installation
        prince_path = hate_path + "/princeprocessor/" + hcatPrinceBin
        try:
            ensure_binary(
                prince_path,
                build_dir=os.path.join(hate_path, "princeprocessor"),
                name="PRINCE",
            )
        except SystemExit:
            print("PRINCE attacks will not be available.")

        # Verify hcstat2gen binary (optional, for LLM attacks)
        # Note: hcstat2gen is part of hashcat-utils, already in hate_crack repo
        hcstat2gen_path = hate_path + "/hashcat-utils/bin/" + hcatHcstat2genBin
        try:
            ensure_binary(
                hcstat2gen_path,
                build_dir=os.path.join(hate_path, "hashcat-utils"),
                name="hcstat2gen",
            )
        except SystemExit:
            print("LLM attacks will not be available.")

        # Verify OMEN binaries (optional, for OMEN attack)
        omen_create_path = os.path.join(_omen_dir, hcatOmenCreateBin)
        omen_enum_path = os.path.join(_omen_dir, hcatOmenEnumBin)
        try:
            ensure_binary(
                omen_create_path,
                build_dir=_omen_dir,
                name="OMEN createNG",
            )
            ensure_binary(
                omen_enum_path,
                build_dir=_omen_dir,
                name="OMEN enumNG",
            )
        except SystemExit:
            print("OMEN attacks will not be available.")

        # Verify pcfg_cracker presence (optional, for PCFG attacks)
        # pcfg_cracker is pure-Python; we just check the script files exist.
        pcfg_guesser_script = os.path.join(hate_path, "pcfg_cracker", "pcfg_guesser.py")
        pcfg_prince_ling_script = os.path.join(
            hate_path, "pcfg_cracker", "prince_ling.py"
        )
        if not os.path.isfile(pcfg_guesser_script) or not os.path.isfile(
            pcfg_prince_ling_script
        ):
            print(
                "pcfg_cracker not found at " + os.path.join(hate_path, "pcfg_cracker")
            )
            print("PCFG attacks will not be available. Run 'make' to fetch submodules.")

    except Exception as e:
        print(f"Module initialization error: {e}")
        if not shutil.which("hashcat") and not os.path.exists("/usr/bin/hashcat"):
            print("Warning: Cannot find hashcat in PATH. Install it to use hate_crack.")
        # Allow module to load even if initialization fails
        pass


hcatHashCount = 0
hcatHashCracked = 0
hcatHashFile = ""
hcatHashFileOrig = None
hcatHashType = ""
hcatBruteCount = 0
hcatDictionaryCount = 0
hcatMaskCount = 0
hcatFingerprintCount = 0
hcatSmartMaskCount = 0
hcatCombinationCount = 0
hcatCombinator3Count = 0
hcatCombinatorXCount = 0
hcatNgramXCount = 0
hcatHybridCount = 0
hcatExtraCount = 0
hcatRecycleCount = 0
hcatGenerateRulesCount = 0
hcatPermuteCount = 0
hcatProcess: subprocess.Popen[Any] | None = None
debug_mode = False
non_interactive = False
hcatUsernamePrefix: bool = False

# Level requested for --debug-mode on rule-based attacks. A hashcat build
# older than the one that introduced mode 5 rejects it with "Invalid
# --debug-mode value specified." (exit 255); _run_hcat_cmd detects that
# specific failure, retries the same invocation at mode 4, and drops this to
# 4 so every later rule-based attack in the process requests mode 4 directly
# instead of failing and retrying again.
_debug_mode_level = 5
_DEBUG_MODE_UNSUPPORTED_MSG = b"Invalid --debug-mode value specified."

# Set from ``flags.rule_debug_mode_enabled`` in main(); --no-rule-debug-mode
# (or ``rule_debug_mode_enabled: false`` in config.json) stops
# _add_debug_mode_for_rules from adding --debug-mode/--debug-file at all.
# Unrelated to ``debug_mode`` above, which only controls hate_crack's own
# verbose logging.
_rule_debug_mode_enabled = True

# Set from ``flags.coverage_enabled`` in main(); --no-coverage (or
# ``coverage_enabled: false`` in config.json) stops _run_hcat_cmd from
# consulting or writing the per-target coverage store at all.
_coverage_enabled = True

# Per-invocation tallies, so a scripted run can tell "the attack ran" from "the
# attack was skipped because coverage had already seen all of it". Both are
# reset by reset_run_counters() at the start of a non-interactive command.
_hcat_launch_count = 0
_coverage_skip_count = 0


def reset_run_counters() -> None:
    global _hcat_launch_count, _coverage_skip_count
    _hcat_launch_count = 0
    _coverage_skip_count = 0


def run_counters() -> tuple[int, int]:
    """(hashcat launches, coverage skips) since the last reset."""
    return _hcat_launch_count, _coverage_skip_count


def _open_wordlist(path):
    """Open a wordlist file, transparently decompressing gzip by magic bytes.

    WARNING: the returned handle must never be passed to
    ``subprocess.Popen(stdin=...)``. When the file is gzip-compressed this
    returns a ``gzip.GzipFile``, and ``GzipFile.fileno()`` resolves to the
    fd of the *underlying compressed file* rather than the decompressed
    stream -- a subprocess given this as stdin reads raw gzip bytes, not
    decompressed text. Reading via ``.read()``/iteration in Python is fine
    (that's what this function exists for); for an external binary use
    ``_wordlist_path()`` instead, which materializes a real decompressed
    path.
    """
    if _plaintext.is_gzipped(path):
        return gzip.open(path, "rb")
    return open(path, "rb")


def _format_cmd(cmd):
    # Shell-style quoting to mirror what a user could run in a terminal.
    return " ".join(shlex.quote(str(part)) for part in cmd)


def _debug_cmd(cmd):
    if debug_mode:
        print(f"[DEBUG] hashcat cmd: {_format_cmd(cmd)}")


def _coverage_store():
    return _coverage.get_store()


def _write_filtered_entries(entries, suffix):
    """Write the still-untried entries to a temp rule/mask file.

    Follows the existing temp-file idiom in this module (``delete=False``, the
    caller unlinks in a ``finally``). Written as bytes with explicit newlines
    because rule lines are whitespace-significant and must survive verbatim.
    """
    with tempfile.NamedTemporaryFile(
        mode="wb",
        suffix=suffix,
        prefix="hate_crack_coverage_",
        delete=False,
    ) as handle:
        for entry in entries:
            # surrogateescape mirrors read_entries' decode, so a rule file that
            # is not valid UTF-8 (rulegen.py writes latin-1) round-trips byte
            # for byte instead of picking up U+FFFD and becoming a different
            # rule. Newlines are written explicitly rather than via text-mode
            # translation.
            handle.write(entry.encode("utf-8", errors="surrogateescape") + b"\n")
        return handle.name


def _plural(noun: str, count: int) -> str:
    return noun if count == 1 else noun + "s"


def _drop_wordlist_args(cmd, dropped: set, hash_file: str):
    """Remove covered wordlists from a command's positional arguments.

    Matching on the bare string is not enough: a wordlist path can legitimately
    coincide with the hash file or with the value of a flag such as ``-o``, and
    dropping it there would silently change where hashcat writes its output or
    which hashes it attacks. Only bare positional occurrences are removed --
    never the hash file, and never a token that follows a flag.
    """
    result = []
    previous_was_flag = False
    for arg in cmd:
        text = str(arg)
        if text in dropped and not previous_was_flag and text != hash_file:
            previous_was_flag = False
            continue
        result.append(arg)
        previous_was_flag = text.startswith("-")
    return result


def _replace_rule_arg(cmd, source_path: str, replacement: str, kind: str):
    """Swap a rule or mask file for its filtered rewrite.

    Scoped to the argument the relevant flag actually points at, for the same
    reason as ``_drop_wordlist_args``: replacing every token equal to
    ``source_path`` would also rewrite an identically-named hash file or output
    path. A mask file is positional, so it is matched as a bare argument.
    """
    result = list(cmd)
    if kind == "mask":
        for index, arg in enumerate(result):
            if str(arg) == source_path and (
                index == 0 or not str(result[index - 1]).startswith("-")
            ):
                result[index] = replacement
                return result
        return result
    for index in range(1, len(result)):
        if str(result[index - 1]) == "-r" and str(result[index]) == source_path:
            result[index] = replacement
            return result
    return result


def _coverage_overlap_scope(plan, spec) -> str:
    """The " against ..." clause naming what the overlap was measured against.

    Rules and masks are tracked per *line*, not per file, so a rule file the
    operator has never selected before can still come back fully covered when
    its lines already ran inside a larger one. Saying only "this hash file"
    reads as a claim about the file they picked, which looks like a bug; naming
    the wordlists makes the real claim checkable.
    """
    if plan.kind == "wordlist" or not spec.wordlists:
        return "this hash file"
    names = sorted({os.path.basename(path) for path in spec.wordlists})
    shown = ", ".join(names[:3])
    if len(names) > 3:
        shown += f", +{len(names) - 3} more"
    return f"this hash file with {shown}"


def _prompt_coverage_filter(plan, attack_name: str, spec=None) -> bool:
    """Ask whether to skip the already-covered entries. Default is yes.

    Only reached when there is genuine overlap, so a fresh engagement never
    sees this prompt.
    """
    noun = {"rule": "rule", "mask": "mask", "wordlist": "wordlist"}.get(
        plan.kind, "entry"
    )
    remaining = plan.total_count - plan.covered_count
    scope = (
        _coverage_overlap_scope(plan, spec) if spec is not None else "this hash file"
    )
    print(
        f"\n[*] Coverage: {plan.covered_count} of {plan.total_count} "
        f"{_plural(noun, plan.covered_count)} in this "
        f"{attack_name or 'attack'} have already been run against {scope}."
    )
    if plan.kind in ("rule", "mask") and plan.covered_count == plan.total_count:
        print(
            f"    ({noun}s are tracked individually, so this can happen the "
            f"first time a {noun} file is used, if a larger one already "
            f"covered every line in it.)"
        )
    if plan.skip:
        if non_interactive:
            return True
        try:
            # A full repeat is the highest-stakes call the feature makes, so the
            # operator gets the same say here as on a partial overlap. Without
            # this, deliberately re-running a covered attack meant restarting
            # the whole tool with --no-coverage.
            answer = input("[?] Skip this attack entirely? [Y/n]: ").strip()
        except EOFError:
            print("[*] No input available; taking the default and skipping.")
            return True
        return answer.lower() not in ("n", "no")
    if non_interactive:
        # A scripted run has nobody to ask; the config/CLI default already
        # decided that filtering is wanted by getting this far.
        return True
    try:
        answer = input(
            f"[?] Skip them and run only the {remaining} "
            f"{_plural(noun, remaining)}? [Y/n]: "
        ).strip()
    except EOFError:
        # stdin is closed -- a piped or cron-driven run that never set
        # non_interactive. Take the documented default rather than letting an
        # unanswerable prompt kill the attack.
        print("[*] No input available; taking the default and filtering.")
        return True
    return answer.lower() not in ("n", "no")


def _apply_coverage(cmd, spec, attack_name: str):
    """Resolve coverage for a pending run.

    Returns ``None`` when the whole run is a repeat and should be skipped, or
    ``(cmd, plan, temp_paths)`` otherwise. ``plan`` is ``None`` when coverage
    could not be established, which means neither filter nor record.
    """
    store = _coverage_store()
    plan = _coverage.plan_run(spec, store.covered, store=store)
    if plan.is_inert:
        return cmd, None, []

    if not plan.has_overlap:
        return cmd, plan, []

    if not _prompt_coverage_filter(plan, attack_name, spec):
        print("[*] Running everything, as requested.")
        return cmd, plan, []

    if plan.skip:
        print(
            f"[*] Skipping {attack_name or 'this attack'}: every "
            f"{plan.kind or 'entry'} in it has already been run against this "
            "hash file."
        )
        return None

    if not plan.filtered_entries:
        # Overlap exists but this run shape cannot be split (chained -r files
        # are a cartesian product; a multi-source mask run has no single file
        # to rewrite). Run it whole.
        return cmd, plan, []

    cmd = list(cmd)
    temp_paths: list[str] = []

    if plan.kind == "wordlist":
        keep = set(plan.filtered_entries)
        dropped = {arg for arg in spec.wordlists if arg not in keep}
        cmd = _drop_wordlist_args(cmd, dropped, spec.hash_file)
    elif plan.source_path is not None:
        suffix = ".hcmask" if plan.kind == "mask" else ".rule"
        replacement = _write_filtered_entries(plan.filtered_entries, suffix)
        temp_paths.append(replacement)
        cmd = _replace_rule_arg(cmd, plan.source_path, replacement, plan.kind)

    print(
        f"[*] Coverage: running {len(plan.filtered_entries)} new "
        f"{plan.kind} entr{'y' if len(plan.filtered_entries) == 1 else 'ies'} "
        f"and skipping {plan.covered_count} already covered."
    )
    return cmd, plan, temp_paths


def _coverage_report(hash_file: str) -> str:
    """Human-readable coverage summary for one hash file.

    Shared by the CLI subcommand and the menu so the two cannot drift.
    """
    target = _coverage.target_id(hash_file)
    if target is None:
        return f"[!] Cannot read {hash_file}."

    summary = _coverage_store().summary(target)
    if not summary["runs"]:
        return f"No attacks recorded against {os.path.basename(hash_file)} yet."

    lines = [
        f"Coverage for {os.path.basename(hash_file)}",
        f"  target id : {target[:16]}...",
        f"  entries   : {summary['entries']} rule/mask/wordlist entries covered",
        f"  runs      : {summary['runs']}",
        f"  last run  : {summary['last_run']}",
        "",
        f"  {'attack':<32}{'entries':>9}{'runs':>7}",
        f"  {'-' * 32}{'-' * 9}{'-' * 7}",
    ]
    for attack, entries, runs in summary["by_attack"]:
        lines.append(f"  {(attack or '(unnamed)')[:32]:<32}{entries:>9}{runs:>7}")
    lines.append("")
    lines.append(
        "  An attack with runs but no entries was logged rather than filtered:"
    )
    lines.append("  a dynamic generator (PRINCE, PCFG, OMEN, Markov, LLM), or a repeat")
    lines.append("  that added nothing new.")
    return "\n".join(lines)


def _coverage_history_report(hash_file: str) -> str:
    target = _coverage.target_id(hash_file)
    if target is None:
        return f"[!] Cannot read {hash_file}."
    rows = _coverage_store().history(target)
    if not rows:
        return f"No attacks recorded against {os.path.basename(hash_file)} yet."
    lines = [f"Run history for {os.path.basename(hash_file)}", ""]
    for attack, detail, ran_at in rows:
        suffix = f"  {detail}" if detail else ""
        lines.append(f"  {ran_at}  {attack or '(unnamed)'}{suffix}")
    return "\n".join(lines)


def _coverage_forget(hash_file: str) -> str:
    target = _coverage.target_id(hash_file)
    if target is None:
        return f"[!] Cannot read {hash_file}."
    dropped = _coverage_store().forget_target(target)
    return (
        f"Dropped {dropped} covered entr{'y' if dropped == 1 else 'ies'} and the "
        f"run history for {os.path.basename(hash_file)}. It will be attacked as "
        "though for the first time."
    )


def _run_coverage_command(args) -> int:
    """`hate_crack coverage status|history|forget --hashfile X`."""
    command = getattr(args, "coverage_command", None)
    if not command:
        print("Error: coverage needs one of: status, history, forget")
        return 2

    hash_file = resolve_path(args.hashfile)
    if not hash_file or not os.path.isfile(hash_file):
        print(f"Error: hash file not found: {args.hashfile}")
        return 1

    if command == "status":
        print(_coverage_report(hash_file))
        return 0
    if command == "history":
        print(_coverage_history_report(hash_file))
        return 0
    if command == "forget":
        if not args.yes:
            print(_coverage_report(hash_file))
            answer = input("\n[?] Drop all of this and start over? [y/N]: ").strip()
            if answer.lower() not in ("y", "yes"):
                print("Left unchanged.")
                return 0
        print(_coverage_forget(hash_file))
        return 0

    print(f"Error: unknown coverage command: {command}")
    return 2


def _run_hcat_cmd(
    cmd,
    attack_name: str = "",
    hash_file: str | None = None,
    *,
    coverage=None,
    stdin=None,
    companion_procs=None,
    reraise_interrupt: bool = False,
    out_path: str | None = None,
):
    """Run hashcat, first consulting the coverage store when given a spec.

    ``coverage`` is a :class:`hate_crack.attack_coverage.CoverageSpec` naming
    the wordlists, rule files and masks this command enumerates. The assembled
    ``cmd`` cannot supply that itself -- it has no way to say which positional
    argument is a wordlist and which is a mask -- which is why the attack
    functions pass it explicitly. Omitting it disables coverage for that
    invocation, which is how dynamic candidate generators opt out.

    Coverage is recorded only on clean completion, so a ctrl-C or a hashcat
    error never leaves the store claiming ground that was not covered.
    """
    plan = None
    temp_paths: list[str] = []

    global _hcat_launch_count, _coverage_skip_count

    if coverage is not None and _coverage_enabled:
        applied = _apply_coverage(cmd, coverage, attack_name)
        if applied is None:
            _coverage_skip_count += 1
            return
        cmd, plan, temp_paths = applied

    _hcat_launch_count += 1
    try:
        completed = _run_hcat_cmd_uncovered(
            cmd,
            attack_name,
            hash_file,
            stdin=stdin,
            companion_procs=companion_procs,
            reraise_interrupt=reraise_interrupt,
            out_path=out_path,
        )
    finally:
        for path in temp_paths:
            with contextlib.suppress(OSError):
                os.unlink(path)

    if plan is not None and completed:
        _coverage_store().record(
            plan.record_keys,
            target=plan.target,
            kind=plan.kind,
            attack=attack_name,
        )
    elif completed and _coverage_enabled and attack_name and hash_file:
        # Attacks that carry no spec are never filtered, but the issue asks for
        # them to be logged as having run -- this is what lets an operator ask
        # "did I already run PRINCE against this target?" about a generator with
        # no fixed keyspace to diff. One row, no keys.
        target = _coverage.target_id(hash_file)
        if target:
            _coverage_store().log_run(target, attack=attack_name, kind="history")


def _run_hcat_cmd_uncovered(
    cmd,
    attack_name: str = "",
    hash_file: str | None = None,
    *,
    stdin=None,
    companion_procs=None,
    reraise_interrupt: bool = False,
    out_path: str | None = None,
) -> bool:
    """Execute a hashcat subprocess and bracket it with notify hooks.

    Returns True when hashcat ran to completion (cracked or exhausted) and was
    not interrupted -- the condition under which coverage may be recorded.

    This consolidates the ``hcatProcess = subprocess.Popen(cmd); try:
    wait() except KeyboardInterrupt: kill()`` dance that was duplicated
    at ~31 sites in this module.  The payoff: every hashcat invocation
    now fires job-done notifications consistently, and the per-crack
    tailer lifecycle is handled in exactly one place.

    - ``attack_name`` is the label that appears in notifications. Pass
      an empty string for no-notify invocations.
    - ``hash_file`` is required to locate ``{hash_file}.out`` for the
      tailer.  When omitted, we skip the tailer and the job-done count.
    - ``stdin`` mirrors the ``subprocess.Popen(..., stdin=...)`` kwarg
      for generator-pipe callers.
    - ``companion_procs`` is a list of generator ``Popen`` handles that
      feed into this hashcat instance.  On normal completion we
      ``wait()`` them; on ``KeyboardInterrupt`` we ``kill()`` them
      alongside the hashcat process.  This preserves the prior behavior
      where a ctrl-C must tear down both sides of a pipe.

    Notifications are fire-and-forget: suppression (see
    ``notify.suppressed_notifications``) and disabled-globally state are
    both handled inside the notify module, so callers need not branch.
    """
    global hcatProcess, _debug_mode_level

    companions = list(companion_procs) if companion_procs else []

    # Resolve the output file path used for the tailer and cracked-count
    # readback.  Most hashcat calls write to ``{hash_file}.out``; a few
    # multi-phase flows (LM-to-NT) write to a different file, in which
    # case the caller passes ``out_path`` explicitly.
    resolved_out = out_path if out_path else (hash_file + ".out" if hash_file else None)

    tailer = None
    if attack_name and resolved_out and not _notify.is_suppressed():
        tailer = _notify.start_tailer(resolved_out, attack_name)

    # ``--debug-mode`` is only ever added by ``_add_debug_mode_for_rules``, so
    # only those invocations pay for the stderr capture needed to detect a
    # hashcat build that rejects the requested mode. stdout is left alone
    # (inherited) so the live progress output is unaffected.
    has_debug_mode = "--debug-mode" in cmd
    stderr_capture = tempfile.TemporaryFile() if has_debug_mode else None

    popen_kwargs = {"stdin": stdin} if stdin is not None else {}
    if stderr_capture is not None:
        popen_kwargs["stderr"] = stderr_capture
    hcatProcess = subprocess.Popen(cmd, **popen_kwargs)
    interrupted = False
    try:
        hcatProcess.wait()
        for gen in companions:
            try:
                gen.wait()
            except Exception:
                pass
    except KeyboardInterrupt:
        interrupted = True
        print("Killing PID {0}...".format(str(hcatProcess.pid)))
        hcatProcess.kill()
        for gen in companions:
            try:
                gen.kill()
            except Exception:
                pass
    finally:
        _notify.stop_tailer(tailer)

    if stderr_capture is not None:
        try:
            stderr_capture.seek(0)
            captured_stderr = stderr_capture.read()
        finally:
            stderr_capture.close()

        if (
            not interrupted
            and hcatProcess.returncode
            and _DEBUG_MODE_UNSUPPORTED_MSG in captured_stderr
        ):
            debug_mode_idx = cmd.index("--debug-mode") + 1
            requested_level = cmd[debug_mode_idx]
            if requested_level == str(_debug_mode_level) and _debug_mode_level > 4:
                print(
                    f"[!] hashcat rejected --debug-mode {requested_level} "
                    "(unsupported by this build); falling back to "
                    "--debug-mode 4 for the rest of this run."
                )
                _debug_mode_level = 4
                fallback_cmd = list(cmd)
                fallback_cmd[debug_mode_idx] = "4"
                # Re-enter the inner runner, not the coverage wrapper:
                # coverage has already been applied to this cmd, and applying
                # it twice would filter an already-filtered rule file.
                return _run_hcat_cmd_uncovered(
                    fallback_cmd,
                    attack_name,
                    hash_file,
                    stdin=stdin,
                    companion_procs=companion_procs,
                    reraise_interrupt=reraise_interrupt,
                    out_path=out_path,
                )
        elif captured_stderr:
            sys.stderr.write(captured_stderr.decode(errors="replace"))
            sys.stderr.flush()

    # Only incur a lineCount read when notifications will actually fire.
    # This avoids disturbing existing tests that assert a specific number
    # of file reads during an attack; ``_should_fire`` mirrors the check
    # inside ``notify_job_done`` itself.
    if (
        attack_name
        and resolved_out
        and not _notify.is_suppressed()
        and _notify.get_settings().enabled
    ):
        cracked = lineCount(resolved_out)
        _notify.notify_job_done(attack_name, cracked, hash_file or resolved_out)

    if interrupted and reraise_interrupt:
        raise KeyboardInterrupt

    # Only exit 1 -- keyspace exhausted -- proves the candidates were actually
    # enumerated, which is the sole condition under which coverage may be
    # recorded.
    #
    # Exit 0 deliberately does NOT count. It means every hash was cracked, and
    # hashcat reports that *without* finishing the keyspace -- including the
    # degenerate case where it enumerates nothing at all, printing "All hashes
    # found as potfile entries" and exiting immediately. That case is live in
    # this project: the potfile matches on the hash string rather than the mode,
    # so one stray cross-mode entry can make hashcat exit 0 having tried
    # nothing, after which every later attack on that file would be skipped as
    # already covered. Under-recording here only costs a redundant run later,
    # and when all hashes are already cracked there is nothing left to lose.
    #
    # A missing returncode only happens behind a test double -- a real Popen
    # always has one set by wait().
    returncode = getattr(hcatProcess, "returncode", None)
    return not interrupted and returncode in (1, None)


def _is_gzipped(path: str) -> bool:
    return _plaintext.is_gzipped(path)


@contextlib.contextmanager
def _wordlist_path(path: str):
    """Yield an uncompressed path for path.

    If the file is gzip-compressed, decompress to a temp file and clean up on
    exit. Otherwise yield the original path unchanged.
    """
    if _is_gzipped(path):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp:
            tmp_name = tmp.name
            with gzip.open(path, "rb") as gz_in:
                shutil.copyfileobj(gz_in, tmp)
        try:
            yield tmp_name
        finally:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
    else:
        yield path


def _usable_plaintext(raw: str) -> str:
    """Return the usable plaintext from a raw wordlist line, or empty string.

    Blank/whitespace-only lines are discarded.  Leading hash fields (as
    produced by hashcat ``--show``, i.e. ``hash:password``) are dropped, and a
    ``$HEX[...]`` wrapper is decoded.  Both only when clearly present, so a
    wordlist entry that merely contains a colon is returned intact.

    Delegates to hate_crack.plaintext so the sampler, the whole-corpus
    aggregator, and rulegen cannot drift apart on what counts as a password.
    """
    return _plaintext.usable_plaintext(raw)


def _add_debug_mode_for_rules(cmd):
    """Add debug mode arguments to hashcat command if rules are being used.

    This function detects if rules are present in the command (by looking for -r flags)
    and adds --debug-mode=5 and --debug-file=<path> if rules are found.
    Debug log path is configurable via hcatDebugLogPath in config.json

    Mode 5 is mode 4 (baseword:rule:candidate) plus the wordlist the baseword
    came from, so a log from a multi-wordlist run records which list is actually
    producing cracks. HashcatRosetta >= 0.3.0 parses that fourth field.

    Skipped entirely when ``--no-rule-debug-mode`` (or
    ``rule_debug_mode_enabled: false`` in config.json) is in effect.
    """
    if "-r" in cmd and _rule_debug_mode_enabled:
        # Create debug output directory if it doesn't exist
        os.makedirs(hcatDebugLogPath, exist_ok=True)

        # Create a debug output filename based on the session ID or hash file
        debug_filename = os.path.join(hcatDebugLogPath, "hashcat_debug.log")
        if "--session" in cmd:
            session_idx = cmd.index("--session") + 1
            if session_idx < len(cmd):
                debug_filename = os.path.join(
                    hcatDebugLogPath, f"hashcat_debug_{cmd[session_idx]}.log"
                )

        cmd.extend(
            ["--debug-mode", str(_debug_mode_level), "--debug-file", debug_filename]
        )
    return cmd


# Sanitize filename for use as hashcat session name
def generate_session_id():
    """Sanitize the hashfile name for use as a hashcat session name

    Hashcat session names can only contain alphanumeric characters, hyphens, and underscores.
    This function removes the file extension and replaces problematic characters.
    """
    # Get just the filename without path
    filename = os.path.basename(hcatHashFile)
    # Remove extension
    name_without_ext = os.path.splitext(filename)[0]
    # Replace any non-alphanumeric chars (except - and _) with underscore
    sanitized = re.sub(r"[^a-zA-Z0-9_-]", "_", name_without_ext)
    return sanitized


# Help
def usage():
    print("usage: python hate_crack.py <hash_file> <hash_type>")
    print(
        '\nThe <hash_type> is attained by running "{hcatBin} --help"\n'.format(
            hcatBin=hcatBin
        )
    )
    print("Example Hashes: http://hashcat.net/wiki/doku.php?id=example_hashes\n")


def ascii_art():
    from hate_crack import __version__

    print(
        r"""

  ___ ___         __             _________                       __
 /   |   \_____ _/  |_  ____     \_   ___ \____________    ____ |  | __
/    ~    \__  \\   __\/ __ \    /    \  \/\_  __ \__  \ _/ ___\|  |/ /
\    Y    // __ \|  | \  ___/    \     \____|  | \// __ \\  \___|    <
 \___|_  /(____  /__|  \___  >____\______  /|__|  (____  /\___  >__|_ \
       \/      \/          \/_____/      \/            \/     \/     \/
                          Version """
        + __version__
        + """
  """
    )


def _run_upgrade(branch="main"):
    """Reset the repo root to origin's tip and reinstall.

    Fetches with `--tags --force`, resets *branch* to `origin/<branch>` via
    `checkout -B`, then runs `make install`. Deliberately does not merge; see the
    comment above the checkout for why that cannot work here.

    *branch* selects the update channel. ``"main"`` is the released channel that
    ``--update`` uses; ``"nightly-dev"`` is the pre-release channel behind
    ``--nightly``, carrying work that has passed CI but has not been cut into a
    release yet.
    """
    import subprocess

    print()
    # Find the actual git repo root - _repo_root may point to
    # site-packages when installed rather than the source checkout.
    git_root_result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=_repo_root,
        capture_output=True,
        text=True,
    )
    if git_root_result.returncode != 0:
        print(
            "\n  Could not find a git repository to upgrade from."
            f"\n  Run manually: git fetch --tags --force origin && git checkout -B {branch} origin/{branch} && make install\n"
        )
        raise SystemExit(1)
    repo_root = git_root_result.stdout.strip()

    # Fetch first so origin/main is present even on a stale clone that has
    # never been fetched since the default branch was renamed master -> main.
    # Without this, `git checkout main` on a master-only clone fails because
    # there's no origin/main ref to auto-create a tracking branch from.
    #
    # --force is required, not cosmetic: a clone holding a tag that points at a
    # different object than origin's makes a plain `git fetch --tags` exit
    # non-zero with "would clobber existing tag", which used to dead-end the
    # upgrade permanently. --force scopes to tag updates only, so it cannot
    # discard the user's commits or working tree.
    fetch_result = subprocess.run(
        ["git", "fetch", "--tags", "--force", "origin"],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    if fetch_result.returncode != 0:
        print(
            f"\n  Failed to fetch from origin:\n  {fetch_result.stderr.strip()}\n"
            f"\n  Upgrade manually: git fetch --tags --force origin && git checkout -B {branch} origin/{branch} && make install\n"
        )
        raise SystemExit(1)

    # Release tags live on main-side merge commits, so pulling on `dev` or
    # any feature branch won't move HEAD onto the new tag — setuptools-scm
    # then regenerates the version as e.g. 2.10.0.postN.devM and the update
    # checker re-fires on next start, looping forever. Switch to main first.
    #
    # Old clones made before the default branch was renamed master -> main
    # sit on a local `master` whose upstream (branch.master.merge) still
    # points at the now-deleted refs/heads/master. A bare `git pull` then
    # fails with "no such ref was fetched". We migrate such clones to a
    # local `main` tracking origin/main so future manual pulls also work.
    branch_result = subprocess.run(
        ["git", "symbolic-ref", "--short", "HEAD"],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    current_branch = (
        branch_result.stdout.strip() if branch_result.returncode == 0 else ""
    )

    # The checkout below runs unconditionally, including when HEAD is already on
    # *branch*. It used to be skipped in that case, leaving the shell chain's
    # `git pull` to advance the branch -- and that is precisely the case that
    # broke in the field, because a merge cannot advance a clone whose history
    # was rewritten. The 2026-07-25 purge rewrote every published commit, so a
    # clone predating it shares no ancestor with origin/main; git then aborts
    # with "Need to specify how to reconcile divergent branches" (or "refusing
    # to merge unrelated histories") and the upgrade never reaches make install.
    # `checkout -B` moves the branch to origin's tip instead of merging into it,
    # which recovers those clones. It discards local commits on the branch, so
    # the dirty check above it is load-bearing and must stay unconditional too.
    #
    # --ignore-submodules=dirty: `make submodules`/`make install` builds the
    # bundled binaries (hashcat-utils, princeprocessor, OMEN, ...) inside their
    # own submodule working trees, which leaves untracked/modified content
    # there (generated sources, object files, a touched Makefile) with no
    # action from the operator. Plain `git status --porcelain` reports that as
    # `M <submodule>` on the superproject, permanently blocking auto-upgrade
    # after the very install this tool tells people to run. `dirty` still
    # reports a submodule pinned to a different commit than recorded, which
    # `checkout -B` on the superproject cannot fix anyway.
    status = subprocess.run(
        ["git", "status", "--porcelain", "--ignore-submodules=dirty"],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    if status.stdout.strip():
        print(
            f"\n  Cannot auto-upgrade: uncommitted changes on '{current_branch or 'HEAD'}'."
            "\n  Commit or stash them, then re-run."
            f"\n  Or upgrade manually: git checkout -B {branch} origin/{branch} && make install\n"
        )
        raise SystemExit(1)

    if current_branch and current_branch != branch:
        print(
            f"\n  Switching from '{current_branch}' to '{branch}' to pick up the new tag..."
        )

    checkout = subprocess.run(
        # -B creates/resets a local `main` pointing at origin/main so this works
        # whether or not a local `main` already exists (e.g. a stale master-only
        # clone that has never had a main branch), and whether or not its
        # history is related to origin's.
        ["git", "checkout", "-B", branch, f"origin/{branch}"],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    if checkout.returncode != 0:
        print(
            f"\n  Failed to switch to {branch}:\n  {checkout.stderr.strip()}\n"
            f"\n  Upgrade manually: git checkout -B {branch} origin/{branch} && make install\n"
        )
        raise SystemExit(1)

    # Repair the upstream so a later manual `git pull` consults
    # origin/main rather than a dangling branch.master.merge ref.
    subprocess.run(
        ["git", "branch", f"--set-upstream-to=origin/{branch}", branch],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )

    import shutil

    uv = shutil.which("uv") or os.path.expanduser("~/.local/bin/uv")

    result = subprocess.run(
        # No fetch or merge here: the fetch above already made the new tags
        # visible to setuptools-scm and the checkout already put the branch at
        # origin's tip. Re-adding either would reintroduce the failures this
        # function exists to survive.
        # make install handles system deps and the CLI shim.
        # uv sync --reinstall-package forces setuptools-scm to regenerate the
        # version from the new tag so the version number updates correctly.
        f"make install && {uv} sync --reinstall-package hate_crack",
        shell=True,
        cwd=repo_root,
    )
    if result.returncode != 0:
        print("\n  Upgrade failed. Check the output above for errors.\n")
        raise SystemExit(1)

    print("\n  Upgrade complete. Please restart hate_crack.\n")
    raise SystemExit(0)


def _head_contains_release_tag(tag):
    """True when *tag* exists in the local checkout and HEAD already contains it.

    The version comparison alone cannot decide "am I up to date", for two
    reasons.

    The first is tag ties: the version is whatever `git describe` resolves to,
    and a commit can carry more than one release tag. When it does, describe
    breaks the tie by ref iteration order -- lexicographic -- so the LOWER tag
    wins: v2.19.15 over v2.20.0 on e37d568, the 2026-07-31 release. The version
    then never reaches the released one no matter how many times the upgrade
    runs, and every start re-offers it.

    The second is the pre-release channel (#271). nightly-dev publishes
    candidates aimed at the version the batch is heading *toward*, so its
    version sorts BELOW the release it becomes: 2.26.2rc1 < 2.26.2 under PEP
    440. Once that target release ships, a nightly-dev checkout that already
    contains it -- plus every commit since -- still compares as older, and the
    notice offers an "upgrade" that is really a downgrade. It fires on every
    start until the branch's target moves past the release.

    Ancestry answers both: if the release commit is reachable from HEAD, the
    release is already in this checkout whatever the version strings say. An
    exact match is the degenerate case (a commit is its own ancestor), so this
    subsumes the equality check it replaces.

    Any failure here (no checkout, unknown tag, no git) returns False and
    leaves the version comparison in charge, which keeps the notice working for
    installs that are not git clones.
    """
    if not tag or not _re_tag_name.fullmatch(tag):
        return False
    try:
        import subprocess

        # ^{commit} so an annotated tag resolves to its commit rather than the
        # tag object, which is not what merge-base wants.
        tagged = subprocess.run(
            ["git", "rev-parse", "-q", "--verify", f"refs/tags/{tag}^{{commit}}"],
            cwd=_repo_root,
            capture_output=True,
            text=True,
        )
        if tagged.returncode != 0 or not tagged.stdout.strip():
            return False
        contains = subprocess.run(
            ["git", "merge-base", "--is-ancestor", tagged.stdout.strip(), "HEAD"],
            cwd=_repo_root,
            capture_output=True,
            text=True,
        )
        return contains.returncode == 0
    except Exception:
        return False


# Tag names come from the releases API, so they are remote input. Constrain them
# to the shape this project actually publishes before handing one to git.
_re_tag_name = re.compile(r"v?[0-9][0-9A-Za-z.\-+]*")


def check_for_updates():
    """Check GitHub for a newer release and print a notice if one exists."""
    try:
        from hate_crack import __version__

        if not REQUESTS_AVAILABLE:
            return
        resp = requests.get(
            "https://api.github.com/repos/trustedsec/hate_crack/releases/latest",
            timeout=5,
        )
        resp.raise_for_status()
        tag = resp.json().get("tag_name", "")
        latest = tag.lstrip("v")
        # Compare base version (before any +g... suffix) against remote tag
        local_base = __version__.split("+")[0]
        if not latest or not local_base:
            return
        from packaging.version import parse

        if parse(latest) > parse(local_base) and not _head_contains_release_tag(tag):
            print(
                f"\n  Update available: {latest} (current: {local_base})."
                f"\n  See https://github.com/trustedsec/hate_crack/releases\n"
            )
            try:
                answer = input("  Upgrade now? [y/N] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if answer == "y":
                _run_upgrade()
    except Exception:
        pass


# File selector with tab autocomplete
def select_file_with_autocomplete(
    prompt, default=None, allow_multiple=False, base_dir=None
):
    """
    Interactive file selector with tab autocomplete functionality.

    Args:
        prompt: The prompt to display to the user
        default: Optional default value if user presses Enter
        allow_multiple: If True, allows comma-separated file list

    Returns:
        String path or list of paths (if allow_multiple=True)
    """

    def path_completer(text, state):
        """Tab completion function for file paths"""
        if not text:
            if base_dir:
                pattern = os.path.join(base_dir, "*")
                matches = glob.glob(pattern)
            else:
                matches = glob.glob("./*")
        else:
            text = os.path.expanduser(text)
            if text.startswith(("/", "./", "../", "~")):
                matches = glob.glob(text + "*")
            elif base_dir:
                pattern = os.path.join(base_dir, text + "*")
                matches = glob.glob(pattern)
            else:
                matches = glob.glob("./" + text + "*")
                matches = [m[2:] if m.startswith("./") else m for m in matches]

        matches = [m + "/" if os.path.isdir(m) else m for m in matches]

        try:
            return matches[state]
        except IndexError:
            return None

    def display_matches(substitution, matches, longest_match_length):
        print()
        for match in matches:
            print(f"  {match}")
        readline.redisplay()

    # Configure readline for tab completion
    readline.set_completer_delims(" \t\n;")
    try:
        readline.set_completion_display_matches_hook(display_matches)
    except AttributeError:
        pass
    try:
        readline.parse_and_bind("tab: complete")
    except Exception:
        pass
    try:
        readline.parse_and_bind("bind ^I rl_complete")
    except Exception:
        pass
    readline.set_completer(path_completer)

    # Build prompt
    full_prompt = f"\n{prompt}"
    if default:
        full_prompt += f" (default: {default})"
    full_prompt += ": "

    try:
        result = input(full_prompt).strip()
    finally:
        # Drop the path completer so later plain prompts (numeric menus, y/n)
        # don't inherit stale file-path tab completion.
        readline.set_completer(None)
    if not result and base_dir:
        result = base_dir

    # Handle default
    if not result and default:
        return default

    # Handle multiple files
    if allow_multiple and "," in result:
        files = [f.strip() for f in result.split(",")]
        return [os.path.expanduser(f) for f in files if f]

    return os.path.expanduser(result) if result else None


# Counts the number of lines in a file
def lineCount(file):
    try:
        count = 0
        with open(file, "rb") as f:
            while True:
                buf = f.read(1 << 20)  # 1 MiB chunks
                if not buf:
                    break
                count += buf.count(b"\n")
        return count
    except Exception:
        return 0


def _write_delimited_field(
    input_path, output_path, field_index, delimiter=":", last_field=False
):
    try:
        with (
            open(input_path, "r", errors="replace") as src,
            open(output_path, "w") as dst,
        ):
            for line in src:
                line = line.rstrip("\n")
                if last_field:
                    # Hash components for some modes (NetNTLM, Kerberos, ...)
                    # embed their own colons, so the plaintext is only ever
                    # reliably found as the last field, not a fixed index.
                    if delimiter in line:
                        dst.write(line.rsplit(delimiter, 1)[-1] + "\n")
                    continue
                parts = line.split(delimiter, field_index)
                if len(parts) >= field_index:
                    dst.write(parts[field_index - 1] + "\n")
        return True
    except FileNotFoundError:
        return False


def _extract_cracked_plaintexts(source_path, working_path):
    """Extract the plaintext field from a cracked-hash file into
    working_path, decoding any $HEX[...] wrapping in the process.

    hashcat wraps a cracked plaintext in $HEX[...] whenever it contains a
    byte that would break the outfile's colon-delimited format (non-UTF-8
    bytes, control characters, a literal ":" in the password) -- common for
    hash modes that allow full Unicode, like NTLM. A caller that reads
    working_path afterward without this decode step gets that literal
    wrapper text instead of the real password.
    """
    _write_delimited_field(source_path, working_path, 2, last_field=True)
    converted = convert_hex(working_path)
    with open(working_path, "w") as working:
        working.writelines("\n".join(converted))


def _write_field_sorted_unique(input_path, output_path, field_index, delimiter=":"):
    try:
        with (
            open(input_path, "r", errors="replace") as src,
            open(output_path, "w") as dst,
        ):
            sort_proc = subprocess.Popen(
                ["sort", "-u"],
                stdin=subprocess.PIPE,
                stdout=dst,
                text=True,
                env={**os.environ, "LC_ALL": "C"},
            )
            for line in src:
                line = line.rstrip("\n")
                parts = line.split(delimiter, field_index)
                if len(parts) >= field_index:
                    sort_proc.stdin.write(parts[field_index - 1] + "\n")
            sort_proc.stdin.close()
            sort_proc.wait()
        return True
    except FileNotFoundError:
        return False


def _count_computer_accounts(input_path: str, delimiter: str = ":") -> int:
    """Count computer accounts (usernames ending with $) in a hash file."""
    count = 0
    try:
        with open(input_path, "r", errors="replace") as src:
            for line in src:
                stripped = line.strip()
                if stripped and stripped.split(delimiter, 1)[0].endswith("$"):
                    count += 1
    except (FileNotFoundError, PermissionError, OSError) as e:
        if not isinstance(e, FileNotFoundError):
            print(f"Warning: Could not process {input_path}: {e}")
    return count


def _filter_computer_accounts(
    input_path: str, output_path: str, delimiter: str = ":"
) -> int:
    """Filter out computer accounts (usernames ending with $) from a hash file.

    Reads the input file, removes lines where the first field (username)
    ends with '$', and writes the remaining lines to output_path.
    Returns the number of computer accounts removed.
    """
    removed = 0
    try:
        with (
            open(input_path, "r", errors="replace") as src,
            open(output_path, "w") as dst,
        ):
            for line in src:
                stripped = line.rstrip("\r\n")
                if not stripped:
                    continue
                username = stripped.split(delimiter, 1)[0]
                if username.endswith("$"):
                    removed += 1
                else:
                    dst.write(stripped + "\n")
    except (FileNotFoundError, PermissionError, OSError) as e:
        if not isinstance(e, FileNotFoundError):
            print(f"Warning: Could not process {input_path}: {e}")
    return removed


def _dedup_netntlm_by_username(
    input_path: str, output_path: str, delimiter: str = ":"
) -> tuple[int, int]:
    """Deduplicate NetNTLM hashes by username, keeping the first occurrence.

    NetNTLM format: username::domain:challenge:response:blob
    The username is the first field before the delimiter.
    Only writes output_path when duplicates are found.
    Returns a tuple of (total_lines, duplicates_removed).

    Uses a two-pass approach to avoid holding all lines in memory:
    - Pass 1: scan to collect seen usernames and count duplicates
    - Pass 2: stream non-duplicate lines directly to the output file
    """
    seen_usernames: set[str] = set()
    duplicates = 0
    total = 0
    try:
        # Pass 1: count totals and identify unique usernames
        with open(input_path, "r", errors="replace") as src:
            for line in src:
                stripped = line.rstrip("\r\n")
                if not stripped:
                    continue
                total += 1
                username = stripped.split(delimiter, 1)[0].lower()
                if username in seen_usernames:
                    duplicates += 1
                else:
                    seen_usernames.add(username)

        # Pass 2: write non-duplicate lines directly to output (only if needed)
        if duplicates > 0:
            first_seen: set[str] = set()
            with (
                open(input_path, "r", errors="replace") as src,
                open(output_path, "w") as dst,
            ):
                for line in src:
                    stripped = line.rstrip("\r\n")
                    if not stripped:
                        continue
                    username = stripped.split(delimiter, 1)[0].lower()
                    if username not in first_seen:
                        first_seen.add(username)
                        dst.write(stripped + "\n")
    except (FileNotFoundError, PermissionError, OSError) as e:
        if not isinstance(e, FileNotFoundError):
            print(f"Warning: Could not process {input_path}: {e}")
    return total, duplicates


def _run_hashcat_show(hash_type, hash_file, output_path, force_overwrite=False):
    """Rewrite `output_path` from `hashcat --show`, refusing to destroy data.

    `--show` can legitimately come back empty (cracks captured via `-o` only, an
    empty or stale `hcatPotfilePath`, a `--username` parse mismatch) and hashcat
    can fail outright. Either case used to truncate an already populated
    `<hashfile>.out` to zero bytes, which on the pwdump path is the only copy of
    the cracked passwords at the time `cleanup()` runs (issue #195).

    So: a non-zero exit never touches the file, and empty output only replaces an
    existing non-empty file when `force_overwrite` is set - which is what
    `restore_from_potfile()` asks for after confirming with the operator. The
    replacement itself goes through a temp file so an interrupted write cannot
    leave a half-file behind. Returns True when `output_path` was written.
    """
    cmd = [
        hcatBin,
        "--show",
        # Use hashcat's built-in potfile unless configured otherwise.
        *([f"--potfile-path={hcatPotfilePath}"] if hcatPotfilePath else []),
        "-m",
        str(hash_type),
        hash_file,
    ]
    # If username:hash format was detected, --show also needs --username
    # to parse the input correctly; otherwise it treats "user:hash" as a
    # literal hash and finds no matches in the potfile.
    _maybe_append_username_flag(cmd)
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        print(
            f"Warning: hashcat --show exited with code {result.returncode};"
            f" leaving {output_path} unchanged."
        )
        stderr_output = result.stderr.decode("utf-8", errors="replace").strip()
        if stderr_output:
            print(f"  hashcat: {stderr_output.splitlines()[-1]}")
        return False
    lines = [
        line
        for line in result.stdout.decode("utf-8", errors="ignore").splitlines()
        # hashcat --show prints parse errors to stdout; skip non-result lines
        if ":" in line and not line.startswith(("Hash parsing error", "* "))
    ]
    if not lines and not force_overwrite:
        try:
            already_populated = os.path.getsize(output_path) > 0
        except OSError:
            already_populated = False
        if already_populated:
            print(
                f"Warning: hashcat --show returned no results; preserving the"
                f" existing contents of {output_path}."
            )
            return False
    temp_path = output_path + ".show.tmp"
    try:
        with open(temp_path, "w") as out:
            for line in lines:
                out.write(line + "\n")
        os.replace(temp_path, output_path)
    finally:
        if os.path.isfile(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
    return True


# Brute Force Attack
def hcatBruteForce(hcatHashType, hcatHashFile, hcatMinLen, hcatMaxLen):
    global hcatBruteCount
    global hcatProcess
    cmd = [
        hcatBin,
        "-m",
        hcatHashType,
        hcatHashFile,
        "--session",
        generate_session_id(),
        "-o",
        f"{hcatHashFile}.out",
        "--increment",
        f"--increment-min={hcatMinLen}",
        f"--increment-max={hcatMaxLen}",
        "-a",
        "3",
        "?a?a?a?a?a?a?a?a?a?a?a?a?a?a",
    ]
    if _should_use_optimized_kernel("hcatBruteForce"):
        _insert_optimized_flag(cmd)
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(cmd)
    _run_hcat_cmd(cmd, attack_name="Brute Force", hash_file=hcatHashFile)

    hcatBruteCount = lineCount(hcatHashFile + ".out")


# Dictionary Attack
def hcatDictionary(hcatHashType, hcatHashFile):
    global hcatDictionaryCount
    global hcatProcess
    rule_best66 = get_rule_path("best66.rule")
    optimized_lists = [
        os.path.join(hcatWordlists, entry.name)
        for entry in list_wordlist_entries(hcatWordlists)
    ]
    if not optimized_lists:
        optimized_lists = [os.path.join(hcatWordlists, "*")]
    cmd = [
        hcatBin,
        "-m",
        hcatHashType,
        hcatHashFile,
        "--session",
        generate_session_id(),
        "-o",
        f"{hcatHashFile}.out",
    ]
    cmd.extend(optimized_lists)
    cmd.extend(["-r", rule_best66])
    if _should_use_optimized_kernel("hcatDictionary"):
        _insert_optimized_flag(cmd)
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(cmd)
    cmd = _add_debug_mode_for_rules(cmd)
    _run_hcat_cmd(
        cmd,
        attack_name="Dictionary",
        hash_file=hcatHashFile,
        coverage=_coverage.CoverageSpec(
            hash_file=hcatHashFile,
            wordlists=tuple(optimized_lists),
            rule_files=(rule_best66,),
        ),
    )

    rule_d3ad0ne = get_rule_path("d3ad0ne.rule")
    rule_toxic = get_rule_path("T0XlC.rule")
    for wordlist in hcatDictionaryWordlist:
        # Combine d3ad0ne + T0XlC rules into a single file so hashcat only
        # starts once per wordlist instead of twice (saves GPU init overhead).
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".rule", prefix="hate_crack_combined_", delete=False
        ) as combined:
            combined_path = combined.name
            for rule_path in (rule_d3ad0ne, rule_toxic):
                with open(rule_path, "rb") as rf:
                    data = rf.read()
                    combined.write(data)
                    if data and not data.endswith(b"\n"):
                        combined.write(b"\n")
        try:
            cmd = [
                hcatBin,
                "-m",
                hcatHashType,
                hcatHashFile,
                "--session",
                generate_session_id(),
                "-o",
                f"{hcatHashFile}.out",
                wordlist,
                "-r",
                combined_path,
            ]
            if _should_use_optimized_kernel("hcatDictionary"):
                _insert_optimized_flag(cmd)
            cmd.extend(shlex.split(hcatTuning))
            _append_potfile_arg(cmd)
            cmd = _add_debug_mode_for_rules(cmd)
            _run_hcat_cmd(
                cmd,
                attack_name="Dictionary",
                hash_file=hcatHashFile,
                coverage=_coverage.CoverageSpec(
                    hash_file=hcatHashFile,
                    wordlists=(wordlist,),
                    rule_files=(combined_path,),
                ),
            )
        finally:
            os.unlink(combined_path)

    hcatDictionaryCount = lineCount(hcatHashFile + ".out") - hcatBruteCount


# Quick Dictionary Attack (Optional Chained Rules)
def hcatQuickDictionary(
    hcatHashType,
    hcatHashFile,
    hcatChains,
    wordlists,
    loopback=False,
    use_potfile_path=True,
    potfile_path=None,
    attack_name="Quick Dictionary",
):
    global hcatProcess
    cmd = [
        hcatBin,
        "-m",
        hcatHashType,
        hcatHashFile,
        "--session",
        generate_session_id(),
        "-o",
        f"{hcatHashFile}.out",
    ]
    if isinstance(wordlists, list):
        cmd.extend(wordlists)
    else:
        cmd.append(wordlists)
    if loopback:
        cmd.append("--loopback")
    if hcatChains:
        cmd.extend(shlex.split(hcatChains))
    if _should_use_optimized_kernel("hcatQuickDictionary"):
        _insert_optimized_flag(cmd)
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(
        cmd, use_potfile_path=use_potfile_path, potfile_path=potfile_path
    )
    cmd = _add_debug_mode_for_rules(cmd)
    _debug_cmd(cmd)
    _run_hcat_cmd(
        cmd,
        attack_name=attack_name,
        hash_file=hcatHashFile,
        coverage=_quick_dictionary_coverage(
            hcatHashFile, hcatChains, wordlists, loopback
        ),
    )


def _quick_dictionary_coverage(hash_file, chains, wordlists, loopback):
    """Build the coverage spec for hcatQuickDictionary.

    ``--loopback`` is recorded but never filtered. hashcat feeds newly-cracked
    plaintexts back in as *extra* candidates, so the run tries the full wordlist
    and rule set plus whatever those recycled plaintexts reach. Recording it is
    therefore sound -- it really did try everything declared here, so a later
    ordinary run of the same wordlist and rules is a genuine repeat. Filtering
    it would not be: a second loopback run has more cracks to recycle and so
    reaches ground the first one could not.
    """
    # Named `args`, not `tokens`: bandit's B105 heuristic reads any comparison
    # against a variable called `token` as a hardcoded credential.
    args = shlex.split(chains) if chains else []
    rule_files = tuple(
        args[index + 1] for index, arg in enumerate(args[:-1]) if arg == "-r"
    )
    lists = tuple(wordlists) if isinstance(wordlists, list) else (wordlists,)
    return _coverage.CoverageSpec(
        hash_file=hash_file,
        wordlists=lists,
        rule_files=rule_files,
        record_only=bool(loopback),
    )


def _valid_hcmask(mask: object) -> bool:
    """Is *mask* a syntactically valid hashcat brute-force mask (or hcmask line)?

    Delegates the actual hcmask grammar — builtin tokens, custom charsets
    (``?1``-``?8``, comma-separated, ``\\,``-escaped), and hashcat's own
    256-position mask-length limit — to
    ``hashcat_rosetta.mask.parse_hcmask_line``. ``llm.generate_masks``
    already ran every suggestion through that exact function before this one
    ever sees it; this check exists for callers reaching ``hcatRosettaMask``
    some other way, and returns ``False`` (rather than raising) for a
    non-string, an empty string, or anything ``parse_hcmask_line`` rejects.

    Three checks stay local because they're about ``.hcmask`` *file* safety,
    not mask grammar, and ``parse_hcmask_line`` has no reason to know about
    them: an embedded ``\\n``/``\\r``/``\\t`` is rejected because each mask
    becomes its own line in the file and a newline would split it into two
    (one of them possibly blank, which hashcat refuses to run); a mask
    starting with ``#`` is rejected because hashcat treats such a
    ``.hcmask`` line as a comment and would silently skip it.
    """
    if not isinstance(mask, str) or not mask:
        return False
    if any(c in mask for c in ("\n", "\r", "\t")):
        return False
    if mask.startswith("#"):
        return False
    # The two names are always set together in the single try/except above
    # (both real or both None) -- checking both, not just the one this
    # function calls, is what lets the type checker narrow the except
    # clause below instead of still seeing `type[RosettaMaskError] | None`.
    if rosetta_parse_hcmask_line is None or RosettaMaskError is None:
        return False
    try:
        rosetta_parse_hcmask_line(mask)
    except RosettaMaskError:
        return False
    return True


# Top Mask Attack
def hcatTopMask(hcatHashType, hcatHashFile, hcatTargetTime):
    global hcatMaskCount
    global hcatProcess
    _extract_cracked_plaintexts(f"{hcatHashFile}.out", f"{hcatHashFile}.working")
    hcatProcess = subprocess.Popen(
        [
            sys.executable,
            os.path.join(hate_path, "PACK", "statsgen.py"),
            f"{hcatHashFile}.working",
            "-o",
            f"{hcatHashFile}.masks",
        ]
    )
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        print("Killing PID {0}...".format(str(hcatProcess.pid)))
        hcatProcess.kill()

    hcatProcess = subprocess.Popen(
        [
            sys.executable,
            os.path.join(hate_path, "PACK", "maskgen.py"),
            f"{hcatHashFile}.masks",
            "--targettime",
            str(hcatTargetTime),
            "--optindex",
            "-q",
            "--pps",
            "14000000000",
            "--minlength=7",
            "-o",
            f"{hcatHashFile}.hcmask",
        ]
    )
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        print("Killing PID {0}...".format(str(hcatProcess.pid)))
        hcatProcess.kill()

    cmd = [
        hcatBin,
        "-m",
        hcatHashType,
        hcatHashFile,
        "--session",
        generate_session_id(),
        "-o",
        f"{hcatHashFile}.out",
        "-a",
        "3",
        f"{hcatHashFile}.hcmask",
    ]
    if _should_use_optimized_kernel("hcatTopMask"):
        _insert_optimized_flag(cmd)
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(cmd)
    _run_hcat_cmd(
        cmd,
        attack_name="Top Mask",
        hash_file=hcatHashFile,
        coverage=_coverage.CoverageSpec(
            hash_file=hcatHashFile,
            mask_files=(f"{hcatHashFile}.hcmask",),
        ),
    )

    hcatMaskCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


def _llm_backend_label() -> str:
    """The human-facing name for the configured LLM backend, for spinner text."""
    return {
        "ollama": "Ollama",
        "vllm": "vLLM",
        "openai": "an OpenAI-compatible server",
    }.get(llmBackend, llmBackend)


def _llm_connection_help() -> str:
    """Backend-aware follow-up line for a failed LLM request.

    Ollama gets the ``ollama serve`` / ``ollama pull`` guidance that always
    applied here; a vLLM or generic OpenAI-compatible operator is not running
    either of those tools, so telling them to would be actively misleading.
    """
    if llmBackend == "ollama":
        return (
            "Ensure Ollama is running (ollama serve) and the model is pulled "
            f"(ollama pull {ollamaModel})."
        )
    return (
        f"Ensure the configured {_llm_backend_label()} server at {ollamaUrl} is "
        f"running and serving the model {ollamaModel!r}."
    )


# Rosetta Mask Attack: natural-language description -> hashcat masks
def hcatRosettaMask(hcatHashType, hcatHashFile, description):
    """Turn a plain-English description into hashcat masks and run them.

    Asks the configured LLM backend (via ``llm.generate_masks``) for masks
    matching *description*, screens the result with ``_valid_hcmask``, writes
    the survivors to ``<hcatHashFile>.hcmask``, and runs a ``-a 3`` mask
    attack against them immediately — mirroring ``hcatTopMask``'s tail.

    All three configured backends (Ollama, vLLM, an OpenAI-compatible server)
    are supported -- ``llm.generate_masks`` shapes the request per backend via
    ``llm.rosetta_backend_kwargs``. If the installed HashcatRosetta submodule
    predates the ``think``/``extra_request_body`` parameters that requires,
    ``llm.generate_masks`` still raises ``llm.RosettaBackendRefused`` for a
    non-Ollama backend, caught below with a message telling the operator to
    update the submodule.
    """
    destination_warning = llm.offsite_destination_warning(
        ollamaUrl, llmBackend, no_cloud=ollamaNoCloud
    )
    if destination_warning is not None:
        print(destination_warning)

    try:
        with spinner(f"Generating masks via {_llm_backend_label()} ({ollamaModel})..."):
            masks = llm.generate_masks(
                ollamaUrl,
                ollamaModel,
                ollamaNumCtx,
                description,
                timeout=ollamaTimeout,
                no_cloud=ollamaNoCloud,
                backend=llmBackend,
                api_key=llmApiKey,
            )
    except llm.LLMTimeoutError:
        print(
            f"Error: the {_llm_backend_label()} request timed out after {ollamaTimeout:g} seconds."
        )
        print(
            f"The model ({ollamaModel}) may still be loading into VRAM. Retry, or "
            "raise OLLAMA_TIMEOUT in the .env file to wait longer."
        )
        return
    except llm.RosettaBackendRefused as e:
        # A precise, self-contained refusal -- printing the generic
        # connection-help line after it would tell the operator to go check
        # a server that is not the problem (the exact failure mode this
        # exception type exists to prevent). Reached when llmBackend is not
        # "ollama" and the installed HashcatRosetta submodule predates the
        # think/extra_request_body parameters that backend needs; the
        # message tells the operator to update the submodule.
        print(f"Error: {e}")
        return
    except llm.CloudDestinationRefused as e:
        # Same reasoning as the RosettaBackendRefused branch above: a precise,
        # self-contained refusal, not a connectivity problem, so the generic
        # connection-help line below would be misleading.
        print(f"Error: {e}")
        return
    except Exception as e:
        print(f"Error generating masks: {e}")
        print(_llm_connection_help())
        return

    valid_masks = [mask for mask in masks if _valid_hcmask(mask)]
    if not valid_masks:
        print("Error: the model returned no usable masks.")
        return

    hcmask_path = f"{hcatHashFile}.hcmask"
    # latin-1, matching hcatSmartMask's .hcmask write: keeps any byte >= 0x80
    # an LLM backend might emit in a mask literal from being re-encoded into
    # a different, multi-byte UTF-8 sequence.
    with open(hcmask_path, "w", encoding="latin-1") as f:
        f.writelines(f"{mask}\n" for mask in valid_masks)
    print(f"Generated {len(valid_masks)} mask(s) -> {hcmask_path}")

    cmd = [
        hcatBin,
        "-m",
        hcatHashType,
        hcatHashFile,
        "--session",
        generate_session_id(),
        "-o",
        f"{hcatHashFile}.out",
        "-a",
        "3",
        hcmask_path,
    ]
    if _should_use_optimized_kernel("hcatRosettaMask"):
        _insert_optimized_flag(cmd)
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(cmd)
    _run_hcat_cmd(cmd, attack_name="Rosetta Mask", hash_file=hcatHashFile)


_FINGERPRINT_KEYSPACE_LIMIT = 50_000_000_000


def _fingerprint_expander_chain(max_expander_len):
    """Escalating substring lengths to expand at, small to big.

    E.g. max_expander_len=21 -> [7, 14, 21]; 24 -> [7, 14, 21, 24].
    """
    lengths = set(range(7, max_expander_len, 7))
    lengths.add(max_expander_len)
    return sorted(n for n in lengths if 7 <= n <= max_expander_len)


def _fingerprint_keyspace_guard(left_path, right_path, label, limit):
    """Return True if a -a1 combination of left/right should proceed.

    -a1's candidate count is exactly len(left) * len(right); on a
    partially-cracked hash list this can run into the billions, so this
    is checked before spending GPU time on it rather than after. Fingerprint
    runs unattended for its whole duration (it's launched once, up front),
    so an over-threshold combination is skipped with a warning rather than
    blocking on a prompt mid-run -- ``limit`` is instead decided once,
    up front, by the caller (falsy/0 means no limit).
    """
    if not limit:
        return True
    keyspace = lineCount(left_path) * lineCount(right_path)
    if keyspace <= limit:
        return True
    print(
        f"[!] {label}: {keyspace:,} candidates exceeds the "
        f"{limit:,}-candidate guardrail. Skipping."
    )
    return False


def _fingerprint_expand_new(expander_len, hcatHashFile, new_plaintexts):
    """Expand only newly-cracked plaintexts and merge the fragments into the
    accumulating {hcatHashFile}.expanded file (deduped).

    Only expanding the delta (not the whole cracked corpus) keeps each
    convergence-loop iteration's cost proportional to what changed, since
    the expander + combinator steps this feeds are the expensive part.
    """
    global hcatProcess

    expander_bin = (
        hcatExpanderBin if expander_len == 7 else f"expander{expander_len}.bin"
    )
    expander_path = os.path.join(hate_path, "hashcat-utils", "bin", expander_bin)
    ensure_binary(
        expander_path,
        build_dir=os.path.join(hate_path, "hashcat-utils"),
        name=expander_bin.replace(".bin", ""),
    )

    delta_path = f"{hcatHashFile}.working.new"
    with open(delta_path, "w") as f:
        f.write("\n".join(new_plaintexts) + "\n")

    delta_expanded_path = f"{hcatHashFile}.expanded.delta"
    with (
        open(delta_path, "rb") as src,
        open(delta_expanded_path, "wb") as dst,
    ):
        expander_proc = subprocess.Popen(
            [expander_path], stdin=src, stdout=subprocess.PIPE
        )
        expander_stdout = expander_proc.stdout
        if expander_stdout is None:
            raise RuntimeError("expander stdout pipe was not created")
        sort_proc = subprocess.Popen(
            ["sort", "-u"],
            stdin=expander_stdout,
            stdout=dst,
            env={**os.environ, "LC_ALL": "C"},
        )
        hcatProcess = sort_proc
        expander_stdout.close()
        try:
            sort_proc.wait()
            expander_proc.wait()
        except KeyboardInterrupt:
            print("Killing PID {0}...".format(str(sort_proc.pid)))
            sort_proc.kill()
            expander_proc.kill()

    expanded_path = f"{hcatHashFile}.expanded"
    fragments = set()
    if os.path.exists(expanded_path):
        with open(expanded_path, errors="replace") as f:
            fragments = {line.rstrip("\n") for line in f if line.strip()}
    with open(delta_expanded_path, errors="replace") as f:
        fragments |= {line.rstrip("\n") for line in f if line.strip()}
    with open(expanded_path, "w") as f:
        for fragment in sorted(fragments):
            f.write(fragment + "\n")


def _fingerprint_run_combine(hcatHashType, hcatHashFile, left, right):
    """Run a -a1 combination of left+right (no guardrail check — caller's job).

    Every side gets a cheap -j/-k capitalize rule for free Capitalized
    coverage of the raw fragments/dictionary words.
    """
    cmd = [
        hcatBin,
        "-m",
        hcatHashType,
        hcatHashFile,
        "--session",
        generate_session_id(),
        "-o",
        f"{hcatHashFile}.out",
        "-a",
        "1",
        "-j",
        "c",
        "-k",
        "c",
        left,
        right,
    ]
    if _should_use_optimized_kernel("hcatFingerprint"):
        _insert_optimized_flag(cmd)
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(cmd)
    _run_hcat_cmd(cmd, attack_name="Fingerprint", hash_file=hcatHashFile)


def _fingerprint_combine(hcatHashType, hcatHashFile, left, right, *, label, limit):
    """Run a -a1 combination of left+right, gated by the keyspace guardrail."""
    if not _fingerprint_keyspace_guard(left, right, label, limit):
        return
    _fingerprint_run_combine(hcatHashType, hcatHashFile, left, right)


# Fingerprint Attack
def hcatFingerprint(
    hcatHashType,
    hcatHashFile,
    max_expander_len: int = 21,
    run_hybrid_on_expanded: bool = False,
    dictionary_wordlist: str | None = None,
    keyspace_limit: int | None = None,
):
    global hcatFingerprintCount

    try:
        max_expander_len = int(max_expander_len)
    except Exception:
        max_expander_len = 21
    if max_expander_len < 7 or max_expander_len > 36:
        raise ValueError("max_expander_len must be an integer between 7 and 36")

    if keyspace_limit is None:
        keyspace_limit = _FINGERPRINT_KEYSPACE_LIMIT

    # No explicit choice from the caller falls back to the configured
    # default (if any); an explicit "" (declined at the prompt) does not,
    # so a user can still opt out of a configured default. Only one
    # wordlist is combined per run, so extra configured entries are noted
    # and ignored rather than silently dropped.
    if dictionary_wordlist is None:
        if len(hcatFingerprintWordlist) > 1:
            print(
                "[!] hcatFingerprintWordlist has multiple entries; using the "
                f"first ({hcatFingerprintWordlist[0]}), ignoring the rest."
            )
        dictionary_wordlist = (
            hcatFingerprintWordlist[0] if hcatFingerprintWordlist else None
        )

    resolved_dict = None
    if dictionary_wordlist:
        candidate = _resolve_wordlist_path(dictionary_wordlist, hcatWordlists)
        if os.path.isfile(candidate):
            resolved_dict = candidate
        else:
            print(f"[!] Wordlist not found: {candidate}")

    expanded_path = f"{hcatHashFile}.expanded"
    open(expanded_path, "w").close()  # fresh accumulator for this attack run

    any_candidates = False
    for expander_len in _fingerprint_expander_chain(max_expander_len):
        seen_plaintexts: set[str] = set()
        crackedBefore = lineCount(hcatHashFile + ".out")
        while True:
            _extract_cracked_plaintexts(
                f"{hcatHashFile}.out", f"{hcatHashFile}.working"
            )
            with open(f"{hcatHashFile}.working", errors="replace") as f:
                current_plaintexts = {line.rstrip("\n") for line in f if line.strip()}
            new_plaintexts = current_plaintexts - seen_plaintexts
            if not new_plaintexts:
                break
            seen_plaintexts |= new_plaintexts

            _fingerprint_expand_new(expander_len, hcatHashFile, sorted(new_plaintexts))
            any_candidates = True

            _fingerprint_combine(
                hcatHashType,
                hcatHashFile,
                expanded_path,
                expanded_path,
                label=f"Fingerprint self-combination (length {expander_len})",
                limit=keyspace_limit,
            )
            if resolved_dict:
                # Both orders share the same candidate count (len(a)*len(b)
                # == len(b)*len(a)), so the guardrail is checked once and its
                # answer applied to both instead of prompting twice.
                dict_label = (
                    f"Fingerprint dictionary-combination (length {expander_len})"
                )
                if _fingerprint_keyspace_guard(
                    expanded_path, resolved_dict, dict_label, keyspace_limit
                ):
                    _fingerprint_run_combine(
                        hcatHashType, hcatHashFile, expanded_path, resolved_dict
                    )
                    _fingerprint_run_combine(
                        hcatHashType, hcatHashFile, resolved_dict, expanded_path
                    )

            # Secondary attack: run hybrid on the expanded candidates (mode 6/7
            # variants). Intentionally optional to avoid changing the
            # "extensive" pipeline ordering.
            if run_hybrid_on_expanded:
                hcatHybrid(hcatHashType, hcatHashFile, [expanded_path])

            crackedAfter = lineCount(hcatHashFile + ".out")
            if crackedAfter == crackedBefore:
                break
            crackedBefore = crackedAfter

    if not any_candidates:
        print(
            "[!] Skipping Fingerprint Attack: no candidates to expand "
            "(no cracked passwords yet)."
        )
    hcatFingerprintCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


# Smart Mask Attack
def _tokenize_runs(plaintext: str) -> list[tuple[str, str]]:
    """Split *plaintext* into maximal same-class runs: "L" (isalpha),
    "D" (isdigit), "S" (everything else -- symbols, whitespace, non-ASCII
    punctuation). Case is not distinguished within an "L" run.

    E.g. "ChangeMe2day1624$!" -> [("L","ChangeMe"), ("D","2"), ("L","day"),
    ("D","1624"), ("S","$!")].
    """
    runs: list[tuple[str, str]] = []
    current_type: str | None = None
    current_chars: list[str] = []
    for char in plaintext:
        if char.isalpha():
            run_type = "L"
        elif char.isdigit():
            run_type = "D"
        else:
            run_type = "S"
        if run_type == current_type:
            current_chars.append(char)
        else:
            if current_type is not None:
                runs.append((current_type, "".join(current_chars)))
            current_type = run_type
            current_chars = [char]
    if current_type is not None:
        runs.append((current_type, "".join(current_chars)))
    return runs


def _shape_signature(runs: list[tuple[str, str]]) -> tuple[str, ...]:
    """The run-type sequence alone, e.g. ("L", "D", "L", "D", "S")."""
    return tuple(run_type for run_type, _content in runs)


def _seed_key(runs: list[tuple[str, str]]) -> tuple[str, ...]:
    """The content of every "L" run, in order -- a cheap first
    approximation of "same generator template", since generator stems are
    almost always alphabetic."""
    return tuple(content for run_type, content in runs if run_type == "L")


# Pure-function default for _cluster_smart_mask_templates when called
# directly (e.g. from tests) without an explicit min_cluster_size.
# hcatSmartMask itself uses the config-configurable hcatSmartMaskMinClusterSize
# global instead, which defaults to this same value.
_SMART_MASK_MIN_CLUSTER_SIZE = 3
_SMART_MASK_CHARSET_COVERAGE_THRESHOLD = 0.5

# Known generator alphabets, smallest first. Checked in this order so an
# all-lowercase sample matches "lowercase" rather than the larger
# "mixed_letters" superset it's also technically a subset of.
_SMART_MASK_KNOWN_ALPHABETS = (
    "0123456789",
    "!@#$%^&*()",
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
)


def _infer_charset(observed_chars: set[str]) -> str:
    """Expand observed_chars to a known alphabet when they look like a
    partial sample of it, otherwise use exactly what was observed.

    "Look like a partial sample" means observed_chars is a subset of a
    known alphabet and covers at least
    _SMART_MASK_CHARSET_COVERAGE_THRESHOLD of it -- e.g. 9 of the 10 US
    shift-row symbols already observed infers the tenth too.
    """
    for alphabet in _SMART_MASK_KNOWN_ALPHABETS:
        alphabet_set = set(alphabet)
        if observed_chars <= alphabet_set:
            coverage = len(observed_chars) / len(alphabet_set)
            if coverage >= _SMART_MASK_CHARSET_COVERAGE_THRESHOLD:
                return alphabet
    return "".join(sorted(observed_chars))


@dataclasses.dataclass(frozen=True)
class _SmartMaskTemplate:
    """One detected literal-skeleton pattern, ready to become .hcmask lines.

    ``fixed_runs`` holds every constant (position, run_type, content)
    triple; ``variable_positions`` names the remaining positions, in
    order, each paired by index with an entry in ``variable_charsets``.
    ``length_combinations`` is the set of observed per-member length
    tuples for the variable positions (one hcmask line per entry).
    """

    fixed_runs: tuple[tuple[int, str, str], ...]
    variable_positions: tuple[int, ...]
    variable_charsets: tuple[str, ...]
    length_combinations: tuple[tuple[int, ...], ...]
    member_count: int
    total_positions: int


def _build_template(
    group: list[list[tuple[str, str]]],
) -> "_SmartMaskTemplate | None":
    """Given a same-shape, same-seed-key group of run lists, determine
    which run positions are constant vs. variable across every member.

    Returns None if every position is constant (exact password reuse --
    nothing left for a mask attack to vary).
    """
    total_positions = len(group[0])
    fixed_runs: list[tuple[int, str, str]] = []
    variable_positions: list[int] = []
    for position in range(total_positions):
        run_type = group[0][position][0]
        contents_at_position = {runs[position][1] for runs in group}
        if len(contents_at_position) == 1:
            fixed_runs.append((position, run_type, group[0][position][1]))
        else:
            variable_positions.append(position)

    if not variable_positions:
        return None

    variable_charsets = []
    for position in variable_positions:
        observed_chars: set[str] = set()
        for runs in group:
            observed_chars.update(runs[position][1])
        variable_charsets.append(_infer_charset(observed_chars))

    length_combinations = sorted(
        {
            tuple(len(runs[position][1]) for position in variable_positions)
            for runs in group
        }
    )

    return _SmartMaskTemplate(
        fixed_runs=tuple(fixed_runs),
        variable_positions=tuple(variable_positions),
        variable_charsets=tuple(variable_charsets),
        length_combinations=tuple(length_combinations),
        member_count=len(group),
        total_positions=total_positions,
    )


def _cluster_smart_mask_templates(
    plaintexts: list[str], min_cluster_size: int = _SMART_MASK_MIN_CLUSTER_SIZE
) -> tuple[list["_SmartMaskTemplate"], int]:
    """Group plaintexts into literal-skeleton templates.

    Returns (templates, skipped_no_stem_count). A shape bucket whose seed
    key is empty (no alphabetic run at all -- an all-digit/symbol stem)
    is skipped rather than risking a bogus merge of unrelated generators;
    skipped_no_stem_count reports how many plaintexts that affected so
    the caller can log it instead of silently dropping them.
    """
    shape_buckets: dict[tuple[str, ...], list[list[tuple[str, str]]]] = {}
    for plaintext in plaintexts:
        runs = _tokenize_runs(plaintext)
        if not runs:
            continue
        shape_buckets.setdefault(_shape_signature(runs), []).append(runs)

    templates: list[_SmartMaskTemplate] = []
    skipped_no_stem = 0
    for members in shape_buckets.values():
        seed_groups: dict[tuple[str, ...], list[list[tuple[str, str]]]] = {}
        for runs in members:
            seed_groups.setdefault(_seed_key(runs), []).append(runs)
        for seed, group in seed_groups.items():
            if not seed:
                skipped_no_stem += len(group)
                continue
            if len(group) < min_cluster_size:
                continue
            template = _build_template(group)
            if template is not None:
                templates.append(template)
    return templates, skipped_no_stem


def _escape_mask_literal(text: str) -> str:
    """Escape literal '?' characters for use inside a hashcat mask string.

    hashcat's mask grammar reserves '?' as a token marker; a literal '?'
    in fixed skeleton text must be doubled ('??') so hashcat treats it as
    a literal character rather than a dangling/unknown token.
    """
    return text.replace("?", "??")


def _build_hcmask_lines(template: "_SmartMaskTemplate") -> list[str]:
    """Build one .hcmask line per observed variable-run length
    combination: literal text for fixed positions (escaped), repeated
    ``?N`` tokens for variable positions.
    """
    # Callers only reach this function after confirming Rosetta is
    # available (see hcatSmartMask's guard clause); this assert is purely
    # so ty narrows the guarded import's `Unknown | None` type here too.
    assert rosetta_format_hcmask_line is not None
    fixed_by_position = {
        position: content for position, _run_type, content in template.fixed_runs
    }
    lines = []
    for lengths in template.length_combinations:
        mask_parts = []
        for position in range(template.total_positions):
            if position in fixed_by_position:
                mask_parts.append(_escape_mask_literal(fixed_by_position[position]))
            else:
                slot_index = template.variable_positions.index(position)
                slot = slot_index + 1
                length = lengths[slot_index]
                mask_parts.append(f"?{slot}" * length)
        mask = "".join(mask_parts)
        lines.append(rosetta_format_hcmask_line(list(template.variable_charsets), mask))
    return lines


_SMART_MASK_KEYSPACE_LIMIT = 50_000_000_000


def hcatSmartMask(
    hcatHashType,
    hcatHashFile,
    min_cluster_size: int | None = None,
    keyspace_limit: int | None = None,
):
    """Detect literal-skeleton password patterns among already-cracked
    plaintexts and run a single targeted -a3 mask attack -- one mask line
    per qualifying template, combined into one .hcmask file -- against the
    full remaining hash list.
    """
    global hcatSmartMaskCount

    if (
        rosetta_parse_hcmask_line is None
        or rosetta_format_hcmask_line is None
        or RosettaMaskError is None
        or rosetta_keyspace is None
    ):
        print(f"[!] Smart Mask: {rosetta_unavailable_reason()}")
        hcatSmartMaskCount = 0
        return

    if min_cluster_size is None:
        min_cluster_size = hcatSmartMaskMinClusterSize
    if keyspace_limit is None:
        keyspace_limit = _SMART_MASK_KEYSPACE_LIMIT

    _extract_cracked_plaintexts(f"{hcatHashFile}.out", f"{hcatHashFile}.working")
    with open(f"{hcatHashFile}.working", errors="replace") as f:
        plaintexts = [line.rstrip("\n") for line in f if line.strip()]

    templates, skipped_no_stem = _cluster_smart_mask_templates(
        plaintexts, min_cluster_size
    )
    if skipped_no_stem:
        print(
            f"[!] Smart Mask: skipping {skipped_no_stem} plaintext(s) with no "
            "alphabetic stem (all-digit/symbol passwords) -- unsupported in "
            "this version."
        )
    if not templates:
        print("[*] Smart Mask: no qualifying clusters found.")
        hcatSmartMaskCount = 0
        return

    all_lines = []
    accounts_covered = 0
    for index, template in enumerate(templates, start=1):
        try:
            lines = _build_hcmask_lines(template)
            parsed_lines = [rosetta_parse_hcmask_line(line) for line in lines]
        except RosettaMaskError as exc:
            print(f"[!] Smart Mask: skipping an unbuildable template ({exc}).")
            continue

        candidate_total = sum(rosetta_keyspace(p) for p in parsed_lines)
        if keyspace_limit and candidate_total > keyspace_limit:
            print(
                f"[!] Smart Mask (template {index}/{len(templates)}, "
                f"{template.member_count} accounts): {candidate_total:,} "
                f"candidates exceeds the {keyspace_limit:,}-candidate guardrail. "
                "Skipping."
            )
            continue

        all_lines.extend(lines)
        accounts_covered += template.member_count

    if not all_lines:
        print(
            "[*] Smart Mask: no templates survived validation or the keyspace "
            "guardrail."
        )
        hcatSmartMaskCount = 0
        return

    hcmask_path = f"{hcatHashFile}.smartmask.hcmask"
    # latin-1: fixed-run literals and charsets come from decoded $HEX[...]
    # plaintexts, where each character already represents one raw byte (see
    # convert_hex). UTF-8 would re-encode any byte >= 0x80 into a different,
    # multi-byte sequence, corrupting the exact bytes hashcat needs to try.
    with open(hcmask_path, "w", encoding="latin-1") as f:
        f.writelines(f"{line}\n" for line in all_lines)

    cmd = [
        hcatBin,
        "-m",
        hcatHashType,
        hcatHashFile,
        "--session",
        generate_session_id(),
        "-o",
        f"{hcatHashFile}.out",
        "-a",
        "3",
        hcmask_path,
    ]
    if _should_use_optimized_kernel("hcatSmartMask"):
        _insert_optimized_flag(cmd)
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(cmd)
    label = f"Smart Mask ({len(all_lines)} pattern(s), {accounts_covered} accounts)"
    try:
        _run_hcat_cmd(
            cmd, attack_name=label, hash_file=hcatHashFile, reraise_interrupt=True
        )
    except KeyboardInterrupt:
        pass
    finally:
        if os.path.exists(hcmask_path):
            os.remove(hcmask_path)

    hcatSmartMaskCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


# Combinator Attack
def hcatCombination(hcatHashType, hcatHashFile, wordlists=None):
    global hcatCombinationCount
    global hcatProcess

    # Use provided wordlists or fall back to config default
    if wordlists is None:
        wordlists = hcatCombinationWordlist

    # Ensure wordlists is a list with at least 2 items
    if not isinstance(wordlists, list):
        wordlists = [wordlists]

    if len(wordlists) < 2:
        print("[!] Combinator attack requires at least 2 wordlists.")
        return

    # Resolve wordlist paths
    resolved_wordlists = []
    for wordlist in wordlists[:2]:  # Only use first 2 wordlists
        resolved = _resolve_wordlist_path(wordlist, hcatWordlists)
        if os.path.isfile(resolved):
            resolved_wordlists.append(resolved)
        else:
            print(f"[!] Wordlist not found: {resolved}")

    if len(resolved_wordlists) < 2:
        print("[!] Could not find 2 valid wordlists. Aborting combinator attack.")
        return

    cmd = [
        hcatBin,
        "-m",
        hcatHashType,
        hcatHashFile,
        "--session",
        generate_session_id(),
        "-o",
        f"{hcatHashFile}.out",
        "-a",
        "1",
        resolved_wordlists[0],
        resolved_wordlists[1],
    ]
    if _should_use_optimized_kernel("hcatCombination"):
        _insert_optimized_flag(cmd)
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(cmd)
    _run_hcat_cmd(cmd, attack_name="Combinator", hash_file=hcatHashFile)

    hcatCombinationCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


# Combinator3 Attack - 3-way combination via combinator3.bin piped to hashcat
def hcatCombinator3(hcatHashType, hcatHashFile, wordlists):
    global hcatCombinator3Count
    global hcatProcess

    if len(wordlists) < 3:
        print("[!] Combinator3 attack requires exactly 3 wordlists.")
        return

    combinator3_bin = os.path.join(hate_path, "hashcat-utils/bin/combinator3.bin")
    with contextlib.ExitStack() as stack:
        resolved = [stack.enter_context(_wordlist_path(w)) for w in wordlists[:3]]
        generator_cmd = [combinator3_bin] + resolved
        hashcat_cmd = [
            hcatBin,
            "-m",
            hcatHashType,
            hcatHashFile,
            "--session",
            generate_session_id(),
            "-o",
            f"{hcatHashFile}.out",
        ]
        if _should_use_optimized_kernel("hcatCombinator3"):
            _insert_optimized_flag(hashcat_cmd)
        hashcat_cmd.extend(shlex.split(hcatTuning))
        _append_potfile_arg(hashcat_cmd)
        generator_proc = subprocess.Popen(generator_cmd, stdout=subprocess.PIPE)
        assert generator_proc.stdout is not None
        _run_hcat_cmd(
            hashcat_cmd,
            attack_name="Combinator",
            hash_file=hcatHashFile,
            stdin=generator_proc.stdout,
            companion_procs=[generator_proc],
        )
        if generator_proc.stdout:
            generator_proc.stdout.close()

    hcatCombinator3Count = lineCount(hcatHashFile + ".out") - hcatHashCracked


# CombinatorX Attack - N-way combination (2-8 wordlists) via combinatorX.bin piped to hashcat
def hcatCombinatorX(hcatHashType, hcatHashFile, wordlists, separator=None):
    global hcatCombinatorXCount
    global hcatProcess

    if len(wordlists) < 2:
        print("[!] CombinatorX attack requires at least 2 wordlists.")
        return

    combinatorX_bin = os.path.join(hate_path, "hashcat-utils/bin/combinatorX.bin")
    with contextlib.ExitStack() as stack:
        resolved = [stack.enter_context(_wordlist_path(w)) for w in wordlists[:8]]
        generator_cmd = [combinatorX_bin]
        for i, f in enumerate(resolved, start=1):
            generator_cmd += [f"--file{i}", f]
        if separator:
            generator_cmd += ["--sepFill", separator]
        hashcat_cmd = [
            hcatBin,
            "-m",
            hcatHashType,
            hcatHashFile,
            "--session",
            generate_session_id(),
            "-o",
            f"{hcatHashFile}.out",
        ]
        if _should_use_optimized_kernel("hcatCombinatorX"):
            _insert_optimized_flag(hashcat_cmd)
        hashcat_cmd.extend(shlex.split(hcatTuning))
        _append_potfile_arg(hashcat_cmd)
        generator_proc = subprocess.Popen(generator_cmd, stdout=subprocess.PIPE)
        assert generator_proc.stdout is not None
        _run_hcat_cmd(
            hashcat_cmd,
            attack_name="Combinator",
            hash_file=hcatHashFile,
            stdin=generator_proc.stdout,
            companion_procs=[generator_proc],
        )
        if generator_proc.stdout:
            generator_proc.stdout.close()

    hcatCombinatorXCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


# NgramX Attack - n-gram candidates from corpus file piped to hashcat
def hcatNgramX(hcatHashType, hcatHashFile, corpus, group_size=3):
    global hcatNgramXCount
    global hcatProcess

    ngramX_bin = os.path.join(hate_path, "hashcat-utils/bin/ngramX.bin")
    with _wordlist_path(corpus) as resolved_corpus:
        generator_cmd = [ngramX_bin, resolved_corpus, str(group_size)]
        hashcat_cmd = [
            hcatBin,
            "-m",
            hcatHashType,
            hcatHashFile,
            "--session",
            generate_session_id(),
            "-o",
            f"{hcatHashFile}.out",
        ]
        if _should_use_optimized_kernel("hcatNgramX"):
            _insert_optimized_flag(hashcat_cmd)
        hashcat_cmd.extend(shlex.split(hcatTuning))
        _append_potfile_arg(hashcat_cmd)
        generator_proc = subprocess.Popen(generator_cmd, stdout=subprocess.PIPE)
        assert generator_proc.stdout is not None
        _run_hcat_cmd(
            hashcat_cmd,
            attack_name="N-gram",
            hash_file=hcatHashFile,
            stdin=generator_proc.stdout,
            companion_procs=[generator_proc],
        )
        if generator_proc.stdout:
            generator_proc.stdout.close()

    hcatNgramXCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


# Hybrid Attack
def hcatHybrid(hcatHashType, hcatHashFile, wordlists=None):
    global hcatHybridCount
    global hcatProcess

    # Use provided wordlists or fall back to config default
    if wordlists is None:
        wordlists = hcatHybridlist

    # Ensure wordlists is a list
    if not isinstance(wordlists, list):
        wordlists = [wordlists]

    resolved_wordlists = []
    for wordlist in wordlists:
        resolved = _resolve_wordlist_path(wordlist, hcatWordlists)
        if any(ch in resolved for ch in "*?[]") or os.path.isfile(resolved):
            resolved_wordlists.append(resolved)
        else:
            print(f"[!] Wordlist not found: {resolved}")
    if not resolved_wordlists:
        print("[!] No valid wordlists found. Aborting hybrid attack.")
        return

    for wordlist in resolved_wordlists:
        variants = [
            ["-a", "6", "-1", "?s?d", wordlist, "?1?1"],
            ["-a", "6", "-1", "?s?d", wordlist, "?1?1?1"],
            ["-a", "6", "-1", "?s?d", wordlist, "?1?1?1?1"],
            ["-a", "7", "-1", "?s?d", "?1?1", wordlist],
            ["-a", "7", "-1", "?s?d", "?1?1?1", wordlist],
            ["-a", "7", "-1", "?s?d", "?1?1?1?1", wordlist],
        ]
        for args in variants:
            cmd = [
                hcatBin,
                "-m",
                hcatHashType,
                hcatHashFile,
                "--session",
                generate_session_id(),
                "-o",
                f"{hcatHashFile}.out",
                *args,
            ]
            if _should_use_optimized_kernel("hcatHybrid"):
                _insert_optimized_flag(cmd)
            cmd.extend(shlex.split(hcatTuning))
            _append_potfile_arg(cmd)
            _run_hcat_cmd(cmd, attack_name="Hybrid", hash_file=hcatHashFile)

        hcatHybridCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


# YOLO Combination Attack
def hcatYoloCombination(hcatHashType, hcatHashFile):
    global hcatProcess
    try:
        while 1:
            _yolo_wordlists = list_wordlist_files(hcatWordlists)
            hcatLeft = random.choice(_yolo_wordlists)
            hcatRight = random.choice(_yolo_wordlists)
            left_path = os.path.join(hcatWordlists, hcatLeft)
            right_path = os.path.join(hcatWordlists, hcatRight)
            cmd = [
                hcatBin,
                "-m",
                hcatHashType,
                hcatHashFile,
                "--session",
                generate_session_id(),
                "-o",
                f"{hcatHashFile}.out",
                "-a",
                "1",
                left_path,
                right_path,
            ]
            if _should_use_optimized_kernel("hcatYoloCombination"):
                _insert_optimized_flag(cmd)
            cmd.extend(shlex.split(hcatTuning))
            _append_potfile_arg(cmd)
            _run_hcat_cmd(
                cmd,
                attack_name="YOLO Combination",
                hash_file=hcatHashFile,
                reraise_interrupt=True,
            )
    except KeyboardInterrupt:
        pass


# Bandrel methodlogy
def hcatBandrel(hcatHashType, hcatHashFile):
    global hcatProcess
    basewords = []
    while True:
        company_name = input(
            "What is the company name (Enter multiples comma separated)? "
        )
        if company_name:
            break
    for name in company_name.split(","):
        basewords.append(name)
    for word in bandrelbasewords.split(","):
        basewords.append(word)
    for name in basewords:
        mask1 = "-1{0}{1}".format(name[0].lower(), name[0].upper())
        mask2 = " ?1{0}".format(name[1:])
        for x in range(6):
            mask2 += "?a"
        cmd = [
            hcatBin,
            "-m",
            hcatHashType,
            "-a",
            "3",
            "--session",
            generate_session_id(),
            "-o",
            f"{hcatHashFile}.out",
            "--runtime",
            str(maxruntime),
            "-i",
            mask1,
            hcatHashFile,
            mask2.strip(),
        ]
        if _should_use_optimized_kernel("hcatBandrel"):
            _insert_optimized_flag(cmd)
        cmd.extend(shlex.split(hcatTuning))
        _append_potfile_arg(cmd)
        _run_hcat_cmd(cmd, attack_name="Bandrel", hash_file=hcatHashFile)
    print(
        "Checking passwords against pipal for top {0} passwords and basewords".format(
            pipal_count
        )
    )
    pipal_basewords = pipal()
    if pipal_basewords:
        for word in pipal_basewords:
            if word:
                mask1 = "-1={0}{1}".format(word[0].lower(), word[0].upper())
                mask2 = " ?1{0}".format(word[1:])
                # ...existing code using mask1, mask2...
            else:
                continue
    else:
        pass
        for x in range(6):
            mask2 += "?a"
        cmd = [
            hcatBin,
            "-m",
            hcatHashType,
            "-a",
            "3",
            "--session",
            generate_session_id(),
            "-o",
            f"{hcatHashFile}.out",
            "--runtime",
            str(maxruntime),
            "-i",
            mask1,
            hcatHashFile,
            mask2.strip(),
        ]
        if _should_use_optimized_kernel("hcatBandrel"):
            _insert_optimized_flag(cmd)
        cmd.extend(shlex.split(hcatTuning))
        _append_potfile_arg(cmd)
        _run_hcat_cmd(cmd, attack_name="Bandrel", hash_file=hcatHashFile)


def _sample_plaintext_file(path, cap, source_label="wordlist"):
    """Return an evenly-spaced sample of usable plaintexts from ``path``.

    ``cap`` is the maximum number of lines to keep (values <= 0 fall back to the
    built-in default of 500).  ``source_label`` is used only in the progress and
    error messages so callers can say "wordlist" or "cracked passwords".

    Returns a list of plaintexts (possibly empty when the file has no usable
    lines), or ``None`` if the file could not be read — in which case an error
    has already been printed.
    """
    # Two-pass evenly-spaced sample: first count usable lines so we can
    # stride-select across the whole file rather than taking a head slice.
    # A head-only sample misses the pattern variation across large wordlists
    # (e.g. rockyou.txt becomes more random further in).
    try:
        total_usable = 0
        with open(path, "r", errors="ignore") as f:
            for raw in f:
                if _usable_plaintext(raw):
                    total_usable += 1
    except Exception as e:
        print(f"Error reading {source_label}: {e}")
        return None

    # Invalid cap (zero or negative): fall back to the built-in default of 500.
    if cap <= 0:
        cap = 500

    if total_usable <= cap:
        # No capping needed — collect all usable lines.
        try:
            sampled: list[str] = []
            with open(path, "r", errors="ignore") as f:
                for raw in f:
                    w = _usable_plaintext(raw)
                    if w:
                        sampled.append(w)
        except Exception as e:
            print(f"Error reading {source_label}: {e}")
            return None
        print(f"Loaded {len(sampled):,} passwords from {source_label}.")
        return sampled

    # Evenly-spaced sample: the k-th pick targets index floor(k * total / cap),
    # which yields EXACTLY cap distinct indices spanning the full range for any
    # 1 <= cap <= total_usable.
    try:
        pick_set = {(k * total_usable) // cap for k in range(cap)}
        sampled = []
        usable_idx = 0
        with open(path, "r", errors="ignore") as f:
            for raw in f:
                w = _usable_plaintext(raw)
                if not w:
                    continue
                if usable_idx in pick_set:
                    sampled.append(w)
                usable_idx += 1
    except Exception as e:
        print(f"Error reading {source_label}: {e}")
        return None
    print(
        f"Sampled {len(sampled):,} of {total_usable:,} passwords from {source_label}."
    )
    return sampled


def _corpus_context(path, source_label="wordlist"):
    """Build the LLM context dict describing the corpus at *path*.

    Returns a dict with a ``summary`` key (whole-corpus statistics) and, when
    the corpus is small enough to fit under ``ollamaMaxSampleLines`` in full, a
    ``sample`` key holding the literal plaintexts as well. Returns None if the
    file cannot be read or holds no passwords, having already printed why.

    Statistics rather than a slice because the sample cap is not the real
    constraint — ``ollamaNumCtx`` is. Several hundred raw plaintexts crowd the
    context window while still describing a fraction of a large dump, and they
    carry no frequency information at all: the model cannot tell a baseword
    used by 8% of the organization from one used by a single person. The
    aggregate covers 100% of the corpus at a bounded size. Literal plaintexts
    are still included when they all fit, since nothing is gained by hiding
    them from a small corpus.
    """
    try:
        with _wordlist_path(path) as resolved_path:
            # "no LLM yet" is load-bearing, not decoration: summarize() is a
            # pure local pass that never contacts the model, but on a corpus
            # of a few million lines it runs for the better part of a minute,
            # and a bare "Analyzing..." reads as the model having stalled.
            cap = hcatCorpusProfileMaxLines
            with spinner(
                f"Profiling {source_label} locally (no LLM yet)..."
            ) as _profile_progress:
                stats = _corpus_stats.summarize(
                    resolved_path,
                    progress=lambda n: _profile_progress.set_detail(
                        f"{n:,} / {cap:,} lines" if cap > 0 else f"{n:,} lines"
                    ),
                    max_lines=cap,
                )

            context = {"summary": _corpus_stats.format_summary(stats)}
            if stats.get("sampled"):
                estimated = stats.get("estimated_total") or stats["total"]
                print(
                    f"Profiled {stats['total']:,} passwords sampled evenly from "
                    f"{source_label} (~{estimated:,} lines, "
                    f"{stats['baseword_total']:,} distinct basewords). Raise "
                    "hcatCorpusProfileMaxLines in config.json to sample more."
                )
            else:
                print(
                    f"Analyzed all {stats['total']:,} passwords in {source_label} "
                    f"({stats['baseword_total']:,} distinct basewords)."
                )
            # A raw NTDS dump and a cracked-output file both live in the
            # working directory with similar names, and the dump produces
            # confident nonsense rather than an error, so say so instead of
            # letting it through quietly.
            hash_shaped = stats.get("hash_shaped", 0)
            if hash_shaped > stats["total"] * 0.25:
                print(
                    f"[!] Warning: {hash_shaped:,} of {stats['total']:,} lines "
                    "look like hashes, not plaintexts. This file may be an "
                    "uncracked dump rather than cracked output; the statistics "
                    "below will be meaningless if so."
                )

            cap = ollamaMaxSampleLines if ollamaMaxSampleLines > 0 else 500
            if stats["total"] <= cap:
                sampled = _sample_plaintext_file(
                    resolved_path, cap, source_label=source_label
                )
                if sampled:
                    context["sample"] = "\n".join(sampled)
            # NOTE: this return sits inside the try, so a ValueError/OSError
            # raised by format_summary() or _sample_plaintext_file() above is
            # swallowed into the OSError handler below and this function
            # returns None instead of propagating. Widened blast radius is
            # incidental to this block, not intentional; inert today because
            # neither helper currently raises those.
            return context
    except OSError as e:
        print(f"Error reading {source_label}: {e}")
        return None
    except ValueError as e:
        print(f"Error: {e}")
        return None


def hcatOllamaResearchTarget(company):
    """Ask the configured LLM backend what it knows about *company*.

    Returns a dict with "industry", "location", and "parent_company" keys; any
    value may be an empty string when the model is not confident or the request
    failed. Never raises: research is a convenience, so any failure degrades to
    empty suggestions (blank prompts) rather than blocking the attack.

    Uses the configured local server (Ollama, vLLM, or another
    OpenAI-compatible server) — see ``OLLAMA_NO_CLOUD`` for the guard that
    keeps the company name from reaching a cloud model or an offsite
    destination.
    """
    blank = {"industry": "", "location": "", "parent_company": ""}
    if not ollamaAutoResearch or not company:
        return blank

    destination_warning = llm.offsite_destination_warning(
        ollamaUrl, llmBackend, no_cloud=ollamaNoCloud
    )
    if destination_warning is not None:
        print(destination_warning)

    try:
        with spinner(
            f"Researching {company} via {_llm_backend_label()} ({ollamaModel})..."
        ):
            result = llm.research_target(
                ollamaUrl,
                ollamaModel,
                ollamaNumCtx,
                company,
                timeout=ollamaTimeout,
                no_cloud=ollamaNoCloud,
                backend=llmBackend,
                api_key=llmApiKey,
            )
    except llm.LLMTimeoutError:
        print(
            f"Note: target research timed out after {ollamaTimeout:g} seconds — "
            "enter the details manually."
        )
        return blank
    except llm.CloudDestinationRefused as e:
        print(f"Note: {e} Enter the details manually.")
        return blank
    except Exception as e:
        print(f"Note: target research unavailable ({e}) — enter the details manually.")
        return blank

    return {
        "industry": result.industry,
        "location": result.location,
        "parent_company": result.parent_company,
    }


# LLM Ollama Attack
def hcatOllama(hcatHashType, hcatHashFile, mode, context_data):
    candidates_path = f"{hcatHashFile}.ollama_candidates"

    # Step A: normalize context into the dict generate_candidates expects.
    if mode == "wordlist":
        wordlist_path = context_data
        if not os.path.isfile(wordlist_path):
            print(f"Error: Wordlist not found: {wordlist_path}")
            return

        gen_context = _corpus_context(wordlist_path)
        if gen_context is None:
            return
    elif mode == "cracked":
        # context_data may carry an explicit path; default to this session's
        # cracked-output file.
        cracked_path = context_data or f"{hcatHashFile}.out"
        if not os.path.isfile(cracked_path):
            print(f"Error: No cracked passwords found: {cracked_path}")
            return

        gen_context = _corpus_context(cracked_path, source_label="cracked passwords")
        if gen_context is None:
            print(
                "Error: No cracked passwords yet — crack some hashes first, then "
                "use this mode to generate more candidates in the same style."
            )
            return
    elif mode == "target":
        gen_context = context_data
    else:
        print(f"Error: Unknown LLM generation mode: {mode}")
        return

    destination_warning = llm.offsite_destination_warning(
        ollamaUrl, llmBackend, no_cloud=ollamaNoCloud
    )
    if destination_warning is not None:
        print(destination_warning)

    # Step B: generate candidates via the Atomic Agents module.
    try:
        with spinner(
            f"Generating password candidates via {_llm_backend_label()} ({ollamaModel})..."
        ):
            candidates = llm.generate_candidates(
                ollamaUrl,
                ollamaModel,
                ollamaNumCtx,
                mode,
                gen_context,
                timeout=ollamaTimeout,
                no_cloud=ollamaNoCloud,
                backend=llmBackend,
                api_key=llmApiKey,
            )
    except llm.LLMTimeoutError:
        print(
            f"Error: the {_llm_backend_label()} request timed out after {ollamaTimeout:g} seconds."
        )
        print(
            f"The model ({ollamaModel}) may still be loading into VRAM. Retry, or "
            "raise OLLAMA_TIMEOUT in the .env file to wait longer."
        )
        return
    except ValueError as e:
        # Defensive: mode is already validated above, but keep an explicit,
        # non-misleading message if generate_candidates ever rejects its input.
        print(f"Error: {e}")
        return
    except llm.CloudDestinationRefused as e:
        # A precise, self-contained refusal, not a connectivity problem, so
        # the generic connection-help line below would be misleading.
        print(f"Error: {e}")
        return
    except Exception as e:
        print(f"Error generating candidates: {e}")
        print(_llm_connection_help())
        return

    if not candidates:
        print(f"Error: {_llm_backend_label()} returned no usable password candidates.")
        return

    try:
        with open(candidates_path, "w") as f:
            for candidate in candidates:
                f.write(candidate + "\n")
    except Exception as e:
        print(f"Error writing candidates file: {e}")
        return

    print(f"Generated {len(candidates)} password candidates -> {candidates_path}")

    # Step C: hashcat wordlist attack with the generated candidates (no rules).
    print("Running wordlist attack with LLM-generated candidates...")
    cmd = [
        hcatBin,
        "-m",
        hcatHashType,
        hcatHashFile,
        "--session",
        generate_session_id(),
        "-o",
        f"{hcatHashFile}.out",
        candidates_path,
    ]
    if _should_use_optimized_kernel("hcatOllama"):
        _insert_optimized_flag(cmd)
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(cmd)
    try:
        _run_hcat_cmd(
            cmd,
            attack_name="LLM",
            hash_file=hcatHashFile,
            reraise_interrupt=True,
        )
    except KeyboardInterrupt:
        return

    # Step D: hashcat with candidates against every rule in the rules directory.
    rule_files = list_rule_files(rulesDirectory)
    if not rule_files:
        print("No rule files found in rules directory. Skipping rule-based attacks.")
        return

    print(
        f"\nRunning LLM candidates with {len(rule_files)} rule file(s) from {rulesDirectory}..."
    )
    for rule in rule_files:
        rule_path = os.path.join(rulesDirectory, rule)
        print(f"\n\tRunning with rule: {rule}")
        cmd = [
            hcatBin,
            "-m",
            hcatHashType,
            hcatHashFile,
            "--session",
            generate_session_id(),
            "-o",
            f"{hcatHashFile}.out",
            "-r",
            rule_path,
            candidates_path,
        ]
        if _should_use_optimized_kernel("hcatOllama"):
            _insert_optimized_flag(cmd)
        cmd.extend(shlex.split(hcatTuning))
        _append_potfile_arg(cmd)
        cmd = _add_debug_mode_for_rules(cmd)
        try:
            _run_hcat_cmd(
                cmd,
                attack_name="LLM",
                hash_file=hcatHashFile,
                reraise_interrupt=True,
            )
        except KeyboardInterrupt:
            return


MIN_PATTERN_LEN = 3


def _clean_pattern(raw):
    """Reduce one model-returned pattern to a bare lowercase baseword.

    Returns "" for anything unusable. The prompt asks for lowercase letters
    only, but the rule file is what supplies case, digits, and punctuation — so
    a model that decorates its answer anyway would otherwise get decorated a
    second time by the rules, stacking a suffix on top of one the model already
    added. The filter is applied here rather than trusted to the prompt for that
    reason.
    """
    if not isinstance(raw, str):
        return ""
    letters = "".join(c for c in raw.lower() if "a" <= c <= "z")
    if len(letters) < MIN_PATTERN_LEN:
        return ""
    return letters


# A thin rule file wastes the pass it is spent on, and local-model yield here
# varies a lot run to run — measured against one 600-line corpus, the same
# prompt and model returned 40 valid rules one run and 16 the next. So a thin
# first answer is asked again rather than accepted, up to this many requests.
MIN_GENERATED_RULES = 25
MAX_RULE_REQUESTS = 2

# Corporate Masks attack length constraints. The bounds are the lengths the
# upstream mask set actually ships (corp_8.hcmask .. corp_14.hcmask); the
# default ceiling stops short of them because keyspace grows steeply with
# length and 8-10 is the useful first pass.
CORPORATE_MASK_MIN_LEN = 8
CORPORATE_MASK_MAX_LEN = 14
CORPORATE_MASK_DEFAULT_MAX_LEN = 10


def _llm_pattern_rules(gen_context):
    """Ask the model for hashcat rules describing *gen_context*'s corpus.

    Returns ``(rules, discarded)`` — the rules that passed
    ``rulegen.validate_rule``, in the order the model ranked them, and how many
    it returned that did not. Returns ``(None, 0)`` when the *first* request
    failed outright, having already printed why; an empty list means the model
    answered but nothing it said was usable.

    Retries once when the yield comes in under ``MIN_GENERATED_RULES``, keeping
    whatever the earlier attempt produced — the model is sampled, not
    deterministic, so a second ask genuinely adds rules rather than repeating
    the first. A failure on a retry is not fatal: rules already in hand still
    run.

    Validation is not optional. hashcat drops an invalid rule silently when the
    file also holds valid ones, so an unscreened bad line becomes missing
    coverage the operator never hears about rather than an error.

    Not a standalone operator entry point -- only ``hcatOllamaPatterns`` calls
    this, and it has already printed ``llm.offsite_destination_warning`` once
    for the whole (patterns + rules) request pair, so this function does not
    print it again.
    """
    rules = []
    seen = set()
    discarded = 0
    for attempt in range(1, MAX_RULE_REQUESTS + 1):
        label = f"Inferring hashcat rules via {_llm_backend_label()} ({ollamaModel})"
        if attempt > 1:
            label += f" — retry {attempt - 1}, {len(rules)} rules so far"
        try:
            with spinner(f"{label}..."):
                raw_rules = llm.generate_rules(
                    ollamaUrl,
                    ollamaModel,
                    ollamaNumCtx,
                    gen_context,
                    timeout=ollamaTimeout,
                    no_cloud=ollamaNoCloud,
                    backend=llmBackend,
                    api_key=llmApiKey,
                )
        except llm.LLMTimeoutError:
            print(
                f"Error: the {_llm_backend_label()} rule request timed out after {ollamaTimeout:g} s."
            )
            return (None, 0) if attempt == 1 else (rules, discarded)
        except ValueError as e:
            print(f"Error: {e}")
            return (None, 0) if attempt == 1 else (rules, discarded)
        except llm.CloudDestinationRefused as e:
            print(f"Error: {e}")
            return (None, 0) if attempt == 1 else (rules, discarded)
        except Exception as e:
            print(f"Error inferring rules: {e}")
            return (None, 0) if attempt == 1 else (rules, discarded)

        for raw in raw_rules:
            if not _rulegen.validate_rule(raw):
                discarded += 1
            elif raw not in seen:
                seen.add(raw)
                rules.append(raw)
        if len(rules) >= MIN_GENERATED_RULES:
            break

    return (rules, discarded)


def hcatOllamaPatterns(hcatHashType, hcatHashFile, source_path):
    """LLM Pattern Rules: infer basewords *and* rules from a corpus, then crack.

    Takes the same shape as the Spoonman attack (see hcatSpoonman and
    hate_crack/rulegen.py) — a baseword list run through a rule file, both
    derived from the corpus — but infers each side with the model instead of
    extracting it. Spoonman is exact and therefore bounded: its basewords all
    appear in the corpus and its rules only reproduce transformations the corpus
    already shows. This asks the model to generalize on both axes at once, so it
    can name word families the corpus only hints at and write decorations the
    corpus does not contain.

    The operator is not asked to choose a rule file. Picking one would defeat
    the point — a stock rule file encodes the internet's habits, while the whole
    reason to spend a model round trip here is to encode *this* organization's.

    Both requests share one corpus analysis, and the rule request is what can
    come back empty in practice, so a model that produces no valid rules falls
    back to running the basewords bare rather than aborting a run whose
    expensive half already succeeded.
    """
    if not os.path.isfile(source_path):
        print(f"Error: pattern source not found: {source_path}")
        return

    gen_context = _corpus_context(source_path, source_label="pattern source")
    if gen_context is None:
        return

    destination_warning = llm.offsite_destination_warning(
        ollamaUrl, llmBackend, no_cloud=ollamaNoCloud
    )
    if destination_warning is not None:
        print(destination_warning)

    try:
        with spinner(
            f"Inferring password patterns via {_llm_backend_label()} ({ollamaModel})..."
        ):
            raw_patterns = llm.generate_candidates(
                ollamaUrl,
                ollamaModel,
                ollamaNumCtx,
                "pattern",
                gen_context,
                timeout=ollamaTimeout,
                no_cloud=ollamaNoCloud,
                backend=llmBackend,
                api_key=llmApiKey,
            )
    except llm.LLMTimeoutError:
        print(
            f"Error: the {_llm_backend_label()} request timed out after {ollamaTimeout:g} seconds."
        )
        print(
            f"The model ({ollamaModel}) may still be loading into VRAM. Retry, or "
            "raise OLLAMA_TIMEOUT in the .env file to wait longer."
        )
        return
    except ValueError as e:
        print(f"Error: {e}")
        return
    except llm.CloudDestinationRefused as e:
        print(f"Error: {e}")
        return
    except Exception as e:
        print(f"Error inferring patterns: {e}")
        print(_llm_connection_help())
        return

    seen = set()
    patterns = []
    for raw in raw_patterns:
        cleaned = _clean_pattern(raw)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            patterns.append(cleaned)

    if not patterns:
        print(
            "Error: none of the model's output survived cleanup — every entry was "
            f"under {MIN_PATTERN_LEN} letters once digits and punctuation were "
            "stripped."
        )
        return

    # Per-run scratch beside the hash file, laid out like .spoonman so both
    # halves of the attack are inspectable after a run; removed by cleanup().
    scratch_dir = f"{hcatHashFile}.llm_patterns"
    patterns_path = os.path.join(scratch_dir, "basewords.txt")
    rules_path = os.path.join(scratch_dir, "rules.rule")
    try:
        os.makedirs(scratch_dir, exist_ok=True)
        with open(patterns_path, "w") as f:
            for pattern in patterns:
                f.write(pattern + "\n")
    except OSError as e:
        print(f"Error writing patterns file: {e}")
        return

    discarded = len(raw_patterns) - len(patterns)
    summary = f"Inferred {len(patterns)} pattern basewords -> {patterns_path}"
    if discarded > 0:
        summary += f" ({discarded} discarded during cleanup)"
    print(summary)

    rules, rules_discarded = _llm_pattern_rules(gen_context)
    rule_chain = ""
    if rules:
        try:
            with open(rules_path, "w") as f:
                for rule in rules:
                    f.write(rule + "\n")
        except OSError as e:
            print(f"Error writing rules file: {e}")
        else:
            rule_chain = f"-r {shlex.quote(rules_path)}"
            rule_summary = f"Inferred {len(rules)} hashcat rules -> {rules_path}"
            if rules_discarded > 0:
                rule_summary += f" ({rules_discarded} rejected as invalid)"
            print(rule_summary)
    if not rule_chain:
        # Say how many were rejected: "the model returned nothing" and "the
        # model returned 40 rules and every one was invalid" call for
        # different responses from the operator, and only the count tells
        # them which happened.
        reason = ""
        if rules_discarded > 0:
            reason = f" (all {rules_discarded} returned rules were rejected as invalid)"
        print(
            f"[!] No usable rules were inferred{reason}; running the basewords "
            "unmutated. Re-run to try again, or use the Spoonman Attack for "
            "rules derived mechanically from the same corpus."
        )

    hcatQuickDictionary(
        hcatHashType,
        hcatHashFile,
        rule_chain,
        patterns_path,
        attack_name="LLM Patterns",
    )


# Middle fast Combinator Attack
def hcatMiddleCombinator(hcatHashType, hcatHashFile):
    global hcatProcess
    masks = hcatMiddleCombinatorMasks
    # Added support for multiple character masks
    new_masks = []
    for mask in masks:
        tmp = []
        if len(mask) > 1:
            for character in mask:
                tmp.append(character)
            new_masks.append("$" + "$".join(tmp))
        else:
            new_masks.append("$" + mask)
    masks = new_masks

    try:
        for x in range(len(masks)):
            cmd = [
                hcatBin,
                "-m",
                hcatHashType,
                hcatHashFile,
                "--session",
                generate_session_id(),
                "-o",
                f"{hcatHashFile}.out",
                "-a",
                "1",
                "-j",
                masks[x],
                hcatMiddleBaseList,
                hcatMiddleBaseList,
            ]
            if _should_use_optimized_kernel("hcatMiddleCombinator"):
                _insert_optimized_flag(cmd)
            cmd.extend(shlex.split(hcatTuning))
            _append_potfile_arg(cmd)
            _run_hcat_cmd(
                cmd,
                attack_name="Middle Combinator",
                hash_file=hcatHashFile,
                reraise_interrupt=True,
            )
    except KeyboardInterrupt:
        pass


# Middle thorough Combinator Attack
def hcatThoroughCombinator(hcatHashType, hcatHashFile):
    global hcatProcess
    masks = hcatThoroughCombinatorMasks
    # Added support for multiple character masks
    new_masks = []
    for mask in masks:
        tmp = []
        if len(mask) > 1:
            for character in mask:
                tmp.append(character)
            new_masks.append("$" + "$".join(tmp))
        else:
            new_masks.append("$" + mask)
    masks = new_masks

    cmd = [
        hcatBin,
        "-m",
        hcatHashType,
        hcatHashFile,
        "--session",
        generate_session_id(),
        "-o",
        f"{hcatHashFile}.out",
        "-a",
        "1",
        hcatThoroughBaseList,
        hcatThoroughBaseList,
    ]
    if _should_use_optimized_kernel("hcatThoroughCombinator"):
        _insert_optimized_flag(cmd)
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(cmd)
    _run_hcat_cmd(cmd, attack_name="Thorough Combinator", hash_file=hcatHashFile)

    try:
        for x in range(len(masks)):
            cmd = [
                hcatBin,
                "-m",
                hcatHashType,
                hcatHashFile,
                "--session",
                generate_session_id(),
                "-o",
                f"{hcatHashFile}.out",
                "-a",
                "1",
                "-j",
                masks[x],
                hcatThoroughBaseList,
                hcatThoroughBaseList,
            ]
            if _should_use_optimized_kernel("hcatThoroughCombinator"):
                _insert_optimized_flag(cmd)
            cmd.extend(shlex.split(hcatTuning))
            _append_potfile_arg(cmd)
            _run_hcat_cmd(
                cmd,
                attack_name="Thorough Combinator",
                hash_file=hcatHashFile,
                reraise_interrupt=True,
            )
    except KeyboardInterrupt:
        pass
    try:
        for x in range(len(masks)):
            cmd = [
                hcatBin,
                "-m",
                hcatHashType,
                hcatHashFile,
                "--session",
                generate_session_id(),
                "-o",
                f"{hcatHashFile}.out",
                "-a",
                "1",
                "-k",
                masks[x],
                hcatThoroughBaseList,
                hcatThoroughBaseList,
            ]
            if _should_use_optimized_kernel("hcatThoroughCombinator"):
                _insert_optimized_flag(cmd)
            cmd.extend(shlex.split(hcatTuning))
            _append_potfile_arg(cmd)
            _run_hcat_cmd(
                cmd,
                attack_name="Thorough Combinator",
                hash_file=hcatHashFile,
                reraise_interrupt=True,
            )
    except KeyboardInterrupt:
        pass
    try:
        for x in range(len(masks)):
            cmd = [
                hcatBin,
                "-m",
                hcatHashType,
                hcatHashFile,
                "--session",
                generate_session_id(),
                "-o",
                f"{hcatHashFile}.out",
                "-a",
                "1",
                "-j",
                masks[x],
                "-k",
                masks[x],
                hcatThoroughBaseList,
                hcatThoroughBaseList,
            ]
            if _should_use_optimized_kernel("hcatThoroughCombinator"):
                _insert_optimized_flag(cmd)
            cmd.extend(shlex.split(hcatTuning))
            _append_potfile_arg(cmd)
            _run_hcat_cmd(
                cmd,
                attack_name="Thorough Combinator",
                hash_file=hcatHashFile,
                reraise_interrupt=True,
            )
    except KeyboardInterrupt:
        pass


# Pathwell Mask Brute Force Attack
def hcatPathwellBruteForce(hcatHashType, hcatHashFile):
    global hcatProcess
    cmd = [
        hcatBin,
        "-m",
        hcatHashType,
        hcatHashFile,
        "--session",
        generate_session_id(),
        "-o",
        f"{hcatHashFile}.out",
        "-a",
        "3",
        os.path.join(hate_path, "masks", "pathwell.hcmask"),
    ]
    if _should_use_optimized_kernel("hcatPathwellBruteForce"):
        _insert_optimized_flag(cmd)
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(cmd)
    _run_hcat_cmd(cmd, attack_name="Pathwell Brute Force", hash_file=hcatHashFile)


# Corporate Masks Attack
def hcatCorporateMasks(
    hcatHashType,
    hcatHashFile,
    minLen=CORPORATE_MASK_MIN_LEN,
    maxLen=CORPORATE_MASK_DEFAULT_MAX_LEN,
):
    """Run hashcat with corporate mask files for the given length range.

    Clamps minLen and maxLen to CORPORATE_MASK_MIN_LEN..CORPORATE_MASK_MAX_LEN,
    swapping if reversed. Skips missing mask files and gracefully handles an
    absent mask directory.
    """
    global hcatProcess
    # Clamp and swap if reversed
    minLen = max(CORPORATE_MASK_MIN_LEN, min(minLen, CORPORATE_MASK_MAX_LEN))
    maxLen = max(CORPORATE_MASK_MIN_LEN, min(maxLen, CORPORATE_MASK_MAX_LEN))
    if minLen > maxLen:
        minLen, maxLen = maxLen, minLen

    # Build list of mask files that exist
    mask_files = []
    for n in range(minLen, maxLen + 1):
        mask_path = os.path.join(_corporate_masks_dir, f"corp_{n}.hcmask")
        if os.path.isfile(mask_path):
            mask_files.append((n, mask_path))

    # Handle missing mask directory or no files
    if not mask_files:
        print("[!] No corporate mask files found.")
        print(f"[!] Expected to find corp_*.hcmask files in: {_corporate_masks_dir}")
        print(
            "[!] Run 'make submodules' or "
            "'git submodule update --init Corporate_Masks' to initialize it."
        )
        return

    # Run one hashcat invocation per mask file
    try:
        for n, mask_path in mask_files:
            print(f"\n[*] Corporate Masks Attack (length {n})")
            cmd = [
                hcatBin,
                "-m",
                hcatHashType,
                hcatHashFile,
                "--session",
                generate_session_id(),
                "-o",
                f"{hcatHashFile}.out",
                "-a",
                "3",
                mask_path,
            ]
            if _should_use_optimized_kernel("hcatCorporateMasks"):
                _insert_optimized_flag(cmd)
            cmd.extend(shlex.split(hcatTuning))
            _append_potfile_arg(cmd)
            _run_hcat_cmd(
                cmd,
                attack_name=f"Corporate Masks (len {n})",
                hash_file=hcatHashFile,
                reraise_interrupt=True,
                coverage=_coverage.CoverageSpec(
                    hash_file=hcatHashFile,
                    mask_files=(mask_path,),
                ),
            )
    except KeyboardInterrupt:
        pass


def hcatAdHocMask(
    hcatHashType,
    hcatHashFile,
    mask,
    custom_charsets="",
    increment=False,
    increment_min="",
    increment_max="",
):
    global hcatProcess
    cmd = [
        hcatBin,
        "-m",
        hcatHashType,
        hcatHashFile,
        "--session",
        generate_session_id(),
        "-o",
        f"{hcatHashFile}.out",
        "-a",
        "3",
    ]
    if custom_charsets:
        cmd.extend(shlex.split(custom_charsets))
    if increment:
        # Either bound may be omitted: hashcat then derives it from the mask,
        # which is what "increment over the full keyspace" means.
        cmd.append("--increment")
        if increment_min:
            cmd.append(f"--increment-min={increment_min}")
        if increment_max:
            cmd.append(f"--increment-max={increment_max}")
    cmd.append(mask)
    if _should_use_optimized_kernel("hcatAdHocMask"):
        _insert_optimized_flag(cmd)
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(cmd)
    _run_hcat_cmd(
        cmd,
        attack_name="Ad-hoc Mask",
        hash_file=hcatHashFile,
        coverage=_adhoc_mask_coverage(
            hcatHashFile, mask, custom_charsets, increment, increment_min, increment_max
        ),
    )


def _adhoc_mask_coverage(
    hash_file, mask, custom_charsets, increment, increment_min, increment_max
):
    """Build the coverage spec for hcatAdHocMask.

    ``mask`` is either a literal mask string or a path to a ``.hcmask`` file --
    the menu's option 2 passes a file. The two must not be conflated: a file
    tracked as a literal would be keyed on its *path*, so appending new mask
    lines to it and re-running would look like an exact repeat and be skipped.
    Tracked as a file it is keyed per line, and becomes filterable besides.
    """
    variant = (
        # The increment flag itself has to be in the key. Leaving both bounds
        # blank is the documented way to increment over the mask's full
        # keyspace, so "increment, no bounds" and "no increment" would
        # otherwise produce the same variant while covering different lengths.
        f"charsets:{custom_charsets}|inc:{int(bool(increment))}:"
        f"{increment_min or ''}-{increment_max or ''}"
    )
    if os.path.isfile(mask):
        return _coverage.CoverageSpec(
            hash_file=hash_file, mask_files=(mask,), variant=variant
        )
    return _coverage.CoverageSpec(hash_file=hash_file, masks=(mask,), variant=variant)


def hcatMarkovTrain(source_file, hcatHashFile):
    global hcatProcess
    hcstat2gen_bin = os.path.join(hate_path, "hashcat-utils", "bin", hcatHcstat2genBin)
    hcstat2_path = f"{hcatHashFile}.hcstat2"
    print(f"[*] Generating markov table -> {hcstat2_path}")

    # Verify hcstat2gen.bin exists
    if not os.path.isfile(hcstat2gen_bin):
        print(f"[!] hcstat2gen.bin not found at {hcstat2gen_bin}")
        return False

    # Verify source file is readable
    if not os.path.isfile(source_file):
        print(f"[!] Source file not found: {source_file}")
        return False

    try:
        with (
            _wordlist_path(source_file) as resolved_source,
            open(resolved_source, "rb") as stdin_f,
        ):
            hcatProcess = subprocess.Popen(
                [hcstat2gen_bin, hcstat2_path], stdin=stdin_f, stderr=subprocess.PIPE
            )
            try:
                hcatProcess.wait(timeout=300)
                if hcatProcess.returncode != 0:
                    _, stderr_data = hcatProcess.communicate()
                    err_msg = (
                        stderr_data.decode("utf-8", errors="replace")
                        if stderr_data
                        else "Unknown error"
                    )
                    print(
                        f"[!] hcstat2gen.bin failed with code {hcatProcess.returncode}: {err_msg}"
                    )
                    return False
            except subprocess.TimeoutExpired:
                print("[!] hcstat2gen.bin timed out after 300 seconds")
                hcatProcess.kill()
                return False
            except KeyboardInterrupt:
                print("Killing PID {0}...".format(str(hcatProcess.pid)))
                hcatProcess.kill()
                return False
    except Exception as e:
        print(f"[!] Failed to run hcstat2gen.bin: {e}")
        return False

    # Verify output file was created
    if not os.path.isfile(hcstat2_path):
        print(f"[!] Output file not created: {hcstat2_path}")
        return False
    if os.path.getsize(hcstat2_path) == 0:
        print(f"[!] Output file is empty: {hcstat2_path}")
        return False

    # Compress the hcstat2 file with LZMA2 (hashcat requires compressed format)
    try:
        with open(hcstat2_path, "rb") as f_in:
            uncompressed_data = f_in.read()
        # Use raw LZMA2 stream (not XZ container) - hashcat decodes with Lzma2Decode()
        compressed_data = lzma.compress(
            uncompressed_data,
            format=lzma.FORMAT_RAW,
            filters=[{"id": lzma.FILTER_LZMA2, "preset": 9}],
        )
        with open(hcstat2_path, "wb") as f_out:
            f_out.write(compressed_data)
    except Exception as e:
        print(f"[!] Failed to compress hcstat2 file: {e}")
        return False

    return True


def hcatMarkovBruteForce(hcatHashType, hcatHashFile, hcatMinLen, hcatMaxLen):
    global hcatProcess
    hcstat2_path = f"{hcatHashFile}.hcstat2"
    cmd = [
        hcatBin,
        "-m",
        hcatHashType,
        hcatHashFile,
        "--session",
        generate_session_id(),
        "-o",
        f"{hcatHashFile}.out",
        "--markov-hcstat2",
        hcstat2_path,
        "--increment",
        f"--increment-min={hcatMinLen}",
        f"--increment-max={hcatMaxLen}",
        "-a",
        "3",
        "?a?a?a?a?a?a?a?a?a?a?a?a?a?a",
    ]
    if _should_use_optimized_kernel("hcatMarkovBruteForce"):
        _insert_optimized_flag(cmd)
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(cmd)
    _run_hcat_cmd(cmd, attack_name="Markov Brute Force", hash_file=hcatHashFile)


# Combipow Passphrase Attack
hcatCombipowCount = 0


def hcatCombipow(hcatHashType, hcatHashFile, wordlist, use_space_sep=True):
    global hcatProcess, hcatCombipowCount
    hcatCombipowCount += 1
    combipow_bin = os.path.join(hate_path, "hashcat-utils/bin/combipow.bin")

    with _wordlist_path(wordlist) as wordlist_path:
        generator_cmd = [combipow_bin]
        if use_space_sep:
            generator_cmd.append("-s")
        generator_cmd.append(wordlist_path)
        session_name = re.sub(
            r"[^a-zA-Z0-9_-]", "_", os.path.splitext(os.path.basename(hcatHashFile))[0]
        )
        hashcat_cmd = [
            hcatBin,
            "--session",
            session_name,
            "-m",
            hcatHashType,
            hcatHashFile,
            "-o",
            f"{hcatHashFile}.out",
        ]
        if _should_use_optimized_kernel("hcatCombipow"):
            _insert_optimized_flag(hashcat_cmd)
        hashcat_cmd.extend(shlex.split(hcatTuning))
        _append_potfile_arg(hashcat_cmd)
        generator_proc = subprocess.Popen(generator_cmd, stdout=subprocess.PIPE)
        _run_hcat_cmd(
            hashcat_cmd,
            attack_name="Combipow",
            hash_file=hcatHashFile,
            stdin=generator_proc.stdout,
            companion_procs=[generator_proc],
        )
        if generator_proc.stdout:
            generator_proc.stdout.close()


# PRINCE Attack
def hcatPrince(hcatHashType, hcatHashFile, attack_name="PRINCE"):
    global hcatProcess
    prince_rules_dir = os.path.join(hate_path, "princeprocessor", "rules")
    prince_rule = get_rule_path("prince_optimized.rule", fallback_dir=prince_rules_dir)
    prince_base = (
        hcatPrinceBaseList[0]
        if isinstance(hcatPrinceBaseList, list)
        else hcatPrinceBaseList
    )
    if not prince_base or not os.path.isfile(prince_base):
        print(f"Prince base list not found: {prince_base}")
        return
    prince_cmd = [
        os.path.join(hate_path, "princeprocessor", hcatPrinceBin),
        "--case-permute",
        "--elem-cnt-min=1",
        "--elem-cnt-max=16",
        "-c",
    ]
    hashcat_cmd = [
        hcatBin,
        "-m",
        hcatHashType,
        hcatHashFile,
        "--session",
        generate_session_id(),
        "-o",
        f"{hcatHashFile}.out",
        "-r",
        prince_rule,
    ]
    if _should_use_optimized_kernel("hcatPrince"):
        _insert_optimized_flag(hashcat_cmd)
    hashcat_cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(hashcat_cmd)
    hashcat_cmd = _add_debug_mode_for_rules(hashcat_cmd)
    with (
        _wordlist_path(prince_base) as resolved_base,
        open(resolved_base, "rb") as base,
    ):
        prince_proc = subprocess.Popen(prince_cmd, stdin=base, stdout=subprocess.PIPE)
        _run_hcat_cmd(
            hashcat_cmd,
            attack_name=attack_name,
            hash_file=hcatHashFile,
            stdin=prince_proc.stdout,
            companion_procs=[prince_proc],
        )
        if prince_proc.stdout:
            prince_proc.stdout.close()


def _resolve_pcfg_ruleset_dir(pcfg_root, ruleset_name):
    """Resolve ruleset_name against pcfg_root/Rules case-insensitively.

    Older config.json files may have "DEFAULT" backfilled to disk from
    before the default changed to "Default" (see #148) — match whatever
    casing exists on disk rather than requiring an exact match.

    ``os.path.isdir()`` alone can't be used for the fast path: on
    case-insensitive filesystems (macOS/Windows default) it returns True
    for a wrong-cased path too, which would make callers report the
    casing they asked for instead of what's actually on disk.
    """
    exact = os.path.join(pcfg_root, "Rules", ruleset_name)
    rules_root = os.path.join(pcfg_root, "Rules")
    if os.path.isdir(rules_root):
        for entry in os.listdir(rules_root):
            if entry == ruleset_name:
                return os.path.join(rules_root, entry)
        for entry in os.listdir(rules_root):
            if entry.lower() == ruleset_name.lower():
                return os.path.join(rules_root, entry)
    return exact


def hcatPCFG(hcatHashType, hcatHashFile):
    """Mode A: pipe pcfg_guesser.py output into hashcat in stdin mode."""
    pcfg_guesser_script = os.path.join(hate_path, "pcfg_cracker", "pcfg_guesser.py")
    if not os.path.isfile(pcfg_guesser_script):
        print(f"pcfg_guesser.py not found at {pcfg_guesser_script}")
        return
    pcfg_root = os.path.join(hate_path, "pcfg_cracker")
    resolved_ruleset_dir = _resolve_pcfg_ruleset_dir(pcfg_root, pcfgRuleset)
    resolved_ruleset_name = os.path.basename(resolved_ruleset_dir)
    pcfg_cmd = [
        sys.executable,
        pcfg_guesser_script,
        "--rule",
        resolved_ruleset_name,
        "--limit",
        str(pcfgMaxCandidates),
    ]
    hashcat_cmd = [
        hcatBin,
        "-m",
        hcatHashType,
        hcatHashFile,
        "--session",
        generate_session_id(),
        "-o",
        f"{hcatHashFile}.out",
    ]
    if _should_use_optimized_kernel("hcatPCFG"):
        _insert_optimized_flag(hashcat_cmd)
    hashcat_cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(hashcat_cmd)
    pcfg_proc = subprocess.Popen(
        pcfg_cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE
    )
    _run_hcat_cmd(
        hashcat_cmd,
        attack_name="PCFG",
        hash_file=hcatHashFile,
        stdin=pcfg_proc.stdout,
        companion_procs=[pcfg_proc],
    )
    if pcfg_proc.stdout:
        pcfg_proc.stdout.close()
    if pcfg_proc.stdin:
        pcfg_proc.stdin.close()


def hcatPrinceLing(hcatHashType, hcatHashFile):
    """Mode B: prince_ling generates a wordlist (with cache+staleness check),
    then we delegate to the existing hcatPrince attack with hcatPrinceBaseList
    temporarily rebound to the cached wordlist.
    """
    global hcatPrinceBaseList
    pcfg_root = os.path.join(hate_path, "pcfg_cracker")
    prince_ling_script = os.path.join(pcfg_root, "prince_ling.py")
    ruleset_dir = _resolve_pcfg_ruleset_dir(pcfg_root, pcfgRuleset)
    if not os.path.isfile(prince_ling_script):
        print(f"prince_ling.py not found at {prince_ling_script}")
        return
    if not os.path.isdir(ruleset_dir):
        print(f"PCFG ruleset not found: {ruleset_dir}")
        return
    resolved_ruleset_name = os.path.basename(ruleset_dir)

    cache_dir = (
        hcatOptimizedWordlists
        if isinstance(hcatOptimizedWordlists, str)
        else str(hcatOptimizedWordlists)
    )
    os.makedirs(cache_dir, exist_ok=True)
    # Both inputs that decide the file's contents are in its name: the ruleset
    # the candidates come from, and the candidate budget passed to
    # prince_ling.py as --size. Leaving the budget out made
    # pcfgPrinceLingMaxCandidates silently inert once a cache existed -- raising
    # it reused the smaller wordlist generated under the old value, with no
    # indication the new setting had not taken effect. Keying on it instead lets
    # each size keep its own cache.
    cache_path = os.path.join(
        cache_dir,
        f"pcfg_prince_ling_{resolved_ruleset_name}_{pcfgPrinceLingMaxCandidates}.txt",
    )
    tmp_path = cache_path + ".tmp"

    # Staleness check: regenerate iff ruleset dir mtime > cache mtime (strict)
    needs_regen = True
    if os.path.isfile(cache_path):
        ruleset_mtime = os.path.getmtime(ruleset_dir)
        cache_mtime = os.path.getmtime(cache_path)
        if ruleset_mtime <= cache_mtime:
            needs_regen = False

    if needs_regen:
        print(f"[*] Generating prince_ling wordlist -> {cache_path}")
        cmd = [
            sys.executable,
            prince_ling_script,
            "--rule",
            resolved_ruleset_name,
            "--output",
            tmp_path,
            "--size",
            str(pcfgPrinceLingMaxCandidates),
        ]
        try:
            subprocess.run(cmd, check=True)
            os.replace(tmp_path, cache_path)
        except (subprocess.CalledProcessError, KeyboardInterrupt, OSError) as e:
            # Clean up partial tmp file
            if os.path.isfile(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
            print(f"prince_ling generation failed: {e}")
            return

    # Delegate to existing PRINCE attack with rebound base list. The
    # ``attack_name`` override keeps notifications matched to the
    # "PRINCE-LING" prompt the user consented to (see issue #110).
    original_base = hcatPrinceBaseList
    hcatPrinceBaseList = [cache_path]
    try:
        hcatPrince(hcatHashType, hcatHashFile, attack_name="PRINCE-LING")
    finally:
        hcatPrinceBaseList = original_base


# Records which corpus a <hash file>.spoonman cache directory was derived from.
# The cache directory is named after the *hash* file, so without this the corpus
# never entered the cache key at all: deriving from one corpus and then invoking
# the attack with a second one whose mtime happened to be older reused the
# first corpus's basewords and rules, silently.
SPOONMAN_PROVENANCE_FILE = "corpus.json"
SPOONMAN_PROVENANCE_FIELDS = ("corpus", "size", "mtime")


def _spoonman_provenance(corpus):
    """Describe *corpus* for the cache key: absolute path, size, and mtime.

    Returns None if it cannot be stat'd, which the caller treats as "cannot
    prove the cache matches" and therefore re-derives.
    """
    try:
        stat = os.stat(corpus)
    except OSError:
        return None
    return {
        "corpus": os.path.abspath(corpus),
        "size": stat.st_size,
        "mtime": stat.st_mtime,
    }


def _read_spoonman_provenance(path):
    """Load a provenance file written by a previous run, or None.

    Missing, empty, unreadable, malformed, and written-by-an-older-version
    (any expected field absent) all come back as None rather than raising: a
    cache we cannot vouch for is a cache miss, not an error.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            recorded = json.load(handle)
    except (OSError, ValueError):
        return None
    if not isinstance(recorded, dict):
        return None
    if any(field not in recorded for field in SPOONMAN_PROVENANCE_FIELDS):
        return None
    return recorded


def _write_spoonman_provenance(path, provenance):
    """Record *provenance* beside the derived output. Best effort.

    A failure here only costs the next run its cache, so it must not abort an
    attack whose expensive derivation has already succeeded.
    """
    if provenance is None:
        return
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(provenance, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except OSError as e:
        print(f"[!] Could not record corpus provenance in {path}: {e}")


def _invalidate_spoonman_provenance(path):
    """Remove the provenance record, marking the cache directory invalid.

    Called immediately before a derivation starts, which is what makes the
    record a validity marker rather than a stale label. ``rulegen.generate()``
    writes basewords.txt in place and non-atomically, and the derivation is a
    two-pass O(corpus) operation an operator will plausibly Ctrl-C -- and
    KeyboardInterrupt is deliberately not caught here, so it propagates. An
    interrupt after basewords.txt was rewritten but before the new record was
    written would otherwise leave the *previous* corpus's record beside the
    *new* corpus's basewords: the next run against the previous corpus would
    then match the record, pass the mtime check, announce a cache hit and crack
    with the wrong corpus's basewords -- the exact failure this record exists
    to prevent. With no record, a half-finished cache directory is a miss.
    """
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError as e:
        # Cannot invalidate, so say so: a reused stale record is the one
        # outcome worth being loud about.
        print(f"[!] Could not invalidate stale corpus provenance {path}: {e}")


def _spoonman_cache_mismatch(recorded, current):
    """Explain why *recorded* does not describe *current*, or None if it does."""
    if current is None:
        return "the corpus could not be read"
    if recorded is None:
        return "its provenance record is missing or unreadable"
    if recorded.get("corpus") != current["corpus"]:
        return f"it was derived from a different corpus ({recorded.get('corpus')})"
    if (
        recorded.get("size") != current["size"]
        or recorded.get("mtime") != current["mtime"]
    ):
        return "the corpus has changed since it was derived"
    return None


# hashcat's optimized kernels (-O) impose a maximum candidate length, and
# anything over it is dropped without a word. 31 is the mode-0 figure, verified
# against hashcat v7.1.2: with -O a 31-character plaintext cracks, a
# 32-character one does not, and hashcat prints no warning and exits cleanly.
# The real cap is mode-dependent, so this single number is a heuristic used
# only to warn -- nothing filters candidates or changes an attack's behaviour
# based on it, and no attempt is made to derive it per hash mode.
OPTIMIZED_KERNEL_MAX_PLAIN_LENGTH = 31

# Above this size, say that the baseword scan below is happening. The scan
# streams, so it is cheap per byte, but a corpus-sized baseword list still
# takes long enough that an unannounced pause before hashcat starts looks like
# a hang.
SPOONMAN_BASEWORD_SCAN_NOTICE_BYTES = 64 * 1024 * 1024


def _count_over_long_basewords(path, cap=OPTIMIZED_KERNEL_MAX_PLAIN_LENGTH):
    """Count lines in *path* longer than *cap* characters; None if unreadable.

    Streams the file one line at a time: a Spoonman baseword list is derived
    from the whole corpus and can be nearly as large, so it must not be read
    into memory just to print a warning.
    """
    try:
        with open(path, encoding="latin-1") as handle:
            return sum(1 for line in handle if len(line.rstrip("\r\n")) > cap)
    except OSError:
        return None


def _warn_optimized_kernel_length_loss(basewords_path):
    """Report how many basewords ``-O`` will silently drop, if ``-O`` is in play.

    Spoonman's baseword list holds whole literal passwords -- every letterless
    or unrepresentable corpus entry becomes its own baseword -- so a corpus with
    long entries loses them outright, with nothing in hashcat's output to say
    so. Informational only: it does not prompt and does not change the run.

    Scope is the derived baseword list only -- the capped file when a cap is in
    effect, the uncapped one otherwise. Extra wordlists are **not** counted:
    this runs before _spoonman_wordlists builds the operand list, and an extra
    can be a directory, so counting them would mean walking arbitrary
    operator-supplied trees. Over-long entries in an extra wordlist are dropped
    by ``-O`` just the same and go unreported, which is one more reason the
    printed count is worded as a floor.
    """
    if not _should_use_optimized_kernel("hcatQuickDictionary"):
        return
    try:
        size = os.path.getsize(basewords_path)
    except OSError:
        size = 0
    if size >= SPOONMAN_BASEWORD_SCAN_NOTICE_BYTES:
        print(
            f"[*] Scanning {size // (1024 * 1024)} MB of basewords for entries "
            "the optimized kernel would drop..."
        )
    over_long = _count_over_long_basewords(basewords_path)
    if not over_long:
        return
    # "At least", and 31 named as the mode-0 figure: the count is a floor in two
    # directions. Spoonman runs at any hash mode and the real -O cap varies with
    # the mode, and a rule that appends characters can carry a baseword that
    # fits here past the cap. An operator must not read this as an exact loss.
    print(
        f"[!] At least {over_long} baseword(s) exceed "
        f"{OPTIMIZED_KERNEL_MAX_PLAIN_LENGTH} characters and will be dropped "
        "silently by hashcat's optimized kernel (-O)."
    )
    print(
        f"    {OPTIMIZED_KERNEL_MAX_PLAIN_LENGTH} is the cap verified for mode 0; "
        "the real cap varies by hash mode, and a rule that appends characters "
        "can push a shorter baseword over it. Re-run with "
        "--no-optimized-kernel (--no-optimize) to keep them."
    )


def _same_path(left, right):
    """Do *left* and *right* resolve to the same filesystem object?

    realpath rather than a string comparison: the two arrive from different
    places (one typed or picked by the operator, one enumerated from a
    directory listing), so a symlink, a ``./`` prefix, or a trailing slash is
    ordinary rather than exotic.
    """
    try:
        return os.path.realpath(left) == os.path.realpath(right)
    except OSError:
        return False


def _path_contains(container, target):
    """Does directory *container* hold *target* somewhere beneath it?

    _same_path alone is depth-blind, and the extras it screens are enumerated
    with list_wordlist_entries, which deliberately includes directories so
    hashcat walks them. A corpus one level inside an offered directory is
    therefore the expected shape, not a corner case -- a wordlist collection
    with the corpus unpacked into its own subdirectory beside the others.

    Both sides go through realpath so a symlinked directory whose target holds
    the corpus is caught too. The separator is appended before the prefix test
    because a bare string prefix would also match a sibling whose name merely
    starts the same way -- ``lists`` would "contain" ``lists2/corpus.txt`` --
    and it is what makes a non-directory *container* answer False on its own,
    since nothing resolves to a path beneath a plain file.
    """
    try:
        container_real = os.path.realpath(container)
        target_real = os.path.realpath(target)
    except OSError:
        return False
    return target_real.startswith(container_real.rstrip(os.sep) + os.sep)


def _spoonman_wordlists(basewords_path, extra_wordlists, corpus=None):
    """Build the dictionary list for the run: derived basewords, then the extras.

    hashcat reads straight-mode dictionaries sequentially, so the order is the
    order they are tried in and the derived basewords -- the corpus-specific
    part, and the only part the rules were measured against -- go first.
    A path that does not exist is named and skipped rather than handed to
    hashcat, which would abort the whole run over one bad entry; if that leaves
    nothing but the derived basewords, the attack proceeds with those.

    *corpus* is skipped if it turns up among the extras, which is a normal
    accident rather than an exotic one: the corpus prompt's base directory is
    hcatWordlists, so a corpus picked there is inside the very directory the
    "derived basewords + configured wordlists" option enumerates. Feeding it
    back in is pure waste -- its lines are ``<digest>:<plaintext>`` records,
    which cannot be candidates -- and on a large corpus it is the dominant cost
    of the run, with nothing on screen to say so.

    An extra that is a **directory containing** the corpus is skipped for the
    same reason: hashcat walks a directory operand, so handing it one that holds
    the corpus feeds the corpus in just as surely as naming the file. The extras
    are enumerated with list_wordlist_entries, which includes directories on
    purpose, so this is the common spelling rather than the rare one. The whole
    directory goes, not just the corpus inside it -- an operand is all-or-nothing
    to hashcat, and there is no way to hand it a directory minus one file.
    """
    wordlists = [basewords_path]
    for extra in extra_wordlists or []:
        if not os.path.exists(extra):
            print(f"[!] Skipping wordlist (not found): {extra}")
            continue
        if corpus is not None and _same_path(extra, corpus):
            print(
                f"[!] Skipping wordlist (it is the corpus this attack derived "
                f"from): {extra}"
            )
            continue
        if corpus is not None and _path_contains(extra, corpus):
            print(
                f"[!] Skipping wordlist (it is a directory containing the corpus "
                f"this attack derived from): {extra}"
            )
            continue
        wordlists.append(extra)
    return wordlists


def _spoonman_capped_basewords(full_path, capped_path, cap):
    """Materialize the *cap* most frequent basewords from a cached full list.

    A cap is operator-chosen, so a warm cache cannot be expected to already
    hold ``basewords.top{N}.txt`` for the N asked for -- and re-deriving to get
    one would mean a two-pass read of the whole corpus, hours on a corpus of
    the size rulegen.py's memory bound is written for. It is not needed:
    rulegen.generate() ranks the basewords once and writes every capped file as
    a **prefix** of basewords.txt, so the first *cap* lines of the cached full
    list are byte-identical to what a derivation would have produced.

    Deliberately does not touch the provenance record. Truncating a cached list
    is not a derivation, so the Task 5 validity marker stays exactly as the
    derivation that wrote basewords.txt left it.

    Streams, because a baseword list can approach corpus size. Returns the
    capped path, or *full_path* if it could not be written -- an unwritable
    cache costs the cap, which is a keyspace preference, and must not cost the
    attack.
    """
    try:
        # Older than the full list means it belongs to a previous derivation
        # (a capped file survives one, since generate() only writes the caps it
        # was asked for), so it would be a stale prefix of a corpus that is no
        # longer there.
        # Strictly newer, deliberately: on a coarse-mtime filesystem (HFS+,
        # FAT, some NFS) a derivation landing in the same tick as an earlier
        # capped write would compare equal, and reusing on equality would serve
        # that stale prefix. The cost of being wrong the other way is a rebuild
        # that produces byte-identical output from a file already on disk.
        if os.path.isfile(capped_path) and os.path.getmtime(
            capped_path
        ) > os.path.getmtime(full_path):
            return capped_path
    except OSError:
        pass
    try:
        with (
            open(full_path, encoding="latin-1") as src,
            open(capped_path, "w", encoding="latin-1") as dst,
        ):
            for index, line in enumerate(src):
                if index >= cap:
                    break
                dst.write(line)
    except OSError as e:
        print(f"[!] Could not write the capped baseword list {capped_path}: {e}")
        print("    Continuing with the full derived baseword list.")
        return full_path
    print(f"[*] Capped the cached baseword list to its {cap} most frequent entries")
    return capped_path


def hcatSpoonman(
    hcatHashType,
    hcatHashFile,
    corpus,
    coverage=None,
    extra_wordlists=None,
    baseword_cap=None,
):
    """Spoonman Attack: derive basewords + rules from *corpus*, then crack with them.

    ``coverage`` picks which generated rule file to run: ``None`` for the full
    set, or an int matching one of the capped files (e.g. ``95`` for
    rules.top95.rule). The full set only reconstructs 100% of the corpus while
    rulegen.generate()'s Counter pruning stays out of the way; once pruning
    fires, coverage is relative to the retained keys instead. See
    hate_crack/rulegen.py and issue #169.

    ``extra_wordlists`` are additional dictionaries to cross the derived rules
    against, appended after the derived basewords. This is the knob that
    matters: measured against unseen passwords, the derived rule set saturates
    almost immediately while most misses are a missing *baseword*.

    ``baseword_cap`` runs ``basewords.top{N}.txt`` instead of the full derived
    list. It trades reach for keyspace and is not an accuracy win. A cap does
    **not** invalidate the cache: N is operator-chosen, so a warm cache will
    usually not hold the file for it, and it is truncated out of the cached
    full list instead of re-derived (see _spoonman_capped_basewords). Zero or
    None means no cap. Like ``coverage``, it is relative to what generate()
    retained: once the Counter pruning fires, a cap is the top N of the
    *retained* basewords rather than of every baseword the corpus held.
    """
    if not os.path.isfile(corpus):
        print(f"Error: corpus not found: {corpus}")
        return

    # Derived basewords/rules are per-run scratch, so they live beside the hash
    # file like the other ephemeral wordlists (.expanded, .combined) and are
    # removed by cleanup().
    cache_dir = f"{hcatHashFile}.spoonman"
    # Deriving is O(corpus), so reuse a previous run's output unless the corpus
    # has changed since. The cache directory is keyed on the hash file, so the
    # mtime comparison alone (as in hcatPrinceLing) is not enough here: a
    # different corpus with an older mtime would pass it. The provenance file
    # records which corpus the directory actually holds.
    # Cache validity is decided on the *uncapped* list, never on a capped one:
    # a cap is a truncation of that list, not a separate derivation.
    full_basewords_path = os.path.join(cache_dir, "basewords.txt")
    basewords_path = full_basewords_path
    rules_path = os.path.join(cache_dir, "rules.full.rule")
    if coverage is not None:
        rules_path = os.path.join(cache_dir, f"rules.top{coverage}.rule")
    provenance_path = os.path.join(cache_dir, SPOONMAN_PROVENANCE_FILE)
    current_provenance = _spoonman_provenance(corpus)
    cached = os.path.isfile(full_basewords_path) and os.path.isfile(rules_path)
    mismatch = _spoonman_cache_mismatch(
        _read_spoonman_provenance(provenance_path), current_provenance
    )
    fresh = cached and os.path.getmtime(corpus) <= os.path.getmtime(full_basewords_path)
    if fresh and mismatch is None:
        print(f"[*] Reusing derived basewords and rules in {cache_dir}")
        if baseword_cap:
            basewords_path = _spoonman_capped_basewords(
                full_basewords_path,
                os.path.join(cache_dir, f"basewords.top{baseword_cap}.txt"),
                baseword_cap,
            )
    else:
        if cached and mismatch is not None:
            # Say why an expensive derivation is running again over what looks
            # from the outside like a warm cache.
            print(f"[*] Ignoring the cache in {cache_dir}: {mismatch}")
        print(f"[*] Deriving basewords and rules from {corpus}")
        # Drop the old record first: from here until the new one is written the
        # cache directory is not to be trusted, including if this is
        # interrupted. See _invalidate_spoonman_provenance.
        _invalidate_spoonman_provenance(provenance_path)
        try:
            with _wordlist_path(corpus) as resolved_corpus:
                result = _rulegen.generate(
                    resolved_corpus,
                    cache_dir,
                    leet_restore=True,
                    baseword_caps=(baseword_cap,) if baseword_cap else (),
                )
        except (OSError, ValueError) as e:
            print(f"Rule derivation failed: {e}")
            return
        basewords_path = result["basewords"]
        rules_path = result["rules"]
        if coverage is not None:
            rules_path = result["capped_rules"].get(coverage, rules_path)
        if baseword_cap:
            basewords_path = result["capped_basewords"].get(
                baseword_cap, basewords_path
            )
        _write_spoonman_provenance(provenance_path, current_provenance)
    print(f"[*] Basewords: {basewords_path}")
    print(f"[*] Rules:     {rules_path}")
    print(f"[*] Coverage:  {os.path.join(cache_dir, 'coverage.txt')}")
    # Scan the list actually being run: with a cap in effect that is the capped
    # file, and its over-long count is not the uncapped file's.
    _warn_optimized_kernel_length_loss(basewords_path)

    wordlists = _spoonman_wordlists(basewords_path, extra_wordlists, corpus=corpus)
    for extra in wordlists[1:]:
        print(f"[*] Also:      {extra}")

    hcatQuickDictionary(
        hcatHashType,
        hcatHashFile,
        f"-r {shlex.quote(rules_path)}",
        wordlists,
        attack_name="Spoonman",
    )


# Rule-ranking metrics offered by the Rosetta attack, mapped to the
# DebugAnalyzer accessor that implements each one and a label for the summary.
ROSETTA_RULE_METRICS = {
    "frequency": ("get_top_rules_by_frequency", "applications"),
    "basewords": ("get_top_rules_by_unique_basewords", "unique basewords"),
    "candidates": ("get_top_rules_by_unique_candidates", "unique candidates"),
}


def rosetta_debug_logs(directory=None):
    """Return hashcat debug logs under *directory*, newest first.

    Defaults to hcatDebugLogPath, which is where _add_debug_mode_for_rules
    parks the --debug-mode 5 output of every rule-based attack, so a normal
    hate_crack session accumulates these without the operator doing anything.

    Zero-byte logs are skipped. hashcat creates the debug file up front but only
    writes on a crack, so a rule-based attack that cracks nothing leaves an empty
    one behind. They carry no basewords or rules for Rosetta to mine, and the
    picker only shows the newest 20 entries, so leaving them in would let dead
    files crowd out logs that still have something in them.
    """
    directory = directory or hcatDebugLogPath
    if not os.path.isdir(directory):
        return []
    found = []
    for name in sorted(os.listdir(directory)):
        path = os.path.join(directory, name)
        try:
            if os.path.isfile(path) and os.path.getsize(path) > 0:
                found.append(path)
        except OSError:
            # Rotated or removed between listdir and stat; not worth aborting.
            continue
    return sorted(found, key=os.path.getmtime, reverse=True)


def rosetta_derive(
    debug_files,
    out_dir,
    metric="frequency",
    top_rules=None,
    top_basewords=None,
):
    """Derive a baseword list and rule file from hashcat debug logs.

    HashcatRosetta parses mode 5 (the current writer) and mode 4 (logs
    predating the switch) natively, detecting the format per file. Every line
    records a candidate that actually cracked a hash, so the basewords and rules
    recovered here are known-productive against this target population. ``top_rules``/``top_basewords`` of None or
    0 mean "keep everything".

    Returns a dict with the two output paths plus the counts behind them.
    Raises RuntimeError if HashcatRosetta is missing and ValueError if the logs
    yield nothing usable.
    """
    if DebugAnalyzer is None:
        raise RuntimeError(rosetta_unavailable_reason())
    if metric not in ROSETTA_RULE_METRICS:
        raise ValueError(f"unknown rule metric: {metric}")

    # Zero-byte files are tolerated (rosetta_debug_logs() already excludes them
    # from the picker, but direct callers may not have filtered). A capture
    # spanning a --debug-mode switch mixes mode-4 and mode-5 files, which is
    # why each one is parsed on its own via analyze_debug_files() rather than
    # merged into one line list first -- format/mode detection samples the
    # start of whatever it's given, so a merged batch lets one file's sample
    # decide the mode for both and silently drops the other file's lines.
    non_empty_files = [path for path in debug_files if os.path.getsize(path) > 0]
    if not non_empty_files:
        raise ValueError("the selected debug logs are empty")

    analyzer = DebugAnalyzer()
    try:
        analyzer.analyze_debug_files(non_empty_files)
    except ValueError as e:
        # analyze_debug_files() raises per-file as soon as one file yields no
        # entries, so a merged batch can never come back with entries but
        # empty rule/baseword stats -- this is the only "nothing usable" case.
        raise ValueError(
            "no hashcat debug entries found. Expected lines of the form "
            "'baseword:rule:candidate' (--debug-mode 4) or "
            "'baseword:rule:candidate:wordlist' (--debug-mode 5)"
        ) from e

    getter = ROSETTA_RULE_METRICS[metric][0]
    rule_limit = top_rules or len(analyzer.rule_stats)
    rules = [rule for rule, _score in getattr(analyzer, getter)(rule_limit)]
    baseword_limit = top_basewords or len(analyzer.baseword_stats)
    basewords = [
        word for word, _count in analyzer.get_top_basewords_by_frequency(baseword_limit)
    ]

    os.makedirs(out_dir, exist_ok=True)
    basewords_path = os.path.join(out_dir, "basewords.txt")
    rules_path = os.path.join(out_dir, "rules.rule")
    with open(basewords_path, "w", encoding="utf-8") as baseword_file:
        baseword_file.writelines(f"{word}\n" for word in basewords)
    with open(rules_path, "w", encoding="utf-8") as rule_file:
        rule_file.writelines(f"{rule}\n" for rule in rules)

    return {
        "basewords": basewords_path,
        "rules": rules_path,
        "baseword_count": len(basewords),
        "rule_count": len(rules),
        "total_basewords": len(analyzer.baseword_stats),
        "total_rules": len(analyzer.rule_stats),
        "entries": len(analyzer.entries),
    }


def hcatRosetta(
    hcatHashType,
    hcatHashFile,
    debug_files,
    metric="frequency",
    top_rules=None,
    top_basewords=None,
):
    """Rosetta Attack: replay the basewords and rules that already cracked.

    Reads hashcat --debug-mode 5 logs, keeps the winning basewords and the
    highest-ranked winning rules, and runs their full cross product. The value
    is in that cross product rather than in the pairs themselves: a pair that
    appears in a log already cracked its hash, but a rule that worked on one
    baseword has usually never been tried against the others.
    """
    if not debug_files:
        print("Error: no debug logs selected.")
        return
    missing = [path for path in debug_files if not os.path.isfile(path)]
    if missing:
        print(f"Error: debug log not found: {missing[0]}")
        return

    # Per-run scratch beside the hash file, laid out like .spoonman so both
    # are removed by cleanup().
    out_dir = f"{hcatHashFile}.rosetta"
    print(f"[*] Analyzing {len(debug_files)} debug log(s) with HashcatRosetta")
    try:
        derived = rosetta_derive(
            debug_files,
            out_dir,
            metric=metric,
            top_rules=top_rules,
            top_basewords=top_basewords,
        )
    except (OSError, ValueError, RuntimeError) as e:
        print(f"Rosetta derivation failed: {e}")
        return

    print(f"[*] Debug entries:  {derived['entries']}")
    print(
        f"[*] Basewords:      {derived['baseword_count']}"
        f" of {derived['total_basewords']} -> {derived['basewords']}"
    )
    print(
        f"[*] Rules ({metric}): {derived['rule_count']} of {derived['total_rules']}"
        f" -> {derived['rules']}"
    )
    print(
        f"[*] Keyspace:       {derived['baseword_count'] * derived['rule_count']} candidates"
    )

    hcatQuickDictionary(
        hcatHashType,
        hcatHashFile,
        f"-r {shlex.quote(derived['rules'])}",
        derived["basewords"],
        attack_name="Rosetta",
    )


def hcatPermute(hcatHashType, hcatHashFile, wordlist):
    global hcatProcess, hcatPermuteCount
    permute_path = os.path.join(hate_path, "hashcat-utils", "bin", "permute.bin")
    if not os.path.isfile(permute_path):
        print(f"Error: permute.bin not found: {permute_path}")
        return
    if not os.path.isfile(wordlist):
        print(f"Error: wordlist not found: {wordlist}")
        return
    hashcat_cmd = [
        hcatBin,
        "-m",
        hcatHashType,
        hcatHashFile,
        "--session",
        generate_session_id(),
        "-o",
        f"{hcatHashFile}.out",
    ]
    if _should_use_optimized_kernel("hcatPermute"):
        _insert_optimized_flag(hashcat_cmd)
    hashcat_cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(hashcat_cmd)
    with (
        _wordlist_path(wordlist) as resolved_wordlist,
        open(resolved_wordlist, "rb") as wl_file,
    ):
        permute_proc = subprocess.Popen(
            [permute_path], stdin=wl_file, stdout=subprocess.PIPE
        )
        _run_hcat_cmd(
            hashcat_cmd,
            attack_name="Permute",
            hash_file=hcatHashFile,
            stdin=permute_proc.stdout,
            companion_procs=[permute_proc],
        )
        if permute_proc.stdout:
            permute_proc.stdout.close()
    hcatPermuteCount = lineCount(f"{hcatHashFile}.out") - hcatHashCracked


# OMEN model directory - writable location for trained model files.
# The binaries live in {hate_path}/omen/ (possibly read-only after install),
# but model output (createConfig, *.level) goes to ~/.hate_crack/omen/.
def _omen_model_dir():
    model_dir = os.path.join(os.path.expanduser("~"), ".hate_crack", "omen")
    os.makedirs(model_dir, exist_ok=True)
    return model_dir


_OMEN_REQUIRED_FILES = ["createConfig", "CP.level", "IP.level", "EP.level", "LN.level"]


def _omen_model_is_valid(model_dir):
    """Return True if all required OMEN model files exist and are non-empty."""
    if not os.path.isdir(model_dir):
        return False
    for name in _OMEN_REQUIRED_FILES:
        path = os.path.join(model_dir, name)
        if not os.path.isfile(path) or os.path.getsize(path) == 0:
            return False
    return True


def _omen_model_info(model_dir):
    """Read model_info.json from model_dir. Returns dict or None."""
    info_path = os.path.join(model_dir, "model_info.json")
    if not os.path.isfile(info_path):
        return None
    try:
        with open(info_path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


# OMEN Attack - Train model
def hcatOmenTrain(training_file):
    import datetime

    omen_dir = _omen_dir
    create_bin = os.path.join(omen_dir, hcatOmenCreateBin)
    if not os.path.isfile(create_bin):
        print(f"Error: OMEN createNG binary not found: {create_bin}")
        return False
    training_file = os.path.abspath(training_file)
    if not os.path.isfile(training_file):
        print(f"Error: Training file not found: {training_file}")
        return False
    model_dir = _omen_model_dir()
    print(f"Training OMEN model with: {training_file}")
    print(f"Model output directory: {model_dir}")
    with _wordlist_path(training_file) as resolved_training_file:
        cmd = [
            create_bin,
            "--iPwdList",
            resolved_training_file,
            "-C",
            os.path.join(model_dir, "createConfig"),
            "-c",
            os.path.join(model_dir, "CP"),
            "-i",
            os.path.join(model_dir, "IP"),
            "-e",
            os.path.join(model_dir, "EP"),
            "-l",
            os.path.join(model_dir, "LN"),
        ]
        print(f"[*] Running: {_format_cmd(cmd)}")
        proc = subprocess.Popen(cmd)
        try:
            proc.wait()
        except KeyboardInterrupt:
            print("Killing PID {0}...".format(str(proc.pid)))
            proc.kill()
            return False
    if proc.returncode != 0:
        print(f"OMEN training failed with exit code {proc.returncode}")
        return False
    print("OMEN model training complete.")
    info = {
        "training_file": training_file,
        "trained_at": datetime.datetime.now().isoformat(),
    }
    try:
        with open(os.path.join(model_dir, "model_info.json"), "w") as f:
            json.dump(info, f)
    except OSError:
        pass
    return True


# OMEN Attack - Generate candidates and pipe to hashcat
def hcatOmen(hcatHashType, hcatHashFile, max_candidates, hcatChains=""):
    global hcatProcess
    omen_dir = _omen_dir
    enum_bin = os.path.join(omen_dir, hcatOmenEnumBin)
    if not os.path.isfile(enum_bin):
        print(f"Error: OMEN enumNG binary not found: {enum_bin}")
        return
    model_dir = _omen_model_dir()
    config_path = os.path.join(model_dir, "createConfig")
    if not os.path.isfile(config_path):
        print(f"Error: OMEN model not found at {config_path}")
        print("Run training first (option 16).")
        return
    enum_cmd = [enum_bin, "-p", "-m", str(max_candidates), "-C", config_path]
    hashcat_cmd = [
        hcatBin,
        "-m",
        hcatHashType,
        hcatHashFile,
        "--session",
        generate_session_id(),
        "-o",
        f"{hcatHashFile}.out",
    ]
    if hcatChains:
        hashcat_cmd.extend(shlex.split(hcatChains))
    if _should_use_optimized_kernel("hcatOmen"):
        _insert_optimized_flag(hashcat_cmd)
    hashcat_cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(hashcat_cmd)
    hashcat_cmd = _add_debug_mode_for_rules(hashcat_cmd)
    print(f"[*] Running: {_format_cmd(enum_cmd)} | {_format_cmd(hashcat_cmd)}")
    _debug_cmd(hashcat_cmd)
    enum_proc = subprocess.Popen(
        enum_cmd, cwd=model_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    try:
        _run_hcat_cmd(
            hashcat_cmd,
            attack_name="OMEN",
            hash_file=hcatHashFile,
            stdin=enum_proc.stdout,
            companion_procs=[enum_proc],
            reraise_interrupt=True,
        )
    except KeyboardInterrupt:
        if enum_proc.stderr:
            enum_proc.stderr.close()
        return
    if enum_proc.stdout:
        enum_proc.stdout.close()
    if enum_proc.returncode != 0:
        stderr_output = (
            enum_proc.stderr.read().decode("utf-8", errors="replace").strip()
        )
        print(f"[!] enumNG failed with exit code {enum_proc.returncode}")
        if stderr_output:
            print(f"[!] enumNG error: {stderr_output}")
    if enum_proc.stderr:
        enum_proc.stderr.close()


# Extra - Good Measure
def hcatGoodMeasure(hcatHashType, hcatHashFile):
    global hcatExtraCount
    global hcatProcess
    rule_combinator = get_rule_path("combinator.rule")
    rule_insidepro = get_rule_path("InsidePro-PasswordsPro.rule")
    cmd = [
        hcatBin,
        "-m",
        hcatHashType,
        hcatHashFile,
        "--session",
        generate_session_id(),
        "-o",
        f"{hcatHashFile}.out",
        "-r",
        rule_combinator,
        "-r",
        rule_insidepro,
        hcatGoodMeasureBaseList,
    ]
    if _should_use_optimized_kernel("hcatGoodMeasure"):
        _insert_optimized_flag(cmd)
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(cmd)
    cmd = _add_debug_mode_for_rules(cmd)
    _run_hcat_cmd(
        cmd,
        attack_name="Good Measure",
        hash_file=hcatHashFile,
        coverage=_coverage.CoverageSpec(
            hash_file=hcatHashFile,
            wordlists=(hcatGoodMeasureBaseList,),
            rule_files=(rule_combinator, rule_insidepro),
        ),
    )

    hcatExtraCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


# LanMan to NT Attack
def hcatLMtoNT():
    global hcatProcess
    _run_hashcat_show("3000", f"{hcatHashFile}.lm", f"{hcatHashFile}.lm.cracked")

    cmd = [
        hcatBin,
        "-m",
        "3000",
        f"{hcatHashFile}.lm",
        "--session",
        generate_session_id(),
        "-o",
        f"{hcatHashFile}.lm.cracked",
        "-1",
        "?u?d?s",
        "--increment",
        "-a",
        "3",
        "?1?1?1?1?1?1?1",
    ]
    if _should_use_optimized_kernel("hcatLMtoNT"):
        _insert_optimized_flag(cmd)
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(cmd)
    _run_hcat_cmd(
        cmd,
        attack_name="LM to NT (LM phase)",
        hash_file=f"{hcatHashFile}.lm",
        out_path=f"{hcatHashFile}.lm.cracked",
    )

    _extract_cracked_plaintexts(f"{hcatHashFile}.lm.cracked", f"{hcatHashFile}.working")
    combine_path = os.path.join(hate_path, "hashcat-utils", "bin", hcatCombinatorBin)
    with open(f"{hcatHashFile}.combined", "wb") as combined_out:
        combine_proc = subprocess.Popen(
            [combine_path, f"{hcatHashFile}.working", f"{hcatHashFile}.working"],
            stdout=subprocess.PIPE,
        )
        hcatProcess = subprocess.Popen(
            ["sort", "-u"],
            stdin=combine_proc.stdout,
            stdout=combined_out,
            env={**os.environ, "LC_ALL": "C"},
        )
        combine_proc.stdout.close()
        try:
            hcatProcess.wait()
            combine_proc.wait()
        except KeyboardInterrupt:
            print("Killing PID {0}...".format(str(hcatProcess.pid)))
            hcatProcess.kill()
            combine_proc.kill()

    _run_hashcat_show("1000", f"{hcatHashFile}.nt", f"{hcatHashFile}.nt.out")

    cmd = [
        hcatBin,
        "-m",
        "1000",
        f"{hcatHashFile}.nt",
        "--session",
        generate_session_id(),
        "-o",
        f"{hcatHashFile}.nt.out",
        f"{hcatHashFile}.combined",
        "-r",
        ensure_toggle_rule()
        or get_rule_path(
            "toggles-lm-ntlm.rule", fallback_dir=os.path.join(hate_path, "rules")
        ),
    ]
    if _should_use_optimized_kernel("hcatLMtoNT"):
        _insert_optimized_flag(cmd)
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(cmd)
    cmd = _add_debug_mode_for_rules(cmd)
    _run_hcat_cmd(
        cmd,
        attack_name="LM to NT (NT phase)",
        hash_file=f"{hcatHashFile}.nt",
        out_path=f"{hcatHashFile}.nt.out",
    )

    # toggle-lm-ntlm.rule by Didier Stevens https://blog.didierstevens.com/2016/07/16/tool-to-generate-hashcat-toggle-rules/


# Recycle Cracked Passwords
def hcatRecycle(hcatHashType, hcatHashFile, hcatNewPasswords):
    global hcatProcess
    working_file = hcatHashFile + ".working"
    if hcatNewPasswords > 0:
        _extract_cracked_plaintexts(f"{hcatHashFile}.out", working_file)
        for rule in hcatRules:
            rule_path = get_rule_path(rule)
            cmd = [
                hcatBin,
                "-m",
                hcatHashType,
                hcatHashFile,
                "--session",
                generate_session_id(),
                "-o",
                f"{hcatHashFile}.out",
                f"{hcatHashFile}.working",
                "-r",
                rule_path,
            ]
            if _should_use_optimized_kernel("hcatRecycle"):
                _insert_optimized_flag(cmd)
            cmd.extend(shlex.split(hcatTuning))
            _append_potfile_arg(cmd)
            cmd = _add_debug_mode_for_rules(cmd)
            _run_hcat_cmd(cmd, attack_name="Recycle", hash_file=hcatHashFile)


def hcatGenerateRules(hcatHashType, hcatHashFile, rule_count, wordlist):
    global hcatProcess, hcatGenerateRulesCount
    generate_rules_path = os.path.join(
        hate_path, "hashcat-utils", "bin", "generate-rules.bin"
    )
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".rule", prefix="hate_crack_random_", delete=False
    ) as rules_file:
        rules_path = rules_file.name
    try:
        result = subprocess.run(
            [generate_rules_path, str(rule_count)],
            capture_output=True,
            text=True,
            check=True,
        )
        with open(rules_path, "w") as f:
            f.write(result.stdout)
        cmd = [
            hcatBin,
            "-m",
            hcatHashType,
            hcatHashFile,
            "--session",
            generate_session_id(),
            "-o",
            f"{hcatHashFile}.out",
            "-r",
            rules_path,
            wordlist,
        ]
        cmd.extend(shlex.split(hcatTuning))
        _append_potfile_arg(cmd)
        cmd = _add_debug_mode_for_rules(cmd)
        _run_hcat_cmd(cmd, attack_name="Random Rules", hash_file=hcatHashFile)
    finally:
        if os.path.exists(rules_path):
            os.unlink(rules_path)
    hcatGenerateRulesCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


def check_potfile(force_overwrite=False):
    """Refresh `<hashfile>.out` from the POT file.

    `force_overwrite` is for the deliberate rebuild path (`restore_from_potfile`
    and `--restore-potfile`), which has already confirmed with the operator that
    an empty POT file may replace whatever is there.
    """
    print("Checking POT file for already cracked hashes...")
    _run_hashcat_show(
        hcatHashType,
        hcatHashFile,
        f"{hcatHashFile}.out",
        force_overwrite=force_overwrite,
    )
    hcatHashCracked = lineCount(hcatHashFile + ".out")
    if hcatHashCracked > 0:
        print(
            "Found %d hashes already cracked.\nCopied hashes to %s.out"
            % (hcatHashCracked, hcatHashFile)
        )
    else:
        print("No hashes found in POT file.")


def _confirm_overwrite(path, prompt):
    """Ask before clobbering `path`. Non-interactive callers always proceed.

    Returns True when the caller should go ahead with the overwrite.
    """
    if not os.path.isfile(path):
        return True
    existing = lineCount(path)
    if existing <= 0:
        return True
    print(f"{path} already contains {existing} cracked hash(es).")
    if not sys.stdin.isatty():
        return True
    answer = input(prompt).strip().lower()
    return answer in ("", "y", "yes")


# Rebuild <hashfile>.out from the POT file, discarding whatever is there now.
def restore_from_potfile():
    if not hcatHashFile:
        print("Error: No hashfile loaded.")
        return False
    out_path = hcatHashFile + ".out"
    if not _confirm_overwrite(
        out_path, "Overwrite it with the POT file contents? (Y/n): "
    ):
        print("Left the existing output file untouched.")
        return False
    check_potfile(force_overwrite=True)
    return True


# creating the combined output for pwdformat + cleartext
def combine_ntlm_output():
    hashes = {}
    # Nothing to merge onto: without a pwdump original these are the same file,
    # and the old code opened its own input with "w+", truncating every cracked
    # password it had just read (issue #195). Compare resolved paths so a
    # different spelling of the same file is caught too. This runs *before*
    # check_potfile() deliberately: in the same-path case the function has no
    # work to do, so rewriting `.out` from the POT file here is pure risk with no
    # upside - every attack already passes `-o <hashfile>.out`, so that file is
    # hashcat's own record of the cracks, and a POT file that is empty or holds a
    # subset of them can only subtract.
    orig_path = str(hcatHashFileOrig)
    live_path = str(hcatHashFile)
    if os.path.abspath(orig_path) == os.path.abspath(live_path):
        print("Hash file is not pwdump format; nothing to combine.")
        return
    check_potfile()
    if not os.path.isfile(hcatHashFile + ".out"):
        print("No hashes found in POT file.")
        return
    with open(hcatHashFile + ".out", "r") as hcatCrackedFile:
        for crackedLine in hcatCrackedFile:
            parts = crackedLine.split(":", 1)
            if len(parts) != 2:
                continue
            hash, password = parts
            hashes[hash] = password.rstrip()
    if not hashes:
        print("No hashes found in POT file.")
        return

    # Build the merged file beside its destination and move it into place only
    # once it has content, so a run that matches nothing cannot replace a good
    # result with an empty one.
    destination = hcatHashFileOrig + ".out"
    temp_path = destination + ".combine.tmp"
    written = 0
    try:
        with open(temp_path, "w") as hcatCombinedHashes:
            with open(hcatHashFileOrig, "r") as hcatOrigFile:
                for origLine in hcatOrigFile:
                    orig_parts = origLine.split(":")
                    if len(orig_parts) < 4:
                        continue
                    ntlm_hash = orig_parts[3]
                    if ntlm_hash in hashes:
                        password = hashes[ntlm_hash]
                        hcatCombinedHashes.write(origLine.strip() + password + "\n")
                        written += 1
        if written:
            os.replace(temp_path, destination)
        else:
            print("No cracked hashes matched the original file; leaving it as is.")
    finally:
        if os.path.isfile(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


# Cleanup Temp Files
def cleanup():
    global pwdump_format
    global hcatHashFileOrig
    try:
        if not hcatHashFileOrig:
            # Fall back to the live hash file so a missed assignment degrades to
            # "skip the pwdump comparison" rather than skipping cleanup entirely.
            if not hcatHashFile:
                return
            hcatHashFileOrig = hcatHashFile
        if hcatHashType == "1000" and pwdump_format:
            print("\nComparing cracked hashes to original file...")
            combine_ntlm_output()
        out_path = hcatHashFileOrig + ".out"
        if os.path.isfile(out_path):
            print(f"\nCracked passwords combined with original hashes in {out_path}")
        else:
            print(
                f"\nNo cracked hashes to combine. Raw output (if any): {hcatHashFile}.out"
            )
        print("\nCleaning up temporary files...")
        if os.path.exists(hcatHashFile + ".masks"):
            os.remove(hcatHashFile + ".masks")
        if os.path.exists(hcatHashFile + ".hcmask"):
            os.remove(hcatHashFile + ".hcmask")
        # Belt-and-braces: hcatSmartMask already removes this itself once its
        # attack finishes, but a hard kill between writing it and that cleanup
        # would otherwise leave it behind.
        if os.path.exists(hcatHashFile + ".smartmask.hcmask"):
            os.remove(hcatHashFile + ".smartmask.hcmask")
        if os.path.exists(hcatHashFile + ".working"):
            os.remove(hcatHashFile + ".working")
        if os.path.exists(hcatHashFile + ".expanded"):
            os.remove(hcatHashFile + ".expanded")
        # A directory since the attack started generating its own rules; the
        # isfile branch clears scratch from before that change, when this
        # attack wrote a single patterns file at the same path. Deliberately
        # names no version: the release number is computed at tag time, so a
        # version in a comment here rots without anything noticing.
        if os.path.isdir(hcatHashFile + ".llm_patterns"):
            shutil.rmtree(hcatHashFile + ".llm_patterns", ignore_errors=True)
        elif os.path.isfile(hcatHashFile + ".llm_patterns"):
            os.remove(hcatHashFile + ".llm_patterns")
        if os.path.isdir(hcatHashFile + ".spoonman"):
            shutil.rmtree(hcatHashFile + ".spoonman", ignore_errors=True)
        if os.path.isdir(hcatHashFile + ".rosetta"):
            shutil.rmtree(hcatHashFile + ".rosetta", ignore_errors=True)
        if os.path.exists(hcatHashFileOrig + ".combined"):
            os.remove(hcatHashFileOrig + ".combined")
        if os.path.exists(hcatHashFileOrig + ".lm"):
            os.remove(hcatHashFileOrig + ".lm")
        if os.path.exists(hcatHashFileOrig + ".lm.cracked"):
            os.remove(hcatHashFileOrig + ".lm.cracked")
        if os.path.exists(hcatHashFileOrig + ".working"):
            os.remove(hcatHashFileOrig + ".working")
        if os.path.exists(hcatHashFileOrig + ".passwords"):
            os.remove(hcatHashFileOrig + ".passwords")
    except DoubleInterrupt:
        cleanup()
        raise
    except KeyboardInterrupt:
        # incase someone mashes the Control+C it will still cleanup
        cleanup()


def hashview_api():
    """Download/Upload data to Hashview API"""
    global hcatHashFile, hcatHashType, hcatHashFileOrig

    if not REQUESTS_AVAILABLE:
        print("\nError: 'requests' module not found.")
        print("Install it with: pip install requests")
        return

    print("\n" + "=" * 60)
    print("Hashview Integration")
    print("=" * 60)

    # Get Hashview connection details from config
    if not hashview_api_key:
        print("\nError: Hashview API key not configured.")
        print("Please set HASHVIEW_API_KEY in the .env file")
        return

    print(f"\nConnecting to Hashview at: {hashview_url}")

    try:
        api_harness = HashviewAPI(hashview_url, hashview_api_key, debug=debug_mode)

        while True:
            print("\n" + "=" * 60)
            print("What would you like to do?")
            print("=" * 60)

            # Build dynamic menu based on state
            menu_options = []
            if hcatHashFile:
                menu_options.append(
                    ("upload_cracked", "Upload Cracked Hashes from current session")
                )
            menu_options.append(("upload_wordlist", "Upload Wordlist"))
            menu_options.append(("download_wordlist", "Download Wordlist"))
            menu_options.append(("download_rules", "Download Rule"))
            menu_options.append(
                (
                    "download_hashes",
                    "Download Hashes (left + found to potfile)",
                )
            )
            if hcatHashFile:
                menu_options.append(
                    ("upload_hashfile_job", "Upload Hashfile and Create Job")
                )
            menu_options.append(("back", "Back to Main Menu"))

            # Build display items with numbered keys
            display_items = []
            option_map = {}
            display_num = 1
            for opt_key, opt_text in menu_options:
                if opt_key == "back":
                    display_items.append(("99", opt_text))
                    option_map["99"] = opt_key
                else:
                    display_items.append((str(display_num), opt_text))
                    option_map[str(display_num)] = opt_key
                    display_num += 1

            choice = interactive_menu(
                display_items,
                title="What would you like to do?",
                prompt="\nSelect an option: ",
            )

            if choice is None or choice not in option_map:
                if choice is not None:
                    print("Invalid option. Please try again.")
                continue

            option_key = option_map[choice]

            if option_key == "upload_cracked":
                # Upload cracked hashes
                if not hcatHashFile:
                    print(
                        "\n✗ Error: No hashfile is currently set. This option is not available."
                    )
                    continue

                print("\n" + "-" * 60)
                print("Upload Cracked Hashes")
                print("-" * 60)

                # Check if we're in an active session
                cracked_file = None
                session_file = None
                try:
                    if "hcatHashFile" in globals() and hcatHashFile:
                        potential_file = hcatHashFile + ".out"
                        if os.path.exists(potential_file):
                            session_file = potential_file
                            print(f"Found session file: {session_file}")
                    elif "hcatHashFile" in globals() and hcatHashFile:
                        potential_file = hcatHashFile + "nt.out"
                        if os.path.exists(potential_file):
                            session_file = potential_file
                            print(f"Found session file: {session_file}")
                except Exception:
                    pass

                # Prompt for file
                if session_file:
                    use_session = input("Use this file? (Y/n): ").strip().lower()
                    if use_session != "n":
                        cracked_file = session_file

                if not cracked_file:
                    cracked_file = select_file_with_autocomplete(
                        f"Enter path to cracked hashes file (.out format) [hash type: {hcatHashType}] (TAB to autocomplete)"
                    )
                    # select_file_with_autocomplete may return a list if allow_multiple=True, but we expect a string
                    if isinstance(cracked_file, list):
                        if cracked_file:
                            cracked_file = cracked_file[0]  # Use the first file
                        else:
                            cracked_file = None
                    if isinstance(cracked_file, str):
                        cracked_file = cracked_file.strip()
                # Validate file exists
                if (
                    not cracked_file
                    or not isinstance(cracked_file, str)
                    or not os.path.exists(cracked_file)
                ):
                    print(f"✗ Error: File not found: {cracked_file}")
                    continue
                # Show file info
                file_size = os.path.getsize(cracked_file)
                with open(cracked_file, "r") as f:
                    line_count = sum(1 for _ in f)
                print(f"File: {cracked_file}")
                print(f"Size: {file_size} bytes")
                print(f"Lines: {line_count}")

                # Block upload if file is empty
                if file_size == 0 or line_count == 0:
                    print(f"✗ Error: File {cracked_file} is empty. Upload aborted.")
                    continue

                # Use the same hash type from main menu
                hash_type = hcatHashType

                # Upload
                print(f"\nUploading to Hashview (hash type: {hash_type})...")
                try:
                    result = api_harness.upload_cracked_hashes(cracked_file, hash_type)
                    print(
                        f"\n✓ Success: {result.get('msg', 'Cracked hashes uploaded')}"
                    )
                    if not isinstance(result, dict):
                        result = {}
                    # What this client sent (available regardless of server version).
                    if "uploaded" in result:
                        line = f"  Uploaded: {result['uploaded']} pair(s)"
                        if result.get("skipped"):
                            line += f" ({result['skipped']} skipped by validation)"
                        print(line)
                    if result.get("skipped_cached"):
                        print(
                            f"  Skipped: {result['skipped_cached']} already uploaded previously"
                        )
                    # What the server actually did (newer Hashview reports these).
                    if "verified" in result or "updated" in result or "count" in result:
                        updated = result.get("updated", result.get("count"))
                        print(f"  Newly cracked in Hashview: {updated}")
                        if "verified" in result:
                            print(f"  Verified: {result['verified']}")
                        if result.get("unmatched"):
                            print(
                                "  Unmatched (already cracked or not in Hashview): "
                                f"{result['unmatched']}"
                            )
                except Exception as e:
                    print(f"\n✗ Error: {str(e)}")
                    import traceback

                    print("\nFull error details:")
                    traceback.print_exc()

            elif option_key == "upload_wordlist":
                print("\n" + "-" * 60)
                print("Upload Wordlist")
                print("-" * 60)
                wordlist_path = select_file_with_autocomplete(
                    "Enter path to wordlist file (TAB to autocomplete)",
                    base_dir=hcatWordlists,
                )
                if isinstance(wordlist_path, list):
                    wordlist_path = wordlist_path[0] if wordlist_path else None
                if isinstance(wordlist_path, str):
                    wordlist_path = wordlist_path.strip()
                if not wordlist_path or not os.path.isfile(wordlist_path):
                    print(f"✗ Error: File not found: {wordlist_path}")
                    continue
                default_name = os.path.basename(wordlist_path)
                wordlist_name = (
                    input(f"Enter wordlist name (default: {default_name}): ").strip()
                    or default_name
                )
                try:
                    result = api_harness.upload_wordlist_file(
                        wordlist_path, wordlist_name
                    )
                    print(f"\n✓ Success: {result.get('msg', 'Wordlist uploaded')}")
                    if "wordlist_id" in result:
                        print(f"  Wordlist ID: {result['wordlist_id']}")
                except Exception as e:
                    print(f"\n✗ Error uploading wordlist: {str(e)}")

            elif option_key == "download_wordlist":
                # Download wordlist
                try:
                    wordlists = api_harness.list_wordlists()
                    wordlist_map = {}
                    if wordlists:
                        print("\n" + "=" * 100)
                        print("Available Wordlists:")
                        print("=" * 100)
                        print(f"{'ID':<10} {'Name':<60} {'Size':>12}")
                        print("-" * 100)
                        for wl in wordlists:
                            wl_id = wl.get("id", "N/A")
                            wl_name = wl.get("name", "N/A")
                            wl_size = wl.get("size", "N/A")
                            name = str(wl_name)
                            if len(name) > 60:
                                name = name[:57] + "..."
                            print(f"{wl_id:<10} {name:<60} {wl_size:>12}")
                            if wl_id != "N/A":
                                try:
                                    wordlist_map[int(wl_id)] = str(wl_name)
                                except ValueError:
                                    pass
                        print("=" * 100)
                    else:
                        print("\nNo wordlists found.")
                except Exception as e:
                    print(f"\n✗ Error fetching wordlists: {str(e)}")
                    continue

                try:
                    wordlist_id = int(input("\nEnter wordlist ID: "))
                except ValueError:
                    print("\n✗ Error: Invalid ID entered. Please enter a numeric ID.")
                    continue

                api_name = (
                    wordlist_map.get(wordlist_id)
                    if "wordlist_map" in locals()
                    else None
                )
                api_filename = "dynamic-all.txt.gz" if wordlist_id == 1 else api_name
                prompt_suffix = (
                    f" (API filename: {api_filename})"
                    if api_filename
                    else " (API filename)"
                )
                output_file = (
                    input(
                        f"Enter output file name{prompt_suffix} or press Enter to use API filename: "
                    ).strip()
                    or None
                )
                if output_file is None and wordlist_id == 1:
                    output_file = "dynamic-all.txt.gz"
                try:
                    download_result = api_harness.download_wordlist(
                        wordlist_id, output_file
                    )
                    print(f"\n✓ Success: Downloaded {download_result['size']} bytes")
                    print(f"  File: {download_result['output_file']}")
                except Exception as e:
                    print(f"\n✗ Error downloading wordlist: {str(e)}")

            elif option_key == "download_rules":
                # Download rule file
                try:
                    rules = api_harness.list_rules()
                    rule_map = {}
                    if rules:
                        print("\n" + "=" * 100)
                        print("Available Rules:")
                        print("=" * 100)
                        print(f"{'ID':<10} {'Name':<60} {'Size':>12}")
                        print("-" * 100)
                        for rule in rules:
                            r_id = rule.get("id", "N/A")
                            r_name = rule.get("name", "N/A")
                            r_size = rule.get("size", "N/A")
                            name = str(r_name)
                            if len(name) > 60:
                                name = name[:57] + "..."
                            print(f"{r_id:<10} {name:<60} {r_size:>12}")
                            if r_id != "N/A":
                                try:
                                    rule_map[int(r_id)] = str(r_name)
                                except ValueError:
                                    pass
                        print("=" * 100)
                    else:
                        print("\nNo rules found.")
                except Exception as e:
                    print(f"\n✗ Error fetching rules: {str(e)}")
                    continue

                try:
                    rules_id = int(input("\nEnter rule ID: "))
                except ValueError:
                    print("\n✗ Error: Invalid ID entered. Please enter a numeric ID.")
                    continue

                api_name = rule_map.get(rules_id)
                prompt_suffix = (
                    f" (API filename: {api_name})" if api_name else " (API filename)"
                )
                output_file = (
                    input(
                        f"Enter output file name{prompt_suffix} or press Enter to use API filename: "
                    ).strip()
                    or api_name
                )
                try:
                    download_result = api_harness.download_rules(rules_id, output_file)
                    print(f"\n✓ Success: Downloaded {download_result['size']} bytes")
                    print(f"  File: {download_result['output_file']}")
                except Exception as e:
                    print(f"\n✗ Error downloading rule: {str(e)}")

            elif option_key == "upload_hashfile_job":
                # Upload hashfile and create job
                if not hcatHashFile:
                    print("\n✗ Error: No hashfile is currently set.")
                    continue
                # First, list customers to help user select
                try:
                    customers_result = api_harness.list_customers()
                    customers = (
                        customers_result.get("customers", [])
                        if isinstance(customers_result, dict)
                        else customers_result
                    )
                    if customers:
                        api_harness.display_customers_multicolumn(customers)
                    else:
                        print("\nNo customers found.")
                except Exception as e:
                    print(f"\n✗ Error fetching customers: {str(e)}")

                # Select or create customer
                customer_input = input(
                    "\nEnter customer ID or N to create new: "
                ).strip()
                if customer_input.lower() == "n":
                    customer_name = input("Enter customer name: ").strip()
                    if customer_name:
                        try:
                            result = api_harness.create_customer(customer_name)
                            print(
                                f"\n✓ Success: {result.get('msg', 'Customer created')}"
                            )
                            customer_id = result.get("customer_id") or result.get("id")
                            if not customer_id:
                                print("\n✗ Error: Customer ID not returned.")
                                continue
                            print(f"  Customer ID: {customer_id}")
                        except Exception as e:
                            print(f"\n✗ Error creating customer: {str(e)}")
                            continue
                    else:
                        print("\n✗ Error: Customer name cannot be empty.")
                        continue
                else:
                    try:
                        customer_id = int(customer_input)
                    except ValueError:
                        print(
                            "\n✗ Error: Invalid ID entered. Please enter a numeric ID or N."
                        )
                        continue

                # Use hashfile from original command if available
                hashfile_path = (
                    hcatHashFileOrig  # Use original path, not the modified one
                )
                if not hashfile_path or not os.path.exists(hashfile_path):
                    hashfile_path = select_file_with_autocomplete(
                        "Enter path to hashfile (TAB to autocomplete)"
                    )
                    # Handle list return from autocomplete
                    if isinstance(hashfile_path, list):
                        hashfile_path = hashfile_path[0] if hashfile_path else None
                    if isinstance(hashfile_path, str):
                        hashfile_path = hashfile_path.strip()

                if not hashfile_path or not os.path.exists(hashfile_path):
                    print(f"Error: File not found: {hashfile_path}")
                    continue

                # Use hash type from original command if available, otherwise prompt
                if hcatHashType and str(hcatHashType).isdigit():
                    hash_type = int(hcatHashType)
                    print(f"Using hash type: {hash_type}")
                else:
                    hash_type = int(input("Enter hash type (e.g., 1000 for NTLM): "))

                # Auto-detect file format based on content
                file_format = 5  # Default to hash_only
                try:
                    with open(
                        hashfile_path, "r", encoding="utf-8", errors="ignore"
                    ) as f:
                        first_line = f.readline().strip()
                        if first_line:
                            # Check for pwdump format (username:hash or username:rid:lmhash:nthash)
                            parts = first_line.split(":")
                            if len(parts) >= 4:
                                # Likely pwdump format (username:rid:lmhash:nthash)
                                file_format = 0
                            elif len(parts) == 2 and not all(
                                c in "0123456789abcdefABCDEF" for c in parts[0]
                            ):
                                # Likely user:hash format (first part is not all hex)
                                file_format = 4
                            # Otherwise default to 5 (hash_only)
                except Exception:
                    file_format = 5  # Default if detection fails

                format_names = {
                    0: "pwdump",
                    1: "NetNTLM",
                    2: "kerberos",
                    3: "shadow",
                    4: "user:hash",
                    5: "hash_only",
                }
                format_list = ", ".join(f"{k}={v}" for k, v in format_names.items())
                print(
                    f"\nAuto-detected file format: {file_format} ({format_names.get(file_format, 'unknown')})"
                )
                override = input(
                    f"Override format number? [{format_list}] (Enter to accept): "
                ).strip()
                if override:
                    try:
                        file_format = int(override)
                    except ValueError:
                        print(
                            f"\n✗ Invalid format '{override}', using auto-detected value."
                        )

                # Default hashfile name to the basename of the file
                hashfile_name = os.path.basename(hashfile_path)
                print(f"Using hashfile name: {hashfile_name}")

                try:
                    result = api_harness.upload_hashfile(
                        hashfile_path,
                        customer_id,
                        hash_type,
                        file_format,
                        hashfile_name,
                    )
                    print(f"\n✓ Success: {result.get('msg', 'Hashfile uploaded')}")
                    if result.get("hashfile_id"):
                        print(f"  Hashfile ID: {result['hashfile_id']}")
                        # Hash count is not returned by the upload API, so we don't display it
                        if "hash_count" in result:
                            print(f"  Hash count: {result['hash_count']}")
                        if "instacracked" in result:
                            print(f"  Insta-cracked: {result['instacracked']}")

                        # Offer to create a job
                        create_job = (
                            input(
                                "\nWould you like to create a job for this hashfile? (Y/n): "
                            )
                            or "Y"
                        )
                        if create_job.upper() == "Y":
                            job_name = input("Enter job name: ")
                            limit_recovered = False
                            try:
                                job_result = api_harness.create_job(
                                    job_name,
                                    result["hashfile_id"],
                                    customer_id,
                                    limit_recovered,
                                )
                                msg = job_result.get("msg", "")
                                if "job_id" in job_result:
                                    print(f"\n✓ Success: {msg or 'Job created'}")
                                    print(f"  Job ID: {job_result['job_id']}")
                                    print(
                                        "\nNote: Job created with automatically assigned tasks based on"
                                    )
                                    print(
                                        f"      historical effectiveness for hash type {hash_type}."
                                    )

                                    # Offer to start the job
                                    start_now = (
                                        input("\nStart the job now? (Y/n): ") or "Y"
                                    )
                                    if start_now.upper() == "Y":
                                        stop_after_one = (
                                            input("Stop after a single result? (y/N): ")
                                            .strip()
                                            .upper()
                                            == "Y"
                                        )
                                        start_result = api_harness.start_job(
                                            job_result["job_id"],
                                            limit_recovered=stop_after_one,
                                        )
                                        print(
                                            f"\n✓ Success: {start_result.get('msg', 'Job started')}"
                                        )
                                else:
                                    print(
                                        f"\n✗ Error: {msg or 'Job creation failed (no job_id returned)'}"
                                    )
                                    print(
                                        "  Note: The Hashview server may have created the job"
                                        " despite this error. Check the Hashview UI before retrying."
                                    )
                            except Exception as e:
                                print(f"\n✗ Error creating job: {str(e)}")
                    if result.get("skipped_cached"):
                        print(
                            f"  Skipped: {result['skipped_cached']} already uploaded previously"
                        )
                except Exception as e:
                    print(f"\n✗ Error uploading hashfile: {str(e)}")

            elif option_key == "download_hashes":
                # Download left hashes
                try:
                    cancel_download = False
                    while True:
                        # First, list customers to help user select
                        customers_result = api_harness.list_customers()
                        customers = (
                            customers_result.get("customers", [])
                            if isinstance(customers_result, dict)
                            else customers_result
                        )
                        if customers:
                            api_harness.display_customers_multicolumn(customers)
                        else:
                            print("\nNo customers found.")

                        # Select or create customer
                        customer_input = input(
                            "\nEnter customer ID or N to create new: "
                        ).strip()
                        if customer_input.lower() == "n":
                            customer_name = input("Enter customer name: ").strip()
                            if customer_name:
                                try:
                                    result = api_harness.create_customer(customer_name)
                                    print(
                                        f"\n✓ Success: {result.get('msg', 'Customer created')}"
                                    )
                                    customer_id = result.get(
                                        "customer_id"
                                    ) or result.get("id")
                                    if not customer_id:
                                        print("\n✗ Error: Customer ID not returned.")
                                        continue
                                    print(f"  Customer ID: {customer_id}")
                                except Exception as e:
                                    print(f"\n✗ Error creating customer: {str(e)}")
                                    continue
                            else:
                                print("\n✗ Error: Customer name cannot be empty.")
                                continue
                        else:
                            try:
                                customer_id = int(customer_input)
                            except ValueError:
                                print(
                                    "\n✗ Error: Invalid ID entered. Please enter a numeric ID or N."
                                )
                                continue

                        # Try to list the customer's hashfiles for convenience.
                        # Servers with the customer-scoped route answer in one
                        # request; older ones fall back to a per-type sweep, and
                        # ones with neither leave the list empty, so the hashfile
                        # ID has to be entered directly (look it up in the web UI).
                        hashfile_map = {}
                        try:
                            print("\nRetrieving customer hashfiles...")
                            customer_hashfiles = api_harness.get_all_customer_hashfiles(
                                customer_id
                            )
                        except Exception as e:
                            customer_hashfiles = []
                            if debug_mode:
                                print(f"[DEBUG] hashfile listing unavailable: {e}")

                        if customer_hashfiles:
                            print("\n" + "=" * 120)
                            print(f"Hashfiles for Customer ID {customer_id}:")
                            print("=" * 120)
                            print(f"{'ID':<10} {'Hash Type':<10} {'Name':<96}")
                            print("-" * 120)
                            for hf in customer_hashfiles:
                                hf_id = hf.get("id")
                                hf_name = hf.get("name", "N/A")
                                hf_type = (
                                    hf.get("hash_type") or hf.get("hashtype") or "N/A"
                                )
                                if hf_id is None:
                                    continue
                                # Truncate long names to fit within 120 columns
                                if len(str(hf_name)) > 96:
                                    hf_name = str(hf_name)[:93] + "..."
                                if debug_mode:
                                    print(
                                        f"[DEBUG] Hashfile {hf_id}: hash_type={hf.get('hash_type')}, hashtype={hf.get('hashtype')}, combined={hf_type}"
                                    )
                                print(f"{hf_id:<10} {hf_type:<10} {hf_name:<96}")
                                hashfile_map[int(hf_id)] = hf_type
                            print("=" * 120)
                            print(f"Total: {len(hashfile_map)} hashfile(s)")
                        else:
                            print(
                                f"\nNo hashfiles listed for customer {customer_id}. "
                                "Either the customer has none, or this Hashview "
                                "server predates the hashfile-listing API. Look up "
                                "the hashfile ID in the Hashview web UI and enter "
                                "it below."
                            )

                        while True:
                            hashfile_id_input = input(
                                "\nEnter hashfile ID (or Q to cancel): "
                            ).strip()
                            if hashfile_id_input.lower() == "q":
                                cancel_download = True
                                break
                            try:
                                hashfile_id = int(hashfile_id_input)
                            except ValueError:
                                print(
                                    "\n✗ Error: Invalid ID entered. Please enter a numeric ID."
                                )
                                continue
                            # Only restrict to the listed set when we actually
                            # have a listing; otherwise accept any ID the user
                            # read from the web UI.
                            if hashfile_map and hashfile_id not in hashfile_map:
                                print(
                                    "\n✗ Error: Hashfile ID not in the list. Please try again."
                                )
                                continue
                            break
                        break

                    # User cancelled at the hash-type prompt: back to the menu.
                    if cancel_download:
                        continue

                    # Set output filename automatically
                    output_file = f"left_{customer_id}_{hashfile_id}.txt"

                    # Get hash type for hashcat from the hashfile map
                    selected_hash_type = hashfile_map.get(hashfile_id)
                    if debug_mode:
                        print(
                            f"[DEBUG] selected_hash_type from map: {selected_hash_type}"
                        )
                    if not selected_hash_type or selected_hash_type == "N/A":
                        try:
                            details = api_harness.get_hashfile_details(hashfile_id)
                            selected_hash_type = details.get("hashtype")
                            if debug_mode:
                                print(
                                    f"[DEBUG] selected_hash_type from get_hashfile_details: {selected_hash_type}"
                                )
                        except Exception as e:
                            if debug_mode:
                                print(f"[DEBUG] Error fetching hashfile details: {e}")
                            selected_hash_type = None

                    # Download the left hashes
                    download_result = api_harness.download_left_hashes(
                        customer_id,
                        hashfile_id,
                        output_file,
                        potfile_path=hcatPotfilePath,
                    )
                    print(f"\n✓ Success: Downloaded {download_result['size']} bytes")
                    print(f"  File: {download_result['output_file']}")
                    if selected_hash_type:
                        print(f"  Hash mode: {selected_hash_type}")

                    # Ask if user wants to switch to this hashfile
                    switch = (
                        input("\nSwitch to this hashfile for cracking? (Y/n): ")
                        .strip()
                        .lower()
                    )
                    if switch != "n":
                        hcatHashFile = download_result["output_file"]
                        # Rebind the original alongside it: cleanup() keys every
                        # temp-file removal and the pwdump comparison off this,
                        # so leaving it stale (or unset) strands artifacts.
                        hcatHashFileOrig = hcatHashFile
                        if selected_hash_type:
                            hcatHashType = str(selected_hash_type)
                        else:
                            hcatHashType = "1000"  # Default to NTLM if unavailable
                        print(f"✓ Switched to hashfile: {hcatHashFile}")
                        print("\nReturning to main menu to start cracking...")
                        return  # Exit hashview menu and return to main menu

                except ValueError:
                    print("\n✗ Error: Invalid ID entered. Please enter a numeric ID.")
                except Exception as e:
                    print(f"\n✗ Error downloading hashes: {str(e)}")

            elif option_key == "back":
                break

    except KeyboardInterrupt:
        print("\nKeyboard interrupt: Returning to main menu...")
        return
    except Exception as e:
        print(f"\nError connecting to Hashview: {str(e)}")


def _auto_input(prompt, default=""):
    """input() wrapper that returns the default without prompting when running
    in non-interactive (scripted) mode. In interactive mode this is identical
    to ``input(prompt) or default``."""
    if non_interactive:
        return default
    return input(prompt) or default


def _attack_ctx():
    ctx = sys.modules.get(__name__)
    if ctx is None:
        return SimpleNamespace(**globals())
    return ctx


def quick_crack():
    return _attacks.quick_crack(_attack_ctx())


def extensive_crack():
    return _attacks.extensive_crack(_attack_ctx())


def brute_force_crack():
    return _attacks.brute_force_crack(_attack_ctx())


def top_mask_crack():
    return _attacks.top_mask_crack(_attack_ctx())


def fingerprint_crack():
    return _attacks.fingerprint_crack(_attack_ctx())


def smart_mask_crack():
    return _attacks.smart_mask_crack(_attack_ctx())


def combinator_crack():
    return _attacks.combinator_crack(_attack_ctx())


def hybrid_crack():
    return _attacks.hybrid_crack(_attack_ctx())


def pathwell_crack():
    return _attacks.pathwell_crack(_attack_ctx())


def corporate_masks_crack():
    return _attacks.corporate_masks_crack(_attack_ctx())


def prince_attack():
    return _attacks.prince_attack(_attack_ctx())


def yolo_combination():
    return _attacks.yolo_combination(_attack_ctx())


def thorough_combinator():
    return _attacks.thorough_combinator(_attack_ctx())


def middle_combinator():
    return _attacks.middle_combinator(_attack_ctx())


def ngram_attack():
    return _attacks.ngram_attack(_attack_ctx())


def restore_potfile_output():
    return _attacks.restore_potfile_output(_attack_ctx())


def combinator_submenu():
    return _attacks.combinator_submenu(_attack_ctx())


def adhoc_mask_crack():
    return _attacks.adhoc_mask_crack(_attack_ctx())


def markov_brute_force():
    return _attacks.markov_brute_force(_attack_ctx())


def bandrel_method():
    return _attacks.bandrel_method(_attack_ctx())


def loopback_attack():
    return _attacks.loopback_attack(_attack_ctx())


def ollama_attack():
    return _attacks.ollama_attack(_attack_ctx())


def omen_attack():
    return _attacks.omen_attack(_attack_ctx())


def combipow_crack():
    return _attacks.combipow_crack(_attack_ctx())


def generate_rules_crack():
    return _attacks.generate_rules_crack(_attack_ctx())


def permute_crack():
    return _attacks.permute_crack(_attack_ctx())


def pcfg_attack():
    return _attacks.pcfg_attack(_attack_ctx())


def prince_ling_attack():
    return _attacks.prince_ling_attack(_attack_ctx())


def spoonman_attack():
    return _attacks.spoonman_attack(_attack_ctx())


def rosetta_attack():
    return _attacks.rosetta_attack(_attack_ctx())


def wordlist_filter_len(infile: str, outfile: str, min_len: int, max_len: int) -> bool:
    """Filter wordlist keeping only words between min_len and max_len (inclusive)."""
    len_bin = os.path.join(hate_path, "hashcat-utils/bin/len.bin")
    with open(infile, "rb") as fin, open(outfile, "wb") as fout:
        result = subprocess.run(
            [len_bin, str(min_len), str(max_len)], stdin=fin, stdout=fout
        )
    return result.returncode == 0


def wordlist_filter_req_include(infile: str, outfile: str, mask: int) -> bool:
    """Filter wordlist keeping only words that include all char classes in mask."""
    req_bin = os.path.join(hate_path, "hashcat-utils/bin/req-include.bin")
    with open(infile, "rb") as fin, open(outfile, "wb") as fout:
        result = subprocess.run([req_bin, str(mask)], stdin=fin, stdout=fout)
    return result.returncode == 0


def wordlist_filter_req_exclude(infile: str, outfile: str, mask: int) -> bool:
    """Filter wordlist removing words that contain any char class in mask."""
    req_bin = os.path.join(hate_path, "hashcat-utils/bin/req-exclude.bin")
    with open(infile, "rb") as fin, open(outfile, "wb") as fout:
        result = subprocess.run([req_bin, str(mask)], stdin=fin, stdout=fout)
    return result.returncode == 0


def wordlist_cutb(infile: str, outfile: str, offset: int, length: int | None) -> bool:
    """Extract a substring from each word starting at offset, optionally limited to length bytes."""
    cutb_bin = os.path.join(hate_path, "hashcat-utils/bin/cutb.bin")
    cmd = [cutb_bin, str(offset)]
    if length is not None:
        cmd.append(str(length))
    with open(infile, "rb") as fin, open(outfile, "wb") as fout:
        result = subprocess.run(cmd, stdin=fin, stdout=fout)
    return result.returncode == 0


def wordlist_splitlen(infile: str, outdir: str) -> bool:
    """Split wordlist into per-length files in outdir."""
    splitlen_bin = os.path.join(hate_path, "hashcat-utils/bin/splitlen.bin")
    with open(infile, "rb") as fin:
        result = subprocess.run([splitlen_bin, outdir], stdin=fin)
    return result.returncode == 0


def wordlist_subtract(infile: str, outfile: str, *remove_files: str) -> bool:
    """Remove lines from infile that appear in any of remove_files, write to outfile."""
    rli_bin = os.path.join(hate_path, "hashcat-utils/bin/rli.bin")
    result = subprocess.run([rli_bin, infile, outfile, *remove_files])
    return result.returncode == 0


def wordlist_subtract_single(infile: str, remove_file: str, outfile: str) -> bool:
    """Subtract remove_file from infile, writing result to stdout captured in outfile."""
    rli2_bin = os.path.join(hate_path, "hashcat-utils/bin/rli2.bin")
    with open(outfile, "wb") as fout:
        result = subprocess.run([rli2_bin, infile, remove_file], stdout=fout)
    return result.returncode == 0


def wordlist_gate(infile: str, outfile: str, mod: int, offset: int) -> bool:
    """Shard wordlist: keep every mod-th line starting at offset."""
    gate_bin = os.path.join(hate_path, "hashcat-utils/bin/gate.bin")
    with open(infile, "rb") as fin, open(outfile, "wb") as fout:
        result = subprocess.run(
            [gate_bin, str(mod), str(offset)], stdin=fin, stdout=fout
        )
    return result.returncode == 0


def _outdir_is_empty(outdir):
    """Does *outdir* hold no split output yet?

    Dot-files do not count. `not os.listdir(outdir)` is False as soon as macOS
    drops a .DS_Store in there, which sent the first wordlist down the merge
    path against an effectively empty directory.

    A missing or non-directory path really is "empty" (there is nothing to
    merge with), so those cases return `True`. A `PermissionError` is
    different: a directory that is write+execute but not readable (mode
    `0333`) still lets files get created inside it even though listing it
    raises. Reporting `True` ("empty") there would send every wordlist down
    the caller's first-wordlist branch (write straight into outdir) instead
    of the merge branch, silently overwriting earlier per-length output.
    Returning `False` forces the merge branch instead, which only stats and
    reads/writes specific filenames and works fine without read access to the
    directory listing.
    """
    try:
        return not [name for name in os.listdir(outdir) if not name.startswith(".")]
    except PermissionError:
        return False
    except (FileNotFoundError, NotADirectoryError):
        return True


def wordlist_optimize(input_wordlists: list[str], outdir: str) -> bool:
    """Consolidate wordlists into per-length deduplicated files in outdir."""
    os.makedirs(outdir, exist_ok=True)
    for wl in input_wordlists:
        if not os.path.isfile(wl):
            print(f"[!] Skipping missing wordlist: {wl}")
            continue
        if _outdir_is_empty(outdir):
            if not wordlist_splitlen(wl, outdir):
                return False
            continue
        with tempfile.TemporaryDirectory(prefix="hc_optimize_") as tmp:
            if not wordlist_splitlen(wl, tmp):
                return False
            for fname in os.listdir(tmp):
                src = os.path.join(tmp, fname)
                dst = os.path.join(outdir, fname)
                if not os.path.isfile(dst):
                    shutil.copyfile(src, dst)
                    continue
                with tempfile.NamedTemporaryFile(
                    delete=False, prefix="hc_optimize_", suffix=".out"
                ) as out_fh:
                    out_path = out_fh.name
                try:
                    if not wordlist_subtract(src, out_path, dst):
                        return False
                    if os.path.getsize(out_path) > 0:
                        with open(dst, "ab") as df, open(out_path, "rb") as sf:
                            df.write(sf.read())
                finally:
                    if os.path.isfile(out_path):
                        os.remove(out_path)
    return True


def wordlist_tools_submenu():
    return _attacks.wordlist_tools_submenu(_attack_ctx())


def rules_cleanup(infile: str, outfile: str, mode: int = 2) -> bool:
    """Clean a rule file using cleanup-rules.bin. Returns True on success.

    cleanup-rules.bin requires a ``mode`` argument (1 = CPU, 2 = GPU) and exits
    with usage text if it is omitted. Defaults to GPU (2), which strips rules
    hashcat cannot run on the GPU.
    """
    cleanup_path = os.path.join(hate_path, "hashcat-utils", "bin", "cleanup-rules.bin")
    with open(infile, "rb") as fin, open(outfile, "wb") as fout:
        result = subprocess.run([cleanup_path, str(mode)], stdin=fin, stdout=fout)
    return result.returncode == 0


def rules_optimize(infile: str, outfile: str) -> bool:
    """Optimize a rule file using rules_optimize.bin. Returns True on success."""
    optimize_path = os.path.join(
        hate_path, "hashcat-utils", "bin", "rules_optimize.bin"
    )
    with open(infile, "rb") as fin, open(outfile, "wb") as fout:
        result = subprocess.run([optimize_path], stdin=fin, stdout=fout)
    return result.returncode == 0


def rule_tools_submenu():
    return _attacks.rule_tools_submenu(_attack_ctx())


def coverage_submenu():
    """Submenu for the per-target coverage store (main-menu option 83).

    The inline ``interactive_menu`` import mirrors ``notifications_submenu``
    below: re-importing per call lets tests patch the real menu function.
    """
    from hate_crack.menu import interactive_menu

    if not hcatHashFile:
        print("\n[!] Load a hash file first.")
        return

    while True:
        items = [
            ("1", "Show coverage for this hash file"),
            ("2", "Show run history for this hash file"),
            ("3", "Forget all coverage for this hash file"),
            ("99", "Back to main menu"),
        ]
        choice = interactive_menu(items, title="\nAttack Coverage:")
        if choice in (None, "99"):
            return
        if choice == "1":
            print()
            print(_coverage_report(hcatHashFile))
        elif choice == "2":
            print()
            print(_coverage_history_report(hcatHashFile))
        elif choice == "3":
            print()
            print(_coverage_report(hcatHashFile))
            answer = input("\n[?] Drop all of this and start over? [y/N]: ").strip()
            if answer.lower() in ("y", "yes"):
                print(_coverage_forget(hcatHashFile))
            else:
                print("Left unchanged.")


def notifications_submenu():
    """Submenu for all Pushover notification controls (main-menu option 82).

    The inline ``interactive_menu`` import is not redundant with the
    module-scope import at the top of this file: re-importing inside the
    function re-reads ``hate_crack.menu.interactive_menu`` on every call,
    which lets tests patch the real menu function via
    ``monkeypatch.setattr(hate_crack.menu, "interactive_menu", ...)``.
    Removing it breaks test isolation.
    """
    from hate_crack.menu import interactive_menu

    while True:
        settings = _notify.get_settings()
        global_label = "ON" if settings.enabled else "OFF"
        per_crack_label = "ON" if settings.per_crack_enabled else "OFF"
        items = [
            ("1", f"Toggle Pushover Notifications [{global_label}]"),
            ("2", f"Toggle Per-Crack Notifications [{per_crack_label}]"),
            ("3", "Send Test Pushover Notification"),
            ("99", "Back to Main Menu"),
        ]
        choice = interactive_menu(items, title="\nNotifications:")
        if choice is None or choice == "99":
            break
        if choice == "1":
            toggle_notifications()
        elif choice == "2":
            toggle_per_crack_notifications()
        elif choice == "3":
            test_pushover_notification()


# convert hex words for recycling
def convert_hex(working_file):
    processed_words = []
    regex = r"^\$HEX\[(\S+)\]"
    with open(working_file, "r") as f:
        for line in f:
            match = re.search(regex, line.rstrip("\n"))
            if match:
                # latin-1, not iso-8859-9: matches the byte-preserving convention
                # the rest of the codebase already uses (see
                # hate_crack.plaintext.decode_hex_wrapper) -- one raw byte maps
                # to one character, which callers that write these characters
                # back out to a hashcat-facing file (e.g. hcatSmartMask's
                # .hcmask) must re-encode with the same codec to round-trip
                # the original bytes exactly.
                processed_words.append(
                    binascii.unhexlify(match.group(1)).decode("latin-1")
                )
            else:
                processed_words.append(line.rstrip("\n"))

    return processed_words


# Display Cracked Hashes
def show_results():
    if os.path.isfile(hcatHashFile + ".out"):
        with open(hcatHashFile + ".out") as hcatOutput:
            for cracked_hash in hcatOutput:
                print(cracked_hash.strip())
    else:
        print("No hashes were cracked :(")


# Analyze Hashes with Pipal
def pipal():
    hcatHashFilePipal = hcatHashFile
    # Both halves of the condition matter, and cleanup() has always had both:
    # the merge is pwdump-only, and running it on a plain hash list used to
    # truncate the cracked output (issues #195, #196).
    if hcatHashType == "1000" and pwdump_format:
        combine_ntlm_output()
        hcatHashFilePipal = hcatHashFileOrig

    if os.path.isfile(pipalPath):
        if os.path.isfile(hcatHashFilePipal + ".out"):
            pipalFile = open(hcatHashFilePipal + ".passwords", "w")
            with open(hcatHashFilePipal + ".out") as hcatOutput:
                for cracked_hash in hcatOutput:
                    password = cracked_hash.split(":")
                    clearTextPass = password[-1]
                    match = re.search(r"^\$HEX\[(\S+)\]", clearTextPass)
                    if match:
                        clearTextPass = binascii.unhexlify(match.group(1)).decode(
                            "iso-8859-9"
                        )
                    if not clearTextPass.endswith("\n"):
                        clearTextPass += "\n"
                    pipalFile.write(clearTextPass)
                pipalFile.close()

            if os.path.getsize(hcatHashFilePipal + ".passwords") == 0:
                print(
                    "\n[!] No cracked passwords to analyse; Pipal would report "
                    "zero entries. Crack some hashes first."
                )
                return None

            # List-form Popen (no shell=True) so paths/filenames containing
            # shell metacharacters can't be interpreted as commands. shlex.split
            # on pipalPath still allows an interpreter prefix (e.g. "ruby
            # /opt/pipal/pipal.rb") to be configured.
            pipal_cmd = shlex.split(pipalPath) + [
                hcatHashFilePipal + ".passwords",
                "-t",
                str(pipal_count),
                "--output",
                hcatHashFilePipal + ".pipal",
            ]
            pipalProcess = subprocess.Popen(pipal_cmd)
            try:
                pipalProcess.wait()
            except KeyboardInterrupt:
                print("Killing PID {0}...".format(str(pipalProcess.pid)))
                pipalProcess.kill()
            print("Pipal file is at " + hcatHashFilePipal + ".pipal\n")
            import sys

            if not sys.stdin.isatty():
                view_choice = "y"
            else:
                view_choice = (
                    input("Would you like to view (cat) the pipal output? (Y/n): ")
                    .strip()
                    .lower()
                )
            if view_choice in ("", "y", "yes"):
                print("\n--- Pipal Output Start ---\n")
                with open(hcatHashFilePipal + ".pipal") as pipalfile:
                    print(pipalfile.read())
                print("\n--- Pipal Output End ---\n")
            with open(hcatHashFilePipal + ".pipal") as pipalfile:
                pipal_content = pipalfile.read()
                # Parse the "Top N base words" section line by line rather than
                # with one rigid regex.  The old approach required *exactly*
                # pipal_count baseword lines, so any cracked set with fewer
                # unique base words than pipal_count (the common case on small
                # cracks) matched nothing and returned []. Collect up to
                # pipal_count base words and stop at the end of the section.
                top_basewords = []
                in_section = False
                for line in pipal_content.splitlines():
                    if re.match(r"\s*Top\s+[0-9]+\s+base words", line):
                        in_section = True
                        continue
                    if in_section:
                        if not line.strip():
                            # blank line terminates the base words section
                            break
                        # Capture the base word (first token); tolerate both
                        # "word = 5 (5%)" and "word 5" separators.
                        match = re.match(r"\s*(\S+)", line)
                        if match:
                            top_basewords.append(match.group(1))
                            if len(top_basewords) >= pipal_count:
                                break
                return top_basewords
        else:
            print("No hashes were cracked :(")
            return []
    else:
        print(
            "The path to pipal.rb is either not set, or is incorrect. "
            "Set PIPAL_PATH in the .env file."
        )
        return


# Exports output to excel file
def export_excel():
    # Check for openyxl dependancy for export
    try:
        import openpyxl
    except ImportError:
        sys.stderr.write(
            "You must install openpyxl first using 'pip install openpyxl' or 'pip3 install openpyxl'\n"
        )
        return

    # Same guard as cleanup() and pipal(): the merge, and the pwdump-shaped
    # rows this export builds, both require pwdump format. Without the second
    # half, a plain hash list had its cracked output truncated and then got an
    # empty spreadsheet reported as a success (issues #195, #196).
    if hcatHashType == "1000" and pwdump_format:
        combine_ntlm_output()
        output = openpyxl.Workbook()
        current_ws = output.create_sheet(title="hate_crack output", index=0)
        current_row = 2
        current_ws["A1"] = "Username"
        current_ws["B1"] = "SID"
        current_ws["C1"] = "LM Hash"
        current_ws["D1"] = "NTLM Hash"
        current_ws["E1"] = "Clear-Text Password"
        with open(hcatHashFileOrig + ".out") as input_file:
            for line in input_file:
                matches = re.match(
                    r"(^[^:]+):([0-9]+):([a-z0-9A-Z]{32}):([a-z0-9A-Z]{32}):::(.*)",
                    line.rstrip("\r\n"),
                )
                if not matches:
                    continue
                username = matches.group(1)
                sid = matches.group(2)
                lm = matches.group(3)
                ntlm = matches.group(4)
                try:
                    clear_text = matches.group(5)
                    match = re.search(r"^\$HEX\[(\S+)\]", clear_text)
                    if match:
                        clear_text = binascii.unhexlify(match.group(1)).decode(
                            "iso-8859-9"
                        )
                except Exception:
                    clear_text = ""
                current_ws["A" + str(current_row)] = username
                current_ws["B" + str(current_row)] = sid
                current_ws["C" + str(current_row)] = lm
                current_ws["D" + str(current_row)] = ntlm
                current_ws["E" + str(current_row)] = clear_text
                current_row += 1
            output.save(hcatHashFile + ".xlsx")
            print("Output exported succesfully to {0}".format(hcatHashFile + ".xlsx"))
    else:
        sys.stderr.write(
            "Excel export is only supported for NTLM hashes in pwdump format "
            "(user:rid:lm:nt:::). Nothing was written.\n"
        )
        return


# Show README
def show_readme():
    with open(hate_path + "/readme.md") as hcatReadme:
        print(hcatReadme.read())


# Analyze Hashcat Rules
def analyze_rules():
    """Analyze hashcat rule file and display opcode statistics."""
    if display_rule_opcodes_summary is None:
        print("\nError: HashcatRosetta formatting module not found.")
        print(rosetta_unavailable_reason())
        return

    print("\n" + "=" * 60)
    print("Rule Opcode Analyzer")
    print("=" * 60)

    # Get rule file path from user with tab completion
    rule_file = select_file_with_autocomplete("Enter path to rule file")

    if not rule_file:
        print("No rule file specified.")
        return

    if not os.path.isfile(rule_file):
        print(f"Error: Rule file not found: {rule_file}")
        return

    try:
        display_rule_opcodes_summary(rule_file)
        print()
    except Exception as e:
        print(f"Error analyzing rule file: {e}")


# Exit Program
def quit_hc():
    cleanup()
    sys.exit(0)


def toggle_notifications():
    """Global on/off toggle for Pushover notifications.

    Flips ``notify_enabled`` in the active settings and persists to
    ``config.json``.  Prints the new state so the user has immediate
    confirmation even though the menu label will also refresh on the
    next render.
    """
    new_state = _notify.toggle_enabled()
    label = "ON" if new_state else "OFF"
    print(f"\nPushover notifications are now {label}.")
    if new_state:
        settings = _notify.get_settings()
        if not settings.pushover_token or not settings.pushover_user:
            print(
                "[!] NOTIFY_PUSHOVER_TOKEN / NOTIFY_PUSHOVER_USER are empty in "
                "the .env file — notifications will silently no-op until set."
            )


def toggle_per_crack_notifications():
    """Runtime toggle for ``notify_per_crack_enabled`` with a UI-level guard.

    Per-crack notifications require global notifications to be ON in order
    to fire (see ``notify.start_tailer``).  Turning per-crack ON while the
    global switch is OFF is silently ineffective, which surprises users —
    so we refuse the transition and point them at the global toggle.

    Turning per-crack OFF is always allowed, regardless of the global
    state, so users can clean up an inconsistent config without friction.
    """
    settings = _notify.get_settings()
    if not settings.per_crack_enabled and not settings.enabled:
        print(
            "\n[!] Global Pushover notifications are OFF. Enable option 1 "
            "(Toggle Pushover Notifications) first."
        )
        return
    new_state = _notify.toggle_per_crack_enabled()
    label = "ON" if new_state else "OFF"
    print(f"\nPer-crack notifications are now {label}.")


def test_pushover_notification():
    """Send a canned test notification so the user can verify Pushover works.

    Ignores the global ``notify_enabled`` toggle on purpose: the point of the
    test is to confirm the wire is live, independent of whether attacks are
    currently wired to notify.  When the global toggle is OFF we still send
    but print a note so the user is not surprised later.
    """
    settings = _notify.get_settings()
    token = settings.pushover_token
    user = settings.pushover_user
    if not token or not user:
        print(
            "\n[!] Pushover credentials missing. Set NOTIFY_PUSHOVER_TOKEN "
            "and NOTIFY_PUSHOVER_USER in the .env file."
        )
        return

    if not settings.enabled:
        print("\n(notifications are globally OFF, but sending test anyway)")

    title = "hate_crack: test notification"
    message = (
        "This is a test notification from hate_crack. "
        "If you see this, Pushover is wired up correctly."
    )
    ok = _notify._send_pushover(token, user, title, message)
    if ok:
        print("[+] Test Pushover notification sent. Check your device.")
    else:
        print("[!] Test Pushover notification failed. See log output for details.")


def get_main_menu_items():
    """Return ordered (key, label) pairs for the main menu."""
    items = [
        ("1", "Quick Crack"),
        ("2", "Extensive Pure_Hate Methodology Crack"),
        ("3", "Brute Force Attack"),
        ("4", "Top Mask Attack"),
        ("5", "Fingerprint Attack"),
        ("6", "Combinator Attacks"),
        ("7", "Hybrid Attack"),
        ("8", "Pathwell Top 100 Mask Brute Force Crack"),
        ("9", "PRINCE Attack"),
        ("10", "Bandrel Methodology"),
        ("11", "Loopback Attack"),
        ("12", "LLM Attack"),
        ("13", "OMEN Attack"),
        ("14", "Ad-hoc Mask Attack"),
        ("15", "Markov Brute Force Attack"),
        ("16", "N-gram Attack"),
        ("17", "Permutation Attack"),
        ("18", "Random Rules Attack"),
        ("19", "Combipow Passphrase Attack"),
        ("20", "PCFG Attack"),
        ("21", "PRINCE-LING Attack"),
        ("22", "Spoonman Attack"),
        ("23", "Rosetta Attack"),
        ("24", "Corporate Masks Brute Force"),
        ("25", "Smart Mask Attack"),
        ("80", "Wordlist Tools"),
        ("81", "Rule File Tools"),
        ("82", "Notifications"),
        ("85", "Attack Coverage"),
        ("93", "Regenerate .out from POT file"),
    ]
    if hashview_api_key:
        items.append(("94", "Hashview API"))
    items.extend(
        [
            ("95", "Analyze hashes with Pipal"),
            ("96", "Export Output to Excel Format"),
            ("97", "Display Cracked Hashes"),
            ("98", "Display README"),
            ("99", "Quit"),
        ]
    )
    return items


def get_main_menu_options():
    """Return the mapping of main menu keys to their handler functions."""
    options = {
        "1": quick_crack,
        "2": extensive_crack,
        "3": brute_force_crack,
        "4": top_mask_crack,
        "5": fingerprint_crack,
        "6": combinator_submenu,
        "7": hybrid_crack,
        "8": pathwell_crack,
        "9": prince_attack,
        "10": bandrel_method,
        "11": loopback_attack,
        "12": ollama_attack,
        "13": omen_attack,
        "14": adhoc_mask_crack,
        "15": markov_brute_force,
        "16": ngram_attack,
        "17": permute_crack,
        "18": generate_rules_crack,
        "19": combipow_crack,
        "20": pcfg_attack,
        "21": prince_ling_attack,
        "22": spoonman_attack,
        "23": rosetta_attack,
        "24": corporate_masks_crack,
        "25": smart_mask_crack,
        "80": wordlist_tools_submenu,
        "81": rule_tools_submenu,
        "82": notifications_submenu,
        "85": coverage_submenu,
        "93": restore_potfile_output,
        "95": pipal,
        "96": export_excel,
        "97": show_results,
        "98": show_readme,
        "99": quit_hc,
    }
    # Only show this when Hashview API is configured (requested behavior).
    if hashview_api_key:
        options["94"] = hashview_api
    return options


# The Main Guts
def main():
    global pwdump_format
    global hcatHashFile
    global hcatHashType
    global hcatHashFileOrig
    global lmHashesFound
    global debug_mode
    global non_interactive
    global hashview_url, hashview_api_key
    global hcatPath, hcatBin, hcatWordlists, hcatOptimizedWordlists, rulesDirectory
    global pipalPath, maxruntime, bandrelbasewords
    global hcatPotfilePath

    signal.signal(signal.SIGINT, _sigint_handler)

    # Initialize global variables
    hcatHashFile = None
    non_interactive = False
    hcatHashType = None
    hcatHashFileOrig = None

    def _build_parser(include_positional, include_subcommands):
        parser = argparse.ArgumentParser(
            prog="hate_crack",
            description="hate_crack - Hashcat automation and wordlist management tool",
        )
        if include_positional:
            parser.add_argument(
                "hashfile",
                nargs="?",
                default=None,
                help="Path to hash file to crack (positional, optional)",
            )
            parser.add_argument(
                "hashtype",
                nargs="?",
                default=None,
                help="Hashcat hash type (e.g., 1000 for NTLM) (positional, optional)",
            )
        parser.add_argument(
            "--download-hashview",
            action="store_true",
            help="Download hashes from Hashview (legacy menu)",
        )
        parser.add_argument(
            "--hashview",
            action="store_true",
            help="Jump directly to Hashview customer/hashfile menu",
        )
        parser.add_argument(
            "--download-torrent",
            metavar="FILENAME",
            help="Download a specific Weakpass torrent file",
        )
        parser.add_argument(
            "--download-all-torrents",
            action="store_true",
            help="Download all available Weakpass torrents from cache",
        )
        parser.add_argument(
            "--weakpass", action="store_true", help="Download wordlists from Weakpass"
        )
        parser.add_argument(
            "--rank",
            type=int,
            default=None,
            help=(
                "Only show wordlists with this rank (use 0 to show all, -1 for "
                "the built-in >4 rule). Overrides `weakpass_min_rank` in "
                "config.json for this run; defaults to that key (-1) when omitted."
            ),
        )
        parser.add_argument(
            "--hashmob", action="store_true", help="Download wordlists from Hashmob.net"
        )
        parser.add_argument(
            "--rules", action="store_true", help="Download rules from Hashmob.net"
        )
        parser.add_argument(
            "--cleanup",
            action="store_true",
            help="Cleanup .out files, torrents, and extract or remove .7z archives",
        )
        parser.add_argument(
            "--update",
            action="store_true",
            help="Update to the latest release from main and reinstall",
        )
        parser.add_argument(
            "--nightly",
            action=argparse.BooleanOptionalAction,
            default=None,
            help=(
                "Update to the latest nightly from nightly-dev instead of main. "
                "Nightlies have passed CI but are not part of a cut release. "
                "Overrides `update_channel` in config.json for this run; --no-nightly "
                "forces the main channel even when config.json selects nightly-dev."
            ),
        )
        parser.add_argument(
            "--no-optimized-kernel",
            "--no-optimize",
            dest="no_optimized_kernel",
            action="store_true",
            help=(
                "Never pass -O to hashcat, for every attack this run. Overrides "
                "`optimizedKernelAttacks` in config.json and drops any -O in "
                "hcatTuning. Use when a candidate exceeds the password or salt "
                "length ceiling the optimized kernels impose."
            ),
        )
        parser.add_argument(
            "--debug",
            action=argparse.BooleanOptionalAction,
            default=None,
            help=(
                "Enable debug mode. Overrides `debug` in config.json for this run; "
                "--no-debug forces it off even when config.json enables it."
            ),
        )
        parser.add_argument(
            "--potfile-path",
            dest="potfile_path",
            default=None,
            help=(
                "Override hashcat potfile path (equivalent to hashcat --potfile-path). "
                "Overrides `hcatPotfilePath` in config.json for this run. Use empty string "
                "to disable overriding and use hashcat's built-in default, or 'auto' to "
                "track whatever per-user potfile the installed hashcat uses."
            ),
        )
        parser.add_argument(
            "--migrate-hashcat-home",
            dest="migrate_hashcat_home",
            action="store_true",
            help=(
                "Copy the contents of the legacy ~/.hashcat directory into the "
                "location hashcat 7+ uses, then exit. Never overwrites or deletes: "
                "a colliding name is copied as <name>.from-legacy, and removing the "
                "old directory is left to you."
            ),
        )
        parser.add_argument(
            "--restore-potfile",
            dest="restore_potfile",
            action=argparse.BooleanOptionalAction,
            default=None,
            help=(
                "Rebuild <hashfile>.out from the POT file at startup, replacing "
                "any existing contents, then continue as normal. Overrides "
                "`restore_potfile_on_start` in config.json for this run; "
                "--no-restore-potfile forces it off even when config.json enables it."
            ),
        )
        parser.add_argument(
            "--no-potfile-path",
            dest="no_potfile_path",
            action="store_true",
            help="Do not pass --potfile-path to hashcat (use hashcat's built-in default).",
        )
        parser.add_argument(
            "--rule-debug-mode",
            dest="rule_debug_mode",
            action=argparse.BooleanOptionalAction,
            default=None,
            help=(
                "Have every rule-based attack pass --debug-mode/--debug-file to "
                "hashcat, so the Rosetta Attack can mine which rules/wordlists "
                "cracked what. Overrides `rule_debug_mode_enabled` in config.json "
                "for this run; --no-rule-debug-mode stops hate_crack from adding "
                "those flags at all -- unrelated to --debug/--no-debug, which "
                "only controls hate_crack's own verbose logging."
            ),
        )
        parser.add_argument(
            "--exit-code-on-skip",
            dest="exit_code_on_skip",
            action="store_true",
            help=(
                "In a scripted run, exit 3 when coverage skipped every pass of "
                "the attack and nothing was launched. Off by default so that "
                "enabling coverage does not start failing existing harnesses."
            ),
        )
        parser.add_argument(
            "--coverage",
            dest="coverage",
            action=argparse.BooleanOptionalAction,
            default=None,
            help=(
                "Track which rules, masks and wordlists have already been run "
                "against this hash file, and offer to skip them on a later "
                "attack. Overrides `coverage_enabled` in config.json for this "
                "run; --no-coverage neither consults nor updates the store."
            ),
        )
        hashview_parser = None
        if not include_subcommands:
            return parser, hashview_parser

        subparsers = parser.add_subparsers(dest="command")
        _noninteractive.add_attack_subparsers(subparsers)

        coverage_parser = subparsers.add_parser(
            "coverage",
            help="Inspect or reset per-target attack coverage",
        )
        coverage_subparsers = coverage_parser.add_subparsers(dest="coverage_command")
        for name, blurb in (
            ("status", "Show what has already been run against a hash file"),
            ("history", "List every attack run against a hash file"),
            ("forget", "Drop all coverage for a hash file so it can be re-attacked"),
        ):
            sub = coverage_subparsers.add_parser(name, help=blurb)
            sub.add_argument(
                "--hashfile",
                required=True,
                help="Hash file whose coverage to act on (identified by content)",
            )
            if name == "forget":
                sub.add_argument(
                    "--yes",
                    action="store_true",
                    help="Skip the confirmation prompt",
                )

        hashview_parser = subparsers.add_parser(
            "hashview", help="Hashview menu actions"
        )
        hashview_subparsers = hashview_parser.add_subparsers(dest="hashview_command")

        hv_upload_cracked = hashview_subparsers.add_parser(
            "upload-cracked",
            help="Upload cracked hashes from a file",
        )
        hv_upload_cracked.add_argument(
            "--file", required=True, help="Path to cracked hashes file (.out format)"
        )
        hv_upload_cracked.add_argument(
            "--hash-type", default="1000", help="Hash type (default: 1000)"
        )

        hv_upload_wordlist = hashview_subparsers.add_parser(
            "upload-wordlist",
            help="Upload a wordlist file",
        )
        hv_upload_wordlist.add_argument(
            "--file", required=True, help="Path to wordlist file"
        )
        hv_upload_wordlist.add_argument(
            "--name", default=None, help="Wordlist name (default: filename)"
        )

        hv_download_left = hashview_subparsers.add_parser(
            "download-hashes",
            help="Download left hashes and append found hashes to potfile",
        )
        hv_download_left.add_argument(
            "--customer-id", required=True, type=int, help="Customer ID"
        )
        hv_download_left.add_argument(
            "--hashfile-id", required=True, type=int, help="Hashfile ID"
        )

        hv_download_rules = hashview_subparsers.add_parser(
            "download-rules",
            help="Download a rule file",
        )
        hv_download_rules.add_argument(
            "--rules-id", required=True, type=int, help="Rule ID"
        )
        hv_download_rules.add_argument(
            "--output",
            default=None,
            help="Output file name (default: rule_<id>.rule in the rules directory)",
        )

        hv_upload_hashfile_job = hashview_subparsers.add_parser(
            "upload-hashfile-job",
            help="Upload a hashfile and create a job",
        )
        hv_upload_hashfile_job.add_argument(
            "--file", required=True, help="Path to hashfile"
        )
        hv_upload_hashfile_job.add_argument(
            "--customer-id", required=True, type=int, help="Customer ID"
        )
        hv_upload_hashfile_job.add_argument(
            "--hash-type", required=True, type=int, help="Hash type (e.g., 1000)"
        )
        hv_upload_hashfile_job.add_argument(
            "--file-format", default=5, type=int, help="File format (default: 5)"
        )
        hv_upload_hashfile_job.add_argument(
            "--hashfile-name", default=None, help="Hashfile name (default: filename)"
        )
        hv_upload_hashfile_job.add_argument(
            "--job-name", required=True, help="Job name"
        )
        hv_upload_hashfile_job.add_argument(
            "--limit-recovered",
            action="store_true",
            help="Limit to recovered hashes only",
        )
        return parser, hashview_parser

    # Removed add_common_args(parser) since config items are now only set via config file
    argv = sys.argv[1:]

    hashview_subcommands = [
        "upload-cracked",
        "upload-wordlist",
        "download-hashes",
        "download-rules",
        "upload-hashfile-job",
    ]
    has_hashview_flag = "--hashview" in argv
    has_hashview_subcommand = any(cmd in argv for cmd in hashview_subcommands)

    # Handle custom help for --hashview (without subcommand)
    if (
        has_hashview_flag
        and not has_hashview_subcommand
        and ("--help" in argv or "-h" in argv)
    ):
        # Build the full parser to get hashview help
        temp_parser, hashview_parser = _build_parser(
            include_positional=False,
            include_subcommands=True,
        )
        if hashview_parser:
            hashview_parser.print_help()
        sys.exit(0)

    # If --hashview flag is used with a subcommand, convert to subcommand format for parser
    if has_hashview_flag and has_hashview_subcommand:
        # Remove --hashview flag and insert "hashview" as subcommand
        argv_temp = [arg for arg in argv if arg != "--hashview"]
        # Find the first hashview subcommand and insert "hashview" before it
        for i, arg in enumerate(argv_temp):
            if arg in hashview_subcommands:
                argv = argv_temp[:i] + ["hashview"] + argv_temp[i:]
                break
        else:
            argv = argv_temp  # Fallback if subcommand not found

    has_attack_subcommand = any(arg in _noninteractive.ATTACK_COMMANDS for arg in argv)
    use_subcommand_parser = (
        "hashview" in argv or "coverage" in argv or has_attack_subcommand
    )
    parser, hashview_parser = _build_parser(
        include_positional=not use_subcommand_parser,
        include_subcommands=use_subcommand_parser,
    )
    args = parser.parse_args(argv)

    if getattr(args, "command", None) in _noninteractive.ATTACK_COMMANDS:
        non_interactive = True

    # Seven flags are per-run overrides of schema-backed keys; resolve_flag_overrides
    # layers the flag (when present) on top of what the loader already merged
    # from os.environ, the key's own home file (config.json for all seven) and
    # the schema default.
    flags = resolve_flag_overrides(
        args,
        config_parser,
        base_dir=hate_path,
        current_potfile_path=hcatPotfilePath,
        hcat_bin=hcatBin,
    )

    global debug_mode, _rule_debug_mode_enabled, _coverage_enabled
    debug_mode = flags.debug
    _rule_debug_mode_enabled = flags.rule_debug_mode_enabled
    _coverage_enabled = flags.coverage_enabled
    if flags.optimized_kernel_disabled:
        disable_optimized_kernel()
        print("[*] Optimized kernels (-O) disabled for this run")
    hcatPotfilePath = flags.potfile_path

    setup_logging(logger, hate_path, debug_mode)

    from types import SimpleNamespace

    config = SimpleNamespace(
        hashview_url=hashview_url,
        hashview_api_key=hashview_api_key,
        hcatPath=hcatPath,
        hcatBin=hcatBin,
        hcatWordlists=hcatWordlists,
        hcatOptimizedWordlists=hcatOptimizedWordlists,
        rules_directory=rulesDirectory,
        pipalPath=pipalPath,
        maxruntime=maxruntime,
        bandrelbasewords=bandrelbasewords,
    )

    hashview_url = config.hashview_url
    hashview_api_key = config.hashview_api_key
    hcatPath = config.hcatPath
    hcatBin = config.hcatBin
    hcatWordlists = config.hcatWordlists
    hcatOptimizedWordlists = config.hcatOptimizedWordlists
    rulesDirectory = config.rules_directory
    pipalPath = config.pipalPath
    maxruntime = config.maxruntime
    bandrelbasewords = config.bandrelbasewords

    if getattr(args, "migrate_hashcat_home", False):
        _run_hashcat_home_migration(hcat_bin=hcatBin)
        sys.exit(0)

    _warn_stale_hashcat_home(hcat_bin=hcatBin)

    if args.update or args.nightly:
        # --nightly implies the upgrade action, so `--nightly` alone works and
        # `--update --nightly` reads as "update, to the nightly channel".
        # Note the trigger is still an explicit flag: `update_channel` in config.json
        # selects *which* channel an upgrade uses, it never starts one.
        _run_upgrade(branch=flags.update_channel)

    if args.download_torrent:
        download_weakpass_torrent(
            download_torrent=download_torrent_file,
            filename=args.download_torrent,
            print_fn=print,
        )
        sys.exit(0)

    if getattr(args, "command", None) == "coverage":
        sys.exit(_run_coverage_command(args))

    if getattr(args, "command", None) == "hashview":
        if not hashview_api_key:
            print("\nError: Hashview API key not configured.")
            print("Please set HASHVIEW_API_KEY in the .env file")
            sys.exit(1)

        api_harness = HashviewAPI(hashview_url, hashview_api_key, debug=debug_mode)

        if args.hashview_command == "upload-cracked":
            cracked_file = resolve_path(args.file)
            if not cracked_file or not os.path.isfile(cracked_file):
                print(f"✗ Error: File not found: {args.file}")
                sys.exit(1)
            result = api_harness.upload_cracked_hashes(
                cracked_file, hash_type=args.hash_type
            )
            print(f"\n✓ Success: {result.get('msg', 'Cracked hashes uploaded')}")
            if "count" in result:
                print(f"  Imported: {result['count']} hashes")
            if result.get("skipped_cached"):
                print(
                    f"  Skipped: {result['skipped_cached']} already uploaded previously"
                )
            sys.exit(0)

        if args.hashview_command == "upload-wordlist":
            wordlist_path = resolve_path(args.file)
            if not wordlist_path or not os.path.isfile(wordlist_path):
                print(f"✗ Error: File not found: {args.file}")
                sys.exit(1)
            result = api_harness.upload_wordlist_file(wordlist_path, args.name)
            print(f"\n✓ Success: {result.get('msg', 'Wordlist uploaded')}")
            if "wordlist_id" in result:
                print(f"  Wordlist ID: {result['wordlist_id']}")
            sys.exit(0)

        if args.hashview_command == "download-hashes":
            download_result = api_harness.download_left_hashes(
                args.customer_id,
                args.hashfile_id,
                potfile_path=hcatPotfilePath,
            )
            print(f"\n✓ Success: Downloaded {download_result['size']} bytes")
            print(f"  File: {download_result['output_file']}")
            sys.exit(0)

        if args.hashview_command == "download-rules":
            download_result = api_harness.download_rules(
                args.rules_id,
                args.output,
            )
            print(f"\n✓ Success: Downloaded {download_result['size']} bytes")
            print(f"  File: {download_result['output_file']}")
            sys.exit(0)

        if args.hashview_command == "upload-hashfile-job":
            hashfile_path = resolve_path(args.file)
            if not hashfile_path or not os.path.isfile(hashfile_path):
                print(f"✗ Error: File not found: {args.file}")
                sys.exit(1)
            upload_result = api_harness.upload_hashfile(
                hashfile_path,
                args.customer_id,
                args.hash_type,
                args.file_format,
                args.hashfile_name,
            )
            print(f"\n✓ Success: {upload_result.get('msg', 'Hashfile uploaded')}")
            if upload_result.get("skipped_cached"):
                print(
                    f"  Skipped: {upload_result['skipped_cached']} already uploaded previously"
                )
            if not upload_result.get("hashfile_id"):
                print("✗ Error: Hashfile upload did not return a hashfile_id.")
                sys.exit(1)
            job_result = api_harness.create_job(
                args.job_name,
                upload_result["hashfile_id"],
                args.customer_id,
                limit_recovered=args.limit_recovered,
            )
            msg = job_result.get("msg", "")
            if "job_id" in job_result:
                print(f"\n✓ Success: {msg or 'Job created'}")
                print(f"  Job ID: {job_result['job_id']}")
                sys.exit(0)
            else:
                print(f"\n✗ Error: {msg or 'Job creation failed (no job_id returned)'}")
                print(
                    "  Note: The Hashview server may have created the job despite this error."
                    " Check the Hashview UI before retrying."
                )
                sys.exit(1)

        print("✗ Error: No hashview subcommand provided.")
        hashview_parser.print_help()
        sys.exit(2)

    if args.cleanup:
        cleanup_wordlist_artifacts()
        sys.exit(0)

    if args.download_all_torrents:
        try:
            download_all_weakpass_torrents(
                fetch_all_wordlists=fetch_all_weakpass_wordlists_multithreaded,
                download_torrent=fetch_torrent_metadata,
                print_fn=print,
            )
        except Exception:
            sys.exit(1)
        sys.exit(0)

    if args.hashview:
        if not hashview_api_key:
            print("Available Customers:")
            print("\nError: Hashview API key not configured.")
            print("Please set HASHVIEW_API_KEY in the .env file")
            sys.exit(1)
        hashview_api()
        sys.exit(0)

    if args.weakpass:
        weakpass_wordlist_menu(rank=flags.weakpass_min_rank)
        sys.exit(0)

    if args.hashmob:
        download_hashmob_wordlists(print_fn=print)
        sys.exit(0)
    if args.rules:
        download_hashmob_rules(print_fn=print, rules_dir=rulesDirectory)
        sys.exit(0)

    if args.hashfile and args.hashtype:
        hcatHashFile = resolve_path(args.hashfile)
        hcatHashFileOrig = hcatHashFile  # Store original before modification
        hcatHashFile = _ensure_hashfile_in_cwd(hcatHashFile)
        hcatHashType = args.hashtype
        if not hcatHashFile or not os.path.isfile(hcatHashFile):
            print(f"Error: hashfile not found: {args.hashfile}")
            sys.exit(1)
        if not str(hcatHashType).isdigit():
            print(f"Error: invalid hash type: {hcatHashType}")
            sys.exit(1)
    else:
        ascii_art()
        if not SKIP_INIT and check_for_updates_enabled:
            check_for_updates()
        _no_hash_items = [
            ("1", "Hashview API"),
            ("2", "Wordlist Tools"),
            ("3", "Rule File Tools"),
            ("4", "Exit"),
        ]
        # The flag states the intent, so go straight to Hashview. Prompting
        # first and then overriding the answer meant even "Exit" opened
        # Hashview (issue #203).
        if args.download_hashview:
            hashview_api()
            if not hcatHashFile:
                sys.exit(0)

        menu_loop = not hcatHashFile
        while menu_loop:
            print("\n" + "=" * 60)
            print("No hash file provided. What would you like to do?")
            print("=" * 60)
            choice = interactive_menu(
                _no_hash_items,
                title="No hash file provided. What would you like to do?",
                prompt="\nSelect an option: ",
            )
            if choice is None:
                # A bare Enter (numbered mode) or Escape (arrow mode) is a
                # cancel gesture, not a typo: re-show the menu without
                # scolding the user. Matches the main menu, which likewise
                # treats a None choice as "ask again".
                continue
            if choice == "1":
                hashview_api()
                # Nothing loaded means the user backed out; re-show the menu.
                if hcatHashFile:
                    menu_loop = False
            elif choice == "2":
                wordlist_tools_submenu()
            elif choice == "3":
                rule_tools_submenu()
            elif choice == "4":
                sys.exit(0)
            else:
                # --weakpass/--hashmob/--rules all exit before this loop,
                # --download-hashview is handled above, and a cancel is
                # handled as None, so the only way here is an answer that
                # matches no menu key.
                print("\n[!] Invalid selection.")

    # At this point, a hashfile must be loaded
    if not hcatHashFile:
        print("\n✗ Error: No hashfile loaded. Exiting.")
        sys.exit(1)

    # Store original hashfile path if not already set (e.g., when downloaded from Hashview)
    if not hcatHashFileOrig:
        hcatHashFileOrig = hcatHashFile
    ascii_art()
    if not SKIP_INIT and check_for_updates_enabled:
        check_for_updates()
    # Get Initial Input Hash Count

    # If LM or NT Mode Selected and pwdump Format Detected, Prompt For LM to NT Attack
    # Track temp files created during preprocessing for cleanup on interruption
    _preprocessing_temp_files: list[str] = []

    def _cleanup_preprocessing_temps() -> None:
        """Remove any temp files created during preprocessing."""
        for path in _preprocessing_temp_files:
            try:
                os.remove(path)
            except OSError:
                pass

    try:
        if hcatHashType == "1000":
            lmHashesFound = False
            pwdump_format = False
            with open(hcatHashFile, "r", encoding="utf-8-sig") as f:
                hcatHashFileLine = ""
                for raw_line in f:
                    hcatHashFileLine = raw_line.strip().replace("\x00", "")
                    if hcatHashFileLine:
                        break
            if re.search(r"[a-f0-9A-F]{32}:[a-f0-9A-F]{32}:::", hcatHashFileLine):
                pwdump_format = True
                print("PWDUMP format detected...")
                # Detect computer accounts (usernames ending with $)
                computer_count = _count_computer_accounts(hcatHashFile)
                if computer_count > 0:
                    print(
                        f"Detected {computer_count} computer account(s)"
                        " (usernames ending with $)."
                    )
                    filter_choice = _auto_input(
                        "Would you like to ignore computer accounts? (Y) ", "Y"
                    )
                    if filter_choice.upper() == "Y":
                        filtered_path = f"{hcatHashFile}.filtered"
                        _preprocessing_temp_files.append(filtered_path)
                        removed = _filter_computer_accounts(hcatHashFile, filtered_path)
                        print(f"Removed {removed} computer account(s).")
                        hcatHashFile = filtered_path
                        # Keep this file - remove from cleanup list
                        _preprocessing_temp_files.remove(filtered_path)
                print("Parsing NT hashes...")
                _write_field_sorted_unique(hcatHashFile, f"{hcatHashFile}.nt", 4)
                print("Parsing LM hashes...")
                _write_field_sorted_unique(hcatHashFile, f"{hcatHashFile}.lm", 3)
                if (
                    (lineCount(hcatHashFile + ".lm") == 1)
                    and (
                        hcatHashFileLine.split(":")[2].lower()
                        != "aad3b435b51404eeaad3b435b51404ee"
                    )
                ) or (lineCount(hcatHashFile + ".lm") > 1):
                    lmHashesFound = True
                    lmChoice = _auto_input(
                        "LM hashes identified. Would you like to brute force"
                        " the LM hashes first? (Y) ",
                        "Y",
                    )
                    if lmChoice.upper() == "Y":
                        hcatLMtoNT()
                hcatHashFileOrig = hcatHashFile
                hcatHashFile = hcatHashFile + ".nt"
            elif re.search(r"^[a-f0-9A-F]{32}$", hcatHashFileLine):
                pwdump_format = False
                print("PWDUMP format was not detected...")
                print("Hash only detected")
            elif re.search(r"^.+:[a-f0-9A-F]{32}$", hcatHashFileLine):
                pwdump_format = False
                print("PWDUMP format was not detected...")
                print("username with Hash detected")
                _write_field_sorted_unique(hcatHashFile, f"{hcatHashFile}.nt", 2)
                hcatHashFileOrig = hcatHashFile
                hcatHashFile = hcatHashFile + ".nt"
            elif re.search(r"^.+::.+:.+:[a-f0-9A-F]{64}:", hcatHashFileLine):
                # NetNTLMv2 format: username::domain:server_challenge:ntproofstr:blob
                # NetNTLMv2-ESS format is similar, with Enhanced Session Security
                pwdump_format = False
                # Try to detect if it's NetNTLMv2-ESS (has specific markers)
                if re.search(
                    r"^.+::.+:.+:[a-f0-9A-F]{16}:[a-f0-9A-F]{32}:[a-f0-9A-F]+$",
                    hcatHashFileLine,
                ):
                    print("NetNTLMv2-ESS format detected")
                    print("Note: Hash type should be 5600 for NetNTLMv2-ESS hashes")
                else:
                    print("NetNTLMv2 format detected")
                    print("Note: Hash type should be 5500 for NetNTLMv2 hashes")
            else:
                print(f"Unrecognized hash format on first line: {hcatHashFileLine!r}")
                print(
                    "Expected one of: pwdump (user:RID:LM:NT:::),"
                    " bare hash (32 hex chars), user:hash, or NetNTLMv2"
                )
                exit(1)
        # Detect and optionally filter computer accounts from NetNTLM hashes
        if hcatHashType in ("5500", "5600"):
            computer_count = _count_computer_accounts(hcatHashFile)
            if computer_count > 0:
                print(
                    f"Detected {computer_count} computer account(s)"
                    " (usernames ending with $)."
                )
                filter_choice = _auto_input(
                    "Would you like to ignore computer accounts? (Y) ", "Y"
                )
                if filter_choice.upper() == "Y":
                    filtered_path = f"{hcatHashFile}.filtered"
                    _preprocessing_temp_files.append(filtered_path)
                    removed = _filter_computer_accounts(hcatHashFile, filtered_path)
                    print(f"Removed {removed} computer account(s).")
                    hcatHashFile = filtered_path
                    _preprocessing_temp_files.remove(filtered_path)

        # Detect and optionally deduplicate NetNTLM hashes by username
        if hcatHashType in ("5500", "5600"):
            dedup_path = hcatHashFile + ".dedup"
            _preprocessing_temp_files.append(dedup_path)
            total, duplicates = _dedup_netntlm_by_username(hcatHashFile, dedup_path)
            if duplicates == 0:
                # No dedup file was created, remove from cleanup list
                _preprocessing_temp_files.remove(dedup_path)
            else:
                print(
                    f"Detected {duplicates} duplicate account(s) out of"
                    f" {total} total NetNTLM hashes."
                )
                dedup_choice = _auto_input(
                    "Would you like to ignore duplicate accounts"
                    " (keep first occurrence only)? (Y) ",
                    "Y",
                )
                if dedup_choice.upper() == "Y":
                    hcatHashFileOrig = hcatHashFile
                    hcatHashFile = dedup_path
                    # Keep this file - remove from cleanup list
                    _preprocessing_temp_files.remove(dedup_path)
                    print(
                        f"Using deduplicated hash file with"
                        f" {total - duplicates} unique accounts."
                    )
                else:
                    # Remove the dedup file if user chose not to use it
                    try:
                        os.remove(dedup_path)
                    except OSError:
                        pass
                    _preprocessing_temp_files.remove(dedup_path)
    except DoubleInterrupt:
        print("\nPreprocessing interrupted. Cleaning up temp files...")
        _cleanup_preprocessing_temps()
        raise
    except KeyboardInterrupt:
        print("\nPreprocessing interrupted. Cleaning up temp files...")
        _cleanup_preprocessing_temps()
        sys.exit(1)

    # Detect username:hash format to inject --username into hashcat commands.
    # Skip modes already handled by the NTLM (1000) and NetNTLM (5500/5600)
    # preprocessing blocks above.
    global hcatUsernamePrefix
    if hcatHashType not in ("1000", "5500", "5600"):
        hcatUsernamePrefix = detect_username_hash_format(hcatHashFile, hcatHashType)
        if hcatUsernamePrefix:
            print("[*] Username prefixes detected \u2014 adding --username flag")

    # Check POT File for Already Cracked Hashes. --restore-potfile forces the
    # rebuild even when .out already exists; the flag is the explicit request,
    # so it skips the interactive overwrite confirmation.
    if flags.restore_potfile:
        check_potfile(force_overwrite=True)
    elif not os.path.isfile(hcatHashFile + ".out"):
        hcatOutput = open(hcatHashFile + ".out", "w+")
        hcatOutput.close()
        print("Checking POT file for already cracked hashes...")
        _run_hashcat_show(hcatHashType, hcatHashFile, f"{hcatHashFile}.out")
        hcatHashCracked = lineCount(hcatHashFile + ".out")
        if hcatHashCracked > 0:
            print(
                "Found %d hashes already cracked.\nCopied hashes to %s.out"
                % (hcatHashCracked, hcatHashFile)
            )
        else:
            print("No hashes found in POT file.")

    if non_interactive:
        sys.exit(_noninteractive.run_noninteractive(_attack_ctx(), args))

    # Display Options
    try:
        options = get_main_menu_options()
        while 1:
            try:
                task = interactive_menu(
                    get_main_menu_items(),
                    title="\nSelect a task:",
                )
                if task is None:
                    continue
                options[task]()
            except KeyError:
                pass
            except DoubleInterrupt:
                print("\n[!] Returning to main menu...")
    except KeyboardInterrupt:
        quit_hc()


# Boilerplate
if __name__ == "__main__":
    main()
