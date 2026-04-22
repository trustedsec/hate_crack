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
import urllib.request
import urllib.error
import contextlib
import gzip
import lzma
import tempfile
from types import SimpleNamespace

#!/usr/bin/env python3

from typing import Any

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
    orig_cwd,
    resolve_path,
    setup_logging,
)
from hate_crack import attacks as _attacks  # noqa: E402
from hate_crack.menu import interactive_menu  # noqa: E402

# Import HashcatRosetta for rule analysis functionality
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "HashcatRosetta"))
    from hashcat_rosetta.formatting import display_rule_opcodes_summary
except ImportError:
    display_rule_opcodes_summary = None


EXCLUDED_WORDLIST_EXTENSIONS = frozenset({".7z", ".torrent", ".out"})


def list_wordlist_files(directory):
    """Return sorted list of filenames in *directory*, excluding non-wordlist artifacts."""
    return sorted(
        f
        for f in os.listdir(directory)
        if f != ".DS_Store"
        and not any(f.endswith(ext) for ext in EXCLUDED_WORDLIST_EXTENSIONS)
    )


DEFAULT_OPTIMIZED_ATTACKS = frozenset(
    {
        "hcatDictionary",
        "hcatQuickDictionary",
        "hcatBandrel",
        "hcatGoodMeasure",
        "hcatRecycle",
        "hcatBruteForce",
        "hcatTopMask",
        "hcatPathwellBruteForce",
        "hcatAdHocMask",
        "hcatMarkovBruteForce",
        "hcatFingerprint",
        "hcatCombination",
        "hcatCombinator3",
        "hcatCombinatorX",
        "hcatHybrid",
        "hcatYoloCombination",
        "hcatMiddleCombinator",
        "hcatThoroughCombinator",
        "hcatCombipow",
        "hcatPrince",
        "hcatPermute",
    }
)

_optimized_kernel_attacks = DEFAULT_OPTIMIZED_ATTACKS


def _should_use_optimized_kernel(attack_name):
    """Return True if *attack_name* should use hashcat's -O (optimized kernels)."""
    return attack_name in _optimized_kernel_attacks


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
    cwd = os.getcwd()
    home = os.path.expanduser("~")
    candidates = [
        cwd,
        os.path.abspath(os.path.join(cwd, os.pardir)),
        _repo_root,
        _package_path,
        "/opt/hate_crack",
        "/usr/local/share/hate_crack",
    ]
    for candidate_name in ["hate_crack", "hate-crack", ".hate_crack"]:
        candidates.append(os.path.join(home, candidate_name))
    return candidates


def _resolve_config_path():
    for candidate in _candidate_roots():
        config_path = os.path.join(candidate, "config.json")
        if os.path.isfile(config_path):
            return config_path
    return None


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
_config_path = _resolve_config_path()
if not _config_path:
    print("Initializing config.json from config.json.example")
    src_config = os.path.abspath(os.path.join(_package_path, "config.json.example"))
    config_dir = _resolve_config_destination()
    dst_config = os.path.abspath(os.path.join(config_dir, "config.json"))
    shutil.copy(src_config, dst_config)
    print(f"Config source: {src_config}")
    print(f"Config destination: {dst_config}")
    _config_path = dst_config

try:
    with open(_config_path) as config:
        config_parser = json.load(config)
except json.JSONDecodeError as e:
    print("\nError: config.json contains invalid JSON")
    print(f"  File: {_config_path}")
    print(f"  Line {e.lineno}, column {e.colno}: {e.msg}")
    print("\nTo fix:")
    print("  1. Edit the file and fix the JSON syntax, or")
    print("  2. Delete the file to regenerate from defaults")
    sys.exit(1)

config_dir = os.path.dirname(_config_path)
defaults_path = os.path.join(config_dir, "config.json.example")
if not os.path.isfile(defaults_path):
    defaults_path = os.path.join(_package_path, "config.json.example")
try:
    with open(defaults_path) as defaults:
        default_config = json.load(defaults)
except json.JSONDecodeError:
    print("\nError: config.json.example contains invalid JSON")
    print(f"  File: {defaults_path}")
    print("  This is a package installation issue. Try reinstalling hate_crack.")
    sys.exit(1)

_missing_keys = []
for _key, _value in default_config.items():
    if _key not in config_parser:
        config_parser[_key] = _value
        _missing_keys.append(_key)
if _missing_keys:
    with open(_config_path, "w") as _cf:
        json.dump(config_parser, _cf, indent=2)
    print(f"[config] Added {len(_missing_keys)} missing key(s) to {_config_path}")
    print(f"         Keys: {', '.join(_missing_keys)}")

hashview_url = config_parser["hashview_url"]
hashview_api_key = config_parser["hashview_api_key"]

SKIP_INIT = os.environ.get("HATE_CRACK_SKIP_INIT") == "1"

logger = logging.getLogger("hate_crack")
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


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
# Default: use ~/.hashcat/hashcat.potfile (explicitly passed to hashcat).
# Disable override with config `hcatPotfilePath: ""` or CLI `--no-potfile-path`.
if "hcatPotfilePath" not in config_parser:
    _default_pot = os.path.expanduser("~/.hashcat/hashcat.potfile")
    if os.path.isfile(_default_pot) or os.path.isdir(os.path.dirname(_default_pot)):
        hcatPotfilePath = _default_pot
    else:
        hcatPotfilePath = os.path.join(orig_cwd(), "hashcat.potfile")
else:
    _raw_pot = (config_parser.get("hcatPotfilePath") or "").strip()
    if _raw_pot == "":
        hcatPotfilePath = ""
    else:
        hcatPotfilePath = os.path.expanduser(_raw_pot)
        if not os.path.isabs(hcatPotfilePath):
            hcatPotfilePath = os.path.join(hate_path, hcatPotfilePath)


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
hcatCombinator3Wordlist = config_parser.get(
    "hcatCombinator3Wordlist", ["rockyou.txt", "rockyou.txt", "rockyou.txt"]
)
hcatCombinatorXWordlist = config_parser.get(
    "hcatCombinatorXWordlist", ["rockyou.txt", "rockyou.txt"]
)
hcatMiddleCombinatorMasks = config_parser["hcatMiddleCombinatorMasks"]
hcatMiddleBaseList = config_parser["hcatMiddleBaseList"]
hcatThoroughCombinatorMasks = config_parser["hcatThoroughCombinatorMasks"]
hcatThoroughBaseList = config_parser["hcatThoroughBaseList"]
hcatPrinceBaseList = config_parser["hcatPrinceBaseList"]
hcatGoodMeasureBaseList = config_parser["hcatGoodMeasureBaseList"]

hcatDebugLogPath = os.path.expanduser(config_parser["hcatDebugLogPath"])

ollamaUrl = "http://" + os.environ.get("OLLAMA_HOST", "localhost:11434")
ollamaModel = config_parser.get("ollamaModel", "mistral")
ollamaNumCtx = int(config_parser.get("ollamaNumCtx", 2048))

omenTrainingList = config_parser.get("omenTrainingList", "rockyou.txt")
omenMaxCandidates = int(config_parser.get("omenMaxCandidates", 1000000))

try:
    _cfg_optimized = config_parser["optimizedKernelAttacks"]
    if isinstance(_cfg_optimized, list):
        _optimized_kernel_attacks = frozenset(_cfg_optimized)
except KeyError:
    pass
check_for_updates_enabled = config_parser.get("check_for_updates", True)

# Notification subsystem bootstrap.  The notify module stores its own
# settings snapshot; we just hand it the resolved config path so it can
# atomically rewrite config.json when the user toggles enabled / answers
# "always" at a prompt.
from hate_crack import notify as _notify  # noqa: E402  (kept close to config load)

_notify.init(_config_path, config_parser)

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
hcatCombinator3Wordlist = _normalize_wordlist_setting(
    hcatCombinator3Wordlist, wordlists_dir
)
hcatCombinatorXWordlist = _normalize_wordlist_setting(
    hcatCombinatorXWordlist, wordlists_dir
)
hcatHybridlist = _normalize_wordlist_setting(hcatHybridlist, wordlists_dir)
hcatMiddleBaseList = _normalize_wordlist_setting(hcatMiddleBaseList, wordlists_dir)
hcatThoroughBaseList = _normalize_wordlist_setting(hcatThoroughBaseList, wordlists_dir)
hcatGoodMeasureBaseList = _normalize_wordlist_setting(
    hcatGoodMeasureBaseList, wordlists_dir
)
hcatPrinceBaseList = _normalize_wordlist_setting(hcatPrinceBaseList, wordlists_dir)
omenTrainingList = _normalize_wordlist_setting(omenTrainingList, wordlists_dir)
if not SKIP_INIT:
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

    except Exception as e:
        print(f"Module initialization error: {e}")
        if not shutil.which("hashcat") and not os.path.exists("/usr/bin/hashcat"):
            print("Warning: Cannot find hashcat in PATH. Install it to use hate_crack.")
        # Allow module to load even if initialization fails
        pass


hcatHashCount = 0
hcatHashCracked = 0
hcatBruteCount = 0
hcatDictionaryCount = 0
hcatMaskCount = 0
hcatFingerprintCount = 0
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


def _open_wordlist(path):
    """Open a wordlist file, transparently decompressing gzip if the path ends with .gz."""
    if path.endswith(".gz"):
        return gzip.open(path, "rb")
    return open(path, "rb")


def _format_cmd(cmd):
    # Shell-style quoting to mirror what a user could run in a terminal.
    return " ".join(shlex.quote(str(part)) for part in cmd)


def _debug_cmd(cmd):
    if debug_mode:
        print(f"[DEBUG] hashcat cmd: {_format_cmd(cmd)}")


def _run_hcat_cmd(
    cmd,
    attack_name: str = "",
    hash_file: str | None = None,
    *,
    stdin=None,
    companion_procs=None,
    reraise_interrupt: bool = False,
    out_path: str | None = None,
):
    """Execute a hashcat subprocess and bracket it with notify hooks.

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
    global hcatProcess

    companions = list(companion_procs) if companion_procs else []

    # Resolve the output file path used for the tailer and cracked-count
    # readback.  Most hashcat calls write to ``{hash_file}.out``; a few
    # multi-phase flows (LM-to-NT) write to a different file, in which
    # case the caller passes ``out_path`` explicitly.
    resolved_out = out_path if out_path else (hash_file + ".out" if hash_file else None)

    tailer = None
    if attack_name and resolved_out and not _notify.is_suppressed():
        tailer = _notify.start_tailer(resolved_out, attack_name)

    popen_kwargs = {"stdin": stdin} if stdin is not None else {}
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


def _is_gzipped(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"\x1f\x8b"
    except OSError:
        return False


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


def _add_debug_mode_for_rules(cmd):
    """Add debug mode arguments to hashcat command if rules are being used.

    This function detects if rules are present in the command (by looking for -r flags)
    and adds --debug-mode=1 and --debug-file=<path> if rules are found.
    Debug log path is configurable via hcatDebugLogPath in config.json
    """
    if "-r" in cmd:
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

        cmd.extend(["--debug-mode", "4", "--debug-file", debug_filename])
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


def _run_upgrade():
    """Run `git pull && make clean && make && make install` in the repo root."""
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
            "\n  Run manually: git pull && git fetch --tags && uv sync --reinstall-package hate_crack\n"
        )
        raise SystemExit(1)
    repo_root = git_root_result.stdout.strip()

    # Locate the uv binary. It may not be in PATH when running as root or via sudo.
    import shutil

    uv = shutil.which("uv") or os.path.expanduser("~/.local/bin/uv")
    if not os.path.isfile(uv):
        print(
            "\n  Could not find the uv binary."
            "\n  Run manually: git pull && git fetch --tags && uv sync --reinstall-package hate_crack\n"
        )
        raise SystemExit(1)

    result = subprocess.run(
        # git fetch --tags ensures new release tags are visible to setuptools-scm.
        # uv sync --reinstall-package forces hate_crack to be rebuilt from
        # current source so setuptools-scm generates the correct version.
        f"git pull && git fetch --tags && {uv} sync --reinstall-package hate_crack",
        shell=True,
        cwd=repo_root,
    )
    if result.returncode == 0:
        print("\n  Upgrade complete. Please restart hate_crack.\n")
    else:
        print("\n  Upgrade failed. Check the output above for errors.\n")
    raise SystemExit(0)


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

        if parse(latest) > parse(local_base):
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

    # Configure readline for tab completion
    readline.set_completer_delims(" \t\n;")
    # Disable the "Display all X possibilities?" prompt
    try:
        readline.parse_and_bind("set completion-query-items -1")
    except Exception:
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

    result = input(full_prompt).strip()
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


def _write_delimited_field(input_path, output_path, field_index, delimiter=":"):
    try:
        with (
            open(input_path, "r", errors="replace") as src,
            open(output_path, "w") as dst,
        ):
            for line in src:
                line = line.rstrip("\n")
                parts = line.split(delimiter, field_index)
                if len(parts) >= field_index:
                    dst.write(parts[field_index - 1] + "\n")
        return True
    except FileNotFoundError:
        return False


def _write_field_sorted_unique(input_path, output_path, field_index, delimiter=":"):
    try:
        with (
            open(input_path, "r", errors="replace") as src,
            open(output_path, "w") as dst,
        ):
            sort_proc = subprocess.Popen(
                ["sort", "-u"], stdin=subprocess.PIPE, stdout=dst, text=True
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


def _run_hashcat_show(hash_type, hash_file, output_path):
    result = subprocess.run(
        [
            hcatBin,
            "--show",
            # Use hashcat's built-in potfile unless configured otherwise.
            *([f"--potfile-path={hcatPotfilePath}"] if hcatPotfilePath else []),
            "-m",
            str(hash_type),
            hash_file,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    with open(output_path, "w") as out:
        for line in result.stdout.decode("utf-8", errors="ignore").splitlines():
            # hashcat --show prints parse errors to stdout; skip non-result lines
            if ":" in line and not line.startswith(("Hash parsing error", "* ")):
                out.write(line + "\n")


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
        os.path.join(hcatWordlists, f) for f in list_wordlist_files(hcatWordlists)
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
    _run_hcat_cmd(cmd, attack_name="Dictionary", hash_file=hcatHashFile)

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
            _run_hcat_cmd(cmd, attack_name="Dictionary", hash_file=hcatHashFile)
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
    _run_hcat_cmd(cmd, attack_name="Quick Dictionary", hash_file=hcatHashFile)


# Top Mask Attack
def hcatTopMask(hcatHashType, hcatHashFile, hcatTargetTime):
    global hcatMaskCount
    global hcatProcess
    _write_delimited_field(f"{hcatHashFile}.out", f"{hcatHashFile}.working", 2)
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
    _run_hcat_cmd(cmd, attack_name="Top Mask", hash_file=hcatHashFile)

    hcatMaskCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


# Fingerprint Attack
def hcatFingerprint(
    hcatHashType,
    hcatHashFile,
    expander_len: int = 7,
    run_hybrid_on_expanded: bool = False,
):
    global hcatFingerprintCount
    global hcatProcess

    try:
        expander_len = int(expander_len)
    except Exception:
        expander_len = 7
    if expander_len < 7 or expander_len > 36:
        raise ValueError("expander_len must be an integer between 7 and 36")

    crackedBefore = lineCount(hcatHashFile + ".out")
    while True:
        _write_delimited_field(f"{hcatHashFile}.out", f"{hcatHashFile}.working", 2)
        expander_bin = (
            hcatExpanderBin if expander_len == 7 else f"expander{expander_len}.bin"
        )
        expander_path = os.path.join(hate_path, "hashcat-utils", "bin", expander_bin)
        ensure_binary(
            expander_path,
            build_dir=os.path.join(hate_path, "hashcat-utils"),
            name=expander_bin.replace(".bin", ""),
        )
        with (
            open(f"{hcatHashFile}.working", "rb") as src,
            open(f"{hcatHashFile}.expanded", "wb") as dst,
        ):
            expander_proc = subprocess.Popen(
                [expander_path], stdin=src, stdout=subprocess.PIPE
            )
            expander_stdout = expander_proc.stdout
            if expander_stdout is None:
                raise RuntimeError("expander stdout pipe was not created")
            sort_proc = subprocess.Popen(
                ["sort", "-u"], stdin=expander_stdout, stdout=dst
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
        fingerprint_cmd = [
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
            f"{hcatHashFile}.expanded",
            f"{hcatHashFile}.expanded",
        ]
        if _should_use_optimized_kernel("hcatFingerprint"):
            _insert_optimized_flag(fingerprint_cmd)
        fingerprint_cmd.extend(shlex.split(hcatTuning))
        _append_potfile_arg(fingerprint_cmd)
        _run_hcat_cmd(
            fingerprint_cmd, attack_name="Fingerprint", hash_file=hcatHashFile
        )

        # Secondary attack: run hybrid on the expanded candidates (mode 6/7 variants).
        # This is intentionally optional to avoid changing the "extensive" pipeline ordering.
        if run_hybrid_on_expanded:
            hcatHybrid(hcatHashType, hcatHashFile, [f"{hcatHashFile}.expanded"])

        crackedAfter = lineCount(hcatHashFile + ".out")
        if crackedAfter == crackedBefore:
            break
        crackedBefore = crackedAfter
    hcatFingerprintCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


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
    _run_hcat_cmd(cmd, attack_name="Combination", hash_file=hcatHashFile)

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
            attack_name="Combinator3",
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
            attack_name="CombinatorX",
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
        hashcat_cmd.extend(shlex.split(hcatTuning))
        _append_potfile_arg(hashcat_cmd)
        generator_proc = subprocess.Popen(generator_cmd, stdout=subprocess.PIPE)
        assert generator_proc.stdout is not None
        _run_hcat_cmd(
            hashcat_cmd,
            attack_name="NgramX",
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


# Pull an Ollama model via the /api/pull streaming endpoint
def _pull_ollama_model(url, model):
    """Pull an Ollama model. Returns True on success, False on failure."""
    print(f"Model '{model}' not found locally. Pulling from Ollama...")
    pull_url = f"{url}/api/pull"
    payload = json.dumps({"name": model, "stream": True}).encode("utf-8")
    req = urllib.request.Request(
        pull_url,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            for raw_line in resp:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                status = data.get("status")
                if status:
                    print(f"  {status}")
    except urllib.error.HTTPError as e:
        print(f"Error pulling model: HTTP {e.code}")
        return False
    except urllib.error.URLError as e:
        print(f"Error: Could not connect to Ollama: {e}")
        return False
    except Exception as e:
        print(f"Error pulling model: {e}")
        return False
    print(f"Successfully pulled model '{model}'.")
    return True


# LLM Ollama Attack
def hcatOllama(hcatHashType, hcatHashFile, mode, context_data):
    global hcatProcess
    candidates_path = f"{hcatHashFile}.ollama_candidates"

    # Step A: Build LLM prompt based on mode
    if mode == "wordlist":
        wordlist_path = context_data
        if not os.path.isfile(wordlist_path):
            print(f"Error: Wordlist not found: {wordlist_path}")
            return
        lines = []
        try:
            with open(wordlist_path, "r", errors="ignore") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    # Use only content after the first colon (e.g. hash:password -> password)
                    if ":" in stripped:
                        stripped = stripped.split(":", 1)[1]
                    if stripped:
                        lines.append(stripped)
        except Exception as e:
            print(f"Error reading wordlist: {e}")
            return
        print(f"Loaded {len(lines)} passwords from wordlist.")
        wordlist_sample = "\n".join(lines)
        prompt = (
            "Generate baseword to be used in a denylist for keeping users from setting their passwords with these basewords."
            "Study the patterns, character choices, and structures. Focus on patterns like capitalization, leetspeak, suffixes, and common substitutions. Here are the sample passwords:\n"
            f"{wordlist_sample}"
        )
    elif mode == "target":
        company = context_data.get("company", "")
        industry = context_data.get("industry", "")
        location = context_data.get("location", "")
        prompt = (
            "You are participating in a capture the flag event as a security professional. "
            "You are my partner in the competition. You need to recover the password to a system to retrieve the flag. "
            "Output as many possible password combinations you think might help us. "
            f"The name of the fake company is {company}. They are a {industry} in {location}. "
            "Use terms related to the industry as basewords and also use permutations of the company name combined with common suffixes. "
            "Only output the candidate password each on a new line. Dont output any explanation. "
            "Only output the password candidate. Do not number the lines or add any extra information to the output"
        )
    else:
        print(f"Error: Unknown LLM generation mode: {mode}")
        return

    # Step B: Call Ollama API to generate candidates
    print(f"Generating password candidates via Ollama ({ollamaModel})...")
    api_url = f"{ollamaUrl}/api/generate"
    payload = json.dumps(
        {
            "model": ollamaModel,
            "prompt": prompt,
            "stream": False,
            "options": {"num_ctx": ollamaNumCtx},
        }
    ).encode("utf-8")

    if debug_mode:
        print(f"[DEBUG] Ollama API URL: {api_url}")
        print(f"[DEBUG] Ollama request payload: {payload.decode('utf-8')}")

    try:
        req = urllib.request.Request(
            api_url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=600) as resp:
            result = json.loads(resp.read().decode("utf-8"))
        if debug_mode:
            print(f"[DEBUG] Ollama response: {json.dumps(result, indent=2)}")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            if _pull_ollama_model(ollamaUrl, ollamaModel):
                try:
                    req = urllib.request.Request(
                        api_url,
                        data=payload,
                        headers={"Content-Type": "application/json"},
                    )
                    with urllib.request.urlopen(req, timeout=600) as resp:
                        result = json.loads(resp.read().decode("utf-8"))
                    if debug_mode:
                        print(
                            f"[DEBUG] Ollama response (after pull): {json.dumps(result, indent=2)}"
                        )
                except Exception as retry_err:
                    print(f"Error calling Ollama API after pull: {retry_err}")
                    return
            else:
                print(f"Could not pull model '{ollamaModel}'. Aborting LLM attack.")
                return
        else:
            print(f"Error: Could not connect to Ollama at {ollamaUrl}: {e}")
            print("Ensure Ollama is running (ollama serve) and try again.")
            return
    except urllib.error.URLError as e:
        print(f"Error: Could not connect to Ollama at {ollamaUrl}: {e}")
        print("Ensure Ollama is running (ollama serve) and try again.")
        return
    except Exception as e:
        print(f"Error calling Ollama API: {e}")
        return

    response_text = result.get("response", "")
    if "I'm sorry, but I can't help with that" in response_text:
        print(
            "Error: Ollama refused the request. Try a different model or adjust your prompt."
        )
        return
    raw_lines = response_text.strip().split("\n")
    # Filter out blank lines and lines that look like numbering/explanation
    candidates = []
    for line in raw_lines:
        stripped = line.strip()
        if not stripped:
            continue
        # Strip leading numbering like "1. " or "1) " or "- "
        cleaned = re.sub(r"^\d+[.)]\s*", "", stripped)
        cleaned = re.sub(r"^[-*]\s*", "", cleaned)
        cleaned = cleaned.strip()
        if cleaned and len(cleaned) <= 128:
            candidates.append(cleaned)

    if not candidates:
        print("Error: Ollama returned no usable password candidates.")
        return

    try:
        with open(candidates_path, "w") as f:
            for candidate in candidates:
                f.write(candidate + "\n")
    except Exception as e:
        print(f"Error writing candidates file: {e}")
        return

    print(f"Generated {len(candidates)} password candidates -> {candidates_path}")
    if debug_mode:
        filtered_count = len(raw_lines) - len(candidates)
        print(
            f"[DEBUG] Filtered out {filtered_count} lines from Ollama response ({len(raw_lines)} raw -> {len(candidates)} candidates)"
        )

    # Step C: Run hashcat wordlist attack with LLM-generated candidates (no rules)
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

    # Step D: Run hashcat with LLM candidates against every rule in the rules directory
    rule_files = sorted(f for f in os.listdir(rulesDirectory) if f != ".DS_Store")
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


def hcatAdHocMask(hcatHashType, hcatHashFile, mask, custom_charsets=""):
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
    cmd.append(mask)
    if _should_use_optimized_kernel("hcatAdHocMask"):
        _insert_optimized_flag(cmd)
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(cmd)
    _run_hcat_cmd(cmd, attack_name="Ad-hoc Mask", hash_file=hcatHashFile)


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
        with _open_wordlist(source_file) as stdin_f:
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

    tmp_file = None
    if wordlist.endswith(".gz"):
        tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
        with gzip.open(wordlist, "rb") as gz_in:
            tmp_file.write(gz_in.read())
        tmp_file.close()
        wordlist_path = tmp_file.name
    else:
        wordlist_path = wordlist

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
    try:
        _run_hcat_cmd(
            hashcat_cmd,
            attack_name="Combipow",
            hash_file=hcatHashFile,
            stdin=generator_proc.stdout,
            companion_procs=[generator_proc],
        )
        if generator_proc.stdout:
            generator_proc.stdout.close()
    finally:
        if tmp_file is not None:
            with contextlib.suppress(OSError):
                os.unlink(tmp_file.name)


# PRINCE Attack
def hcatPrince(hcatHashType, hcatHashFile):
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
    with _open_wordlist(prince_base) as base:
        prince_proc = subprocess.Popen(prince_cmd, stdin=base, stdout=subprocess.PIPE)
        _run_hcat_cmd(
            hashcat_cmd,
            attack_name="PRINCE",
            hash_file=hcatHashFile,
            stdin=prince_proc.stdout,
            companion_procs=[prince_proc],
        )
        if prince_proc.stdout:
            prince_proc.stdout.close()


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
    with _open_wordlist(wordlist) as wl_file:
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
    cmd = [
        create_bin,
        "--iPwdList",
        training_file,
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
    _run_hcat_cmd(cmd, attack_name="Good Measure", hash_file=hcatHashFile)

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
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(cmd)
    _run_hcat_cmd(
        cmd,
        attack_name="LM to NT (LM phase)",
        hash_file=f"{hcatHashFile}.lm",
        out_path=f"{hcatHashFile}.lm.cracked",
    )

    _write_delimited_field(f"{hcatHashFile}.lm.cracked", f"{hcatHashFile}.working", 2)
    converted = convert_hex("{hash_file}.working".format(hash_file=hcatHashFile))
    with open(
        "{hash_file}.working".format(hash_file=hcatHashFile), mode="w"
    ) as working:
        working.writelines("\n".join(converted))
    combine_path = os.path.join(hate_path, "hashcat-utils", "bin", hcatCombinatorBin)
    with open(f"{hcatHashFile}.combined", "wb") as combined_out:
        combine_proc = subprocess.Popen(
            [combine_path, f"{hcatHashFile}.working", f"{hcatHashFile}.working"],
            stdout=subprocess.PIPE,
        )
        hcatProcess = subprocess.Popen(
            ["sort", "-u"], stdin=combine_proc.stdout, stdout=combined_out
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
        _write_delimited_field(f"{hcatHashFile}.out", working_file, 2)

        converted = convert_hex(working_file)

        # Overwrite working file with updated converted words
        with open(working_file, "w") as f:
            f.write("\n".join(converted))
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
        _run_hcat_cmd(cmd, attack_name="Random Rules", hash_file=hcatHashFile)
    finally:
        if os.path.exists(rules_path):
            os.unlink(rules_path)
    hcatGenerateRulesCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


def check_potfile():
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


# creating the combined output for pwdformat + cleartext
def combine_ntlm_output():
    hashes = {}
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
    with open(hcatHashFileOrig + ".out", "w+") as hcatCombinedHashes:
        with open(hcatHashFileOrig, "r") as hcatOrigFile:
            for origLine in hcatOrigFile:
                orig_parts = origLine.split(":")
                if len(orig_parts) < 4:
                    continue
                ntlm_hash = orig_parts[3]
                if ntlm_hash in hashes:
                    password = hashes[ntlm_hash]
                    hcatCombinedHashes.write(origLine.strip() + password + "\n")


# Cleanup Temp Files
def cleanup():
    global pwdump_format
    global hcatHashFileOrig
    try:
        if not hcatHashFileOrig:
            return
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
        if os.path.exists(hcatHashFile + ".working"):
            os.remove(hcatHashFile + ".working")
        if os.path.exists(hcatHashFile + ".expanded"):
            os.remove(hcatHashFile + ".expanded")
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
    global hcatHashFile, hcatHashType

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
        print("Please set 'hashview_api_key' in config.json")
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
                    if "count" in result:
                        print(f"  Imported: {result['count']} hashes")
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
                    if "hashfile_id" in result:
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
                except Exception as e:
                    print(f"\n✗ Error uploading hashfile: {str(e)}")

            elif option_key == "download_hashes":
                # Download left hashes
                try:
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

                        # List hashfiles for the customer
                        try:
                            customer_hashfiles = api_harness.get_customer_hashfiles(
                                customer_id
                            )

                            if not customer_hashfiles:
                                print(
                                    f"\nNo hashfiles found for customer ID {customer_id}"
                                )
                                continue

                            print("\n" + "=" * 120)
                            print(f"Hashfiles for Customer ID {customer_id}:")
                            print("=" * 120)
                            print(f"{'ID':<10} {'Hash Type':<10} {'Name':<96}")
                            print("-" * 120)
                            hashfile_map = {}
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
                        except Exception as e:
                            print(f"\nWarning: Could not list hashfiles: {e}")
                            continue

                        while True:
                            try:
                                hashfile_id_input = input(
                                    "\nEnter hashfile ID: "
                                ).strip()
                                hashfile_id = int(hashfile_id_input)
                            except ValueError:
                                print(
                                    "\n✗ Error: Invalid ID entered. Please enter a numeric ID."
                                )
                                continue
                            if hashfile_id not in hashfile_map:
                                print(
                                    "\n✗ Error: Hashfile ID not in the list. Please try again."
                                )
                                continue
                            break
                        break

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
                    if debug_mode:
                        print(
                            f"[DEBUG] Calling download_left_hashes with hash_type={selected_hash_type}"
                        )
                    download_result = api_harness.download_left_hashes(
                        customer_id,
                        hashfile_id,
                        output_file,
                        hash_type=selected_hash_type,
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


def combinator_crack():
    return _attacks.combinator_crack(_attack_ctx())


def hybrid_crack():
    return _attacks.hybrid_crack(_attack_ctx())


def pathwell_crack():
    return _attacks.pathwell_crack(_attack_ctx())


def prince_attack():
    return _attacks.prince_attack(_attack_ctx())


def yolo_combination():
    return _attacks.yolo_combination(_attack_ctx())


def thorough_combinator():
    return _attacks.thorough_combinator(_attack_ctx())


def middle_combinator():
    return _attacks.middle_combinator(_attack_ctx())


def combinator3_crack():
    return _attacks.combinator3_crack(_attack_ctx())


def combinatorX_crack():
    return _attacks.combinatorX_crack(_attack_ctx())


def combinator_3plus_crack():
    return _attacks.combinator_3plus_crack(_attack_ctx())


def ngram_attack():
    return _attacks.ngram_attack(_attack_ctx())


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


def wordlist_tools_submenu():
    return _attacks.wordlist_tools_submenu(_attack_ctx())


def rules_cleanup(infile: str, outfile: str) -> bool:
    """Clean a rule file using cleanup-rules.bin. Returns True on success."""
    cleanup_path = os.path.join(hate_path, "hashcat-utils", "bin", "cleanup-rules.bin")
    with open(infile, "rb") as fin, open(outfile, "wb") as fout:
        result = subprocess.run([cleanup_path], stdin=fin, stdout=fout)
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


def notifications_submenu():
    """Submenu for all Pushover notification controls (main-menu option 82)."""
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
                try:
                    processed_words.append(
                        binascii.unhexlify(match.group(1)).decode("iso-8859-9")
                    )
                except UnicodeDecodeError:
                    pass
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
    if hcatHashType == "1000":
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
                    pipalFile.write(clearTextPass)
                pipalFile.close()

            pipalProcess = subprocess.Popen(
                "{pipal_path} {pipal_file} -t {pipal_count} --output {pipal_out}".format(
                    pipal_path=pipalPath,
                    pipal_file=hcatHashFilePipal + ".passwords",
                    pipal_out=hcatHashFilePipal + ".pipal",
                    pipal_count=pipal_count,
                ),
                shell=True,
            )
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
                pipal_content = pipalfile.readlines()
                raw_pipal = "\n".join(pipal_content)
                raw_pipal = re.sub("\n+", "\n", raw_pipal)
                raw_regex = r"Top [0-9]+ base words\n"
                for word in range(pipal_count):
                    raw_regex += r"(\S+).*\n"
                basewords_re = re.compile(raw_regex)
                results = re.search(basewords_re, raw_pipal)
                top_basewords = []
                if results:
                    if results.lastindex is not None:
                        for i in range(1, results.lastindex + 1):
                            if i is not None:
                                top_basewords.append(results.group(i))
                    else:
                        pass
                    return top_basewords
                else:
                    return []
        else:
            print("No hashes were cracked :(")
            return []
    else:
        print("The path to pipal.rb is either not set, or is incorrect.")
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

    if hcatHashType == "1000":
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
        sys.stderr.write("Excel output only supported for pwdformat for NTLM hashes")
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
        print("Make sure HashcatRosetta submodule is properly initialized.")
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
                "[!] notify_pushover_token / notify_pushover_user are empty in "
                "config.json — notifications will silently no-op until set."
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
            "\n[!] Pushover credentials missing. Set notify_pushover_token "
            "and notify_pushover_user in config.json."
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
        ("13", "Bandrel Methodology"),
        ("14", "Loopback Attack"),
        ("15", "LLM Attack"),
        ("16", "OMEN Attack"),
        ("17", "Ad-hoc Mask Attack"),
        ("18", "Markov Brute Force Attack"),
        ("19", "N-gram Attack"),
        ("20", "Permutation Attack"),
        ("21", "Random Rules Attack"),
        ("22", "Combipow Passphrase Attack"),
        ("80", "Wordlist Tools"),
        ("81", "Rule File Tools"),
        ("82", "Notifications"),
        ("90", "Download rules from Hashmob.net"),
        ("91", "Analyze Hashcat Rules"),
        ("92", "Download wordlists from Hashmob.net"),
        ("93", "Weakpass Wordlist Menu"),
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
        "13": bandrel_method,
        "14": loopback_attack,
        "15": ollama_attack,
        "16": omen_attack,
        "17": adhoc_mask_crack,
        "18": markov_brute_force,
        "19": ngram_attack,
        "20": permute_crack,
        "21": generate_rules_crack,
        "22": combipow_crack,
        "80": wordlist_tools_submenu,
        "81": rule_tools_submenu,
        "82": notifications_submenu,
        "90": lambda: download_hashmob_rules(rules_dir=rulesDirectory),
        "91": analyze_rules,
        "92": download_hashmob_wordlists,
        "93": weakpass_wordlist_menu,
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
    global hashview_url, hashview_api_key
    global hcatPath, hcatBin, hcatWordlists, hcatOptimizedWordlists, rulesDirectory
    global pipalPath, maxruntime, bandrelbasewords
    global hcatPotfilePath

    signal.signal(signal.SIGINT, _sigint_handler)

    # Initialize global variables
    hcatHashFile = None
    hcatHashType = None
    hcatHashFileOrig = None

    def _build_parser(include_positional, include_subcommands):
        parser = argparse.ArgumentParser(
            description="hate_crack - Hashcat automation and wordlist management tool"
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
            default=-1,
            help="Only show wordlists with this rank (use 0 to show all, default: >4)",
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
            help="Pull latest changes and reinstall (git pull && make clean && make && make install)",
        )
        parser.add_argument("--debug", action="store_true", help="Enable debug mode")
        parser.add_argument(
            "--potfile-path",
            dest="potfile_path",
            default=None,
            help=(
                "Override hashcat potfile path (equivalent to hashcat --potfile-path). "
                "Use empty string to disable overriding and use hashcat's built-in default."
            ),
        )
        parser.add_argument(
            "--no-potfile-path",
            dest="no_potfile_path",
            action="store_true",
            help="Do not pass --potfile-path to hashcat (use hashcat's built-in default).",
        )
        hashview_parser = None
        if not include_subcommands:
            return parser, hashview_parser

        subparsers = parser.add_subparsers(dest="command")

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
        hv_download_left.add_argument(
            "--hash-type",
            default=None,
            help="Hash type for hashcat (e.g., 1000 for NTLM)",
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

    use_subcommand_parser = "hashview" in argv
    parser, hashview_parser = _build_parser(
        include_positional=not use_subcommand_parser,
        include_subcommands=use_subcommand_parser,
    )
    args = parser.parse_args(argv)

    global debug_mode
    debug_mode = args.debug

    # CLI flags override config file.
    if getattr(args, "no_potfile_path", False):
        hcatPotfilePath = ""
    if getattr(args, "potfile_path", None) is not None:
        # Empty string means: revert to hashcat's default behavior.
        if args.potfile_path.strip() == "":
            hcatPotfilePath = ""
        else:
            p = os.path.expanduser(args.potfile_path.strip())
            if not os.path.isabs(p):
                p = os.path.join(hate_path, p)
            hcatPotfilePath = p

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

    if args.update:
        _run_upgrade()

    if args.download_torrent:
        download_weakpass_torrent(
            download_torrent=download_torrent_file,
            filename=args.download_torrent,
            print_fn=print,
        )
        sys.exit(0)

    if getattr(args, "command", None) == "hashview":
        if not hashview_api_key:
            print("\nError: Hashview API key not configured.")
            print("Please set 'hashview_api_key' in config.json")
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
                hash_type=args.hash_type,
                potfile_path=hcatPotfilePath,
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
            if "hashfile_id" not in upload_result:
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
                download_torrent=download_torrent_file,
                print_fn=print,
            )
        except Exception:
            sys.exit(1)
        sys.exit(0)

    if args.hashview:
        if not hashview_api_key:
            print("Available Customers:")
            print("\nError: Hashview API key not configured.")
            print("Please set 'hashview_api_key' in config.json")
            sys.exit(1)
        hashview_api()
        sys.exit(0)

    if args.weakpass:
        weakpass_wordlist_menu(rank=args.rank)
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
            ("2", "Download wordlists from Weakpass"),
            ("3", "Download wordlists from Hashmob.net"),
            ("4", "Download rules from Hashmob.net"),
            ("5", "Exit"),
        ]
        menu_loop = True
        while menu_loop:
            print("\n" + "=" * 60)
            print("No hash file provided. What would you like to do?")
            print("=" * 60)
            choice = interactive_menu(
                _no_hash_items,
                title="No hash file provided. What would you like to do?",
                prompt="\nSelect an option: ",
            )
            if choice == "1" or args.download_hashview:
                hashview_api()
                # Check if hashfile was set by hashview_api
                if not hcatHashFile:
                    if args.download_hashview:
                        # Exit if called from command line
                        sys.exit(0)
                    # Otherwise continue the menu loop
                else:
                    menu_loop = False
            elif choice == "2" or args.weakpass:
                weakpass_wordlist_menu(rank=args.rank)
                if args.weakpass:
                    sys.exit(0)
                # Otherwise continue the menu loop
            elif choice == "3" or args.hashmob:
                download_hashmob_wordlists(print_fn=print)
                if args.hashmob:
                    sys.exit(0)
                # Otherwise continue the menu loop
            elif choice == "4" or args.rules:
                download_hashmob_rules(print_fn=print, rules_dir=rulesDirectory)
                if args.rules:
                    sys.exit(0)
                # Otherwise continue the menu loop
            elif choice == "5":
                sys.exit(0)
            else:
                if (
                    args.download_hashview
                    or args.weakpass
                    or args.hashmob
                    or args.rules
                ):
                    sys.exit(0)

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
                    filter_choice = (
                        input("Would you like to ignore computer accounts? (Y) ") or "Y"
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
                    lmChoice = (
                        input(
                            "LM hashes identified. Would you like to brute force"
                            " the LM hashes first? (Y) "
                        )
                        or "Y"
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
                filter_choice = (
                    input("Would you like to ignore computer accounts? (Y) ") or "Y"
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
                dedup_choice = (
                    input(
                        "Would you like to ignore duplicate accounts"
                        " (keep first occurrence only)? (Y) "
                    )
                    or "Y"
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

    # Check POT File for Already Cracked Hashes
    if not os.path.isfile(hcatHashFile + ".out"):
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
