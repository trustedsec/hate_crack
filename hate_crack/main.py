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
import subprocess
import shlex
import argparse
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
    resolve_path,
    setup_logging,
)
from hate_crack import attacks as _attacks  # noqa: E402

# Import HashcatRosetta for rule analysis functionality
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'HashcatRosetta'))
    from hashcat_rosetta.formatting import display_rule_opcodes_summary
except ImportError:
    display_rule_opcodes_summary = None


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
    return os.getcwd()


def _resolve_hate_path(package_path, config_dict=None):
    # Try to use hcatPath from config.json if it's set and contains assets
    if config_dict and config_dict.get("hcatPath"):
        assets_path = config_dict.get("hcatPath")
        if _has_hate_crack_assets(assets_path):
            return assets_path

    # Check common locations for the repo
    for candidate in _candidate_roots():
        if _has_hate_crack_assets(candidate):
            return candidate

    # When installed as a tool, assets should be defined in config.json hcatPath
    # If not set, default to package path (which may not have assets)
    if _has_hate_crack_assets(package_path):
        return package_path

    # Last resort: return package_path, but this likely means assets are missing
    if not config_dict or not config_dict.get("hcatPath"):
        print(
            "\nWarning: Could not find hate_crack assets (hashcat-utils, princeprocessor)."
        )
        print("Set 'hcatPath' in config.json to the installation directory:")
        print('  "hcatPath": "/path/to/hate_crack"')
        print("Or run from the repository directory where these assets are located.\n")

    return package_path


def _ensure_hashfile_in_cwd(hashfile_path):
    """Ensure hashfile path points to cwd to keep output files in execution dir."""
    if not hashfile_path:
        return hashfile_path
    try:
        cwd = os.getcwd()
    except Exception:
        return hashfile_path
    if not os.path.isabs(hashfile_path):
        return hashfile_path
    if os.path.dirname(hashfile_path) == cwd:
        return hashfile_path
    basename = os.path.basename(hashfile_path)
    local_path = os.path.join(cwd, basename)
    if os.path.exists(local_path):
        return local_path
    try:
        os.symlink(hashfile_path, local_path)
        return local_path
    except Exception:
        try:
            shutil.copy2(hashfile_path, local_path)
            return local_path
        except Exception:
            return hashfile_path


# First get a temporary path to load config
_initial_package_path = os.path.dirname(os.path.realpath(__file__))
_config_path = _resolve_config_path()
if not _config_path:
    print("Initializing config.json from config.json.example")
    src_config = os.path.abspath(
        os.path.join(_initial_package_path, "config.json.example")
    )
    config_dir = _resolve_config_destination()
    dst_config = os.path.abspath(os.path.join(config_dir, "config.json"))
    shutil.copy(src_config, dst_config)
    print(f"Config source: {src_config}")
    print(f"Config destination: {dst_config}")
    _config_path = dst_config

with open(_config_path) as config:
    config_parser = json.load(config)

config_dir = os.path.dirname(_config_path)
defaults_path = os.path.join(config_dir, "config.json.example")
if not os.path.isfile(defaults_path):
    defaults_path = os.path.join(_initial_package_path, "config.json.example")
with open(defaults_path) as defaults:
    default_config = json.load(defaults)

# Now resolve hate_path using config
hate_path = _resolve_hate_path(_initial_package_path, config_parser)

# If hate_path differs from initial path, reload config from the new location
if hate_path != _initial_package_path:
    if os.path.isfile(hate_path + "/config.json"):
        with open(hate_path + "/config.json") as config:
            config_parser = json.load(config)
    if os.path.isfile(hate_path + "/config.json.example"):
        with open(hate_path + "/config.json.example") as defaults:
            default_config = json.load(defaults)

try:
    hashview_url = config_parser["hashview_url"]
except KeyError as e:
    print(
        "{0} is not defined in config.json using defaults from config.json.example".format(
            e
        )
    )
    hashview_url = default_config.get("hashview_url", "https://localhost:8443")

try:
    hashview_api_key = config_parser["hashview_api_key"]
except KeyError as e:
    print(
        "{0} is not defined in config.json using defaults from config.json.example".format(
            e
        )
    )
    hashview_api_key = default_config.get("hashview_api_key", "")

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
                    "These are part of the hate_crack repository, not hashcat installation."
                )
                print("\nPlease run hate_crack from the repository directory:")
                print("  cd /path/to/hate_crack && hate_crack <hash_file> <hash_type>")
                print(
                    '\nOr set "hcatPath" in config.json to the hate_crack directory that contains hashcat-utils and princeprocessor:'
                )
                print('  "hcatPath": "/path/to/hate_crack"')
                quit(1)

            # Binary missing - need to build
            print(f"Error: {name or 'binary'} not found at {binary_path}.")
            print("\nPlease build the utilities by running:")
            print(f"  cd {build_dir} && make")
            print("\nEnsure build tools (gcc, make) are installed on your system.")
            quit(1)
        else:
            print(
                f"Error: {name or binary_path} not found or not executable at {binary_path}."
            )
            quit(1)
    return binary_path


# NOTE: hcatPath is for hashcat binary location, NOT for hate_crack assets
# If empty in config, we fall back to hate_path as a convenience
# But hashcat-utils and princeprocessor should ALWAYS use hate_path
hcatPath = config_parser.get("hcatPath", "") or hate_path
hcatBin = config_parser["hcatBin"]
hcatTuning = config_parser["hcatTuning"]
hcatWordlists = config_parser["hcatWordlists"]
hcatOptimizedWordlists = config_parser["hcatOptimizedWordlists"]
hcatRules: list[str] = []


# Optional: override hashcat's default potfile location.
# Default: use ~/.hashcat/hashcat.potfile (explicitly passed to hashcat).
# Disable override with config `hcatPotfilePath: ""` or CLI `--no-potfile-path`.
if "hcatPotfilePath" not in config_parser:
    hcatPotfilePath = os.path.expanduser("~/.hashcat/hashcat.potfile")
else:
    _raw_pot = (config_parser.get("hcatPotfilePath") or "").strip()
    if _raw_pot == "":
        hcatPotfilePath = ""
    else:
        hcatPotfilePath = os.path.expanduser(_raw_pot)
        if not os.path.isabs(hcatPotfilePath):
            hcatPotfilePath = os.path.join(hate_path, hcatPotfilePath)


def _append_potfile_arg(cmd, *, use_potfile_path=True, potfile_path=None):
    if not use_potfile_path:
        return
    pot = potfile_path or hcatPotfilePath
    if pot:
        cmd.append(f"--potfile-path={pot}")

try:
    rulesDirectory = config_parser["rules_directory"]
except KeyError as e:
    print(
        "{0} is not defined in config.json using defaults from config.json.example".format(
            e
        )
    )
    rulesDirectory = default_config.get("rules_directory")
if not rulesDirectory:
    rulesDirectory = (
        os.path.join(hcatPath, "rules")
        if hcatPath
        else os.path.join(hate_path, "rules")
    )
rulesDirectory = os.path.expanduser(rulesDirectory)
if not os.path.isabs(rulesDirectory):
    rulesDirectory = os.path.join(hate_path, rulesDirectory)

# Normalize wordlist directories
hcatWordlists = os.path.expanduser(hcatWordlists)
if not os.path.isabs(hcatWordlists):
    hcatWordlists = os.path.join(hate_path, hcatWordlists)
hcatOptimizedWordlists = os.path.expanduser(hcatOptimizedWordlists)
if not os.path.isabs(hcatOptimizedWordlists):
    hcatOptimizedWordlists = os.path.join(hate_path, hcatOptimizedWordlists)
if not os.path.isdir(hcatWordlists):
    fallback_wordlists = os.path.join(hate_path, "wordlists")
    if os.path.isdir(fallback_wordlists):
        print(f"[!] hcatWordlists directory not found: {hcatWordlists}")
        print(f"[!] Falling back to {fallback_wordlists}")
        hcatWordlists = fallback_wordlists
if not os.path.isdir(hcatOptimizedWordlists):
    fallback_optimized = os.path.join(hate_path, "optimized_wordlists")
    if os.path.isdir(fallback_optimized):
        print(
            f"[!] hcatOptimizedWordlists directory not found: {hcatOptimizedWordlists}"
        )
        print(f"[!] Falling back to {fallback_optimized}")
        hcatOptimizedWordlists = fallback_optimized

try:
    maxruntime = config_parser["bandrelmaxruntime"]
except KeyError as e:
    print(
        "{0} is not defined in config.json using defaults from config.json.example".format(
            e
        )
    )
    maxruntime = default_config["bandrelmaxruntime"]

try:
    bandrelbasewords = config_parser["bandrel_common_basedwords"]
except KeyError as e:
    print(
        "{0} is not defined in config.json using defaults from config.json.example".format(
            e
        )
    )
    bandrelbasewords = default_config["bandrel_common_basedwords"]

try:
    pipal_count = config_parser["pipal_count"]
except KeyError as e:
    print(
        "{0} is not defined in config.json using defaults from config.json.example".format(
            e
        )
    )
    pipal_count = default_config["pipal_count"]

try:
    pipalPath = config_parser["pipalPath"]
except KeyError as e:
    print(
        "{0} is not defined in config.json using defaults from config.json.example".format(
            e
        )
    )
    pipalPath = default_config["pipalPath"]

try:
    hcatDictionaryWordlist = config_parser["hcatDictionaryWordlist"]
except KeyError as e:
    print(
        "{0} is not defined in config.json using defaults from config.json.example".format(
            e
        )
    )
    hcatDictionaryWordlist = default_config["hcatDictionaryWordlist"]
try:
    hcatHybridlist = config_parser["hcatHybridlist"]
except KeyError as e:
    print(
        "{0} is not defined in config.json using defaults from config.json.example".format(
            e
        )
    )
    hcatHybridlist = default_config[e.args[0]]
try:
    hcatCombinationWordlist = config_parser["hcatCombinationWordlist"]
except KeyError as e:
    print(
        "{0} is not defined in config.json using defaults from config.json.example".format(
            e
        )
    )
    hcatCombinationWordlist = default_config[e.args[0]]
try:
    hcatMiddleCombinatorMasks = config_parser["hcatMiddleCombinatorMasks"]
except KeyError as e:
    print(
        "{0} is not defined in config.json using defaults from config.json.example".format(
            e
        )
    )
    hcatMiddleCombinatorMasks = default_config[e.args[0]]
try:
    hcatMiddleBaseList = config_parser["hcatMiddleBaseList"]
except KeyError as e:
    print(
        "{0} is not defined in config.json using defaults from config.json.example".format(
            e
        )
    )
    hcatMiddleBaseList = default_config[e.args[0]]
try:
    hcatThoroughCombinatorMasks = config_parser["hcatThoroughCombinatorMasks"]
except KeyError as e:
    print(
        "{0} is not defined in config.json using defaults from config.json.example".format(
            e
        )
    )
    hcatThoroughCombinatorMasks = default_config[e.args[0]]
try:
    hcatThoroughBaseList = config_parser["hcatThoroughBaseList"]
except KeyError as e:
    print(
        "{0} is not defined in config.json using defaults from config.json.example".format(
            e
        )
    )
    hcatThoroughBaseList = default_config[e.args[0]]
try:
    hcatPrinceBaseList = config_parser["hcatPrinceBaseList"]
except KeyError as e:
    print(
        "{0} is not defined in config.json using defaults from config.json.example".format(
            e
        )
    )
    hcatPrinceBaseList = default_config[e.args[0]]
try:
    hcatGoodMeasureBaseList = config_parser["hcatGoodMeasureBaseList"]
except KeyError as e:
    print(
        "{0} is not defined in config.json using defaults from config.json.example".format(
            e
        )
    )
    hcatGoodMeasureBaseList = default_config[e.args[0]]

try:
    hcatDebugLogPath = config_parser.get("hcatDebugLogPath", "./hashcat_debug")
    # Expand user home directory if present
    hcatDebugLogPath = os.path.expanduser(hcatDebugLogPath)
except KeyError as e:
    print(
        "{0} is not defined in config.json using defaults from config.json.example".format(
            e
        )
    )
    hcatDebugLogPath = os.path.expanduser(default_config.get("hcatDebugLogPath", "./hashcat_debug"))

hcatExpanderBin = "expander.bin"
hcatCombinatorBin = "combinator.bin"
hcatPrinceBin = "pp64.bin"


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
hcatMiddleBaseList = _normalize_wordlist_setting(hcatMiddleBaseList, wordlists_dir)
hcatThoroughBaseList = _normalize_wordlist_setting(hcatThoroughBaseList, wordlists_dir)
hcatGoodMeasureBaseList = _normalize_wordlist_setting(
    hcatGoodMeasureBaseList, wordlists_dir
)
hcatPrinceBaseList = _normalize_wordlist_setting(hcatPrinceBaseList, wordlists_dir)

if not SKIP_INIT:
    # Verify hashcat binary is available
    # hcatPath is for assets (hashcat-utils, princeprocessor), not hashcat binary location
    # hcatBin should be in PATH or be an absolute path
    try:
        if os.path.isabs(hcatBin):
            if not os.path.isfile(hcatBin):
                print(
                    f"Hashcat binary not found at {hcatBin}. Please check configuration and try again."
                )
                quit(1)
        else:
            # hcatBin should be in PATH
            if shutil.which(hcatBin) is None:
                print(
                    f'Hashcat binary "{hcatBin}" not found in PATH. Please check configuration and try again.'
                )
                quit(1)

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
                quit(1)

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
hcatHybridCount = 0
hcatExtraCount = 0
hcatRecycleCount = 0
hcatProcess: subprocess.Popen[Any] | None = None
debug_mode = False


def _format_cmd(cmd):
    # Shell-style quoting to mirror what a user could run in a terminal.
    return " ".join(shlex.quote(str(part)) for part in cmd)


def _debug_cmd(cmd):
    if debug_mode:
        print(f"[DEBUG] hashcat cmd: {_format_cmd(cmd)}")


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
                debug_filename = os.path.join(hcatDebugLogPath, f"hashcat_debug_{cmd[session_idx]}.log")
        
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
    print(r"""

  ___ ___         __             _________                       __    
 /   |   \_____ _/  |_  ____     \_   ___ \____________    ____ |  | __
/    ~    \__  \\   __\/ __ \    /    \  \/\_  __ \__  \ _/ ___\|  |/ /
\    Y    // __ \|  | \  ___/    \     \____|  | \// __ \\  \___|    < 
 \___|_  /(____  /__|  \___  >____\______  /|__|  (____  /\___  >__|_ \
       \/      \/          \/_____/      \/            \/     \/     \/
                          Version 2.0
  """)


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
            text = "./"

        # Expand ~ to home directory
        text = os.path.expanduser(text)

        # Handle both absolute and relative paths
        if (
            text.startswith("/")
            or text.startswith("./")
            or text.startswith("../")
            or text.startswith("~")
        ):
            matches = glob.glob(text + "*")
        else:
            matches = glob.glob("./" + text + "*")
            matches = [m[2:] if m.startswith("./") else m for m in matches]

        # Add trailing slash for directories
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
        with open(file) as outFile:
            count = 0
            for line in outFile:
                count = count + 1
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


def _run_hashcat_show(hash_type, hash_file, output_path):
    with open(output_path, "w") as out:
        subprocess.run(
            [
                hcatBin,
                "--show",
                # Use hashcat's built-in potfile unless configured otherwise.
                *([f"--potfile-path={hcatPotfilePath}"] if hcatPotfilePath else []),
                "-m",
                str(hash_type),
                hash_file,
            ],
            stdout=out,
            check=False,
        )


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
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(cmd)
    hcatProcess = subprocess.Popen(cmd)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        print("Killing PID {0}...".format(str(hcatProcess.pid)))
        hcatProcess.kill()

    hcatBruteCount = lineCount(hcatHashFile + ".out")


# Dictionary Attack
def hcatDictionary(hcatHashType, hcatHashFile):
    global hcatDictionaryCount
    global hcatProcess
    rule_best66 = get_rule_path("best66.rule")
    optimized_lists = sorted(glob.glob(os.path.join(hcatOptimizedWordlists, "*")))
    if not optimized_lists:
        optimized_lists = [os.path.join(hcatOptimizedWordlists, "*")]
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
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(cmd)
    cmd = _add_debug_mode_for_rules(cmd)
    hcatProcess = subprocess.Popen(cmd)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        print("Killing PID {0}...".format(str(hcatProcess.pid)))
        hcatProcess.kill()

    for wordlist in hcatDictionaryWordlist:
        rule_d3ad0ne = get_rule_path("d3ad0ne.rule")
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
            rule_d3ad0ne,
        ]
        cmd.extend(shlex.split(hcatTuning))
        _append_potfile_arg(cmd)
        cmd = _add_debug_mode_for_rules(cmd)
        hcatProcess = subprocess.Popen(cmd)
        try:
            hcatProcess.wait()
        except KeyboardInterrupt:
            print("Killing PID {0}...".format(str(hcatProcess.pid)))
            hcatProcess.kill()

        rule_toxic = get_rule_path("T0XlC.rule")
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
            rule_toxic,
        ]
        cmd.extend(shlex.split(hcatTuning))
        _append_potfile_arg(cmd)
        cmd = _add_debug_mode_for_rules(cmd)
        hcatProcess = subprocess.Popen(cmd)
        try:
            hcatProcess.wait()
        except KeyboardInterrupt:
            print("Killing PID {0}...".format(str(hcatProcess.pid)))
            hcatProcess.kill()

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
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(cmd, use_potfile_path=use_potfile_path, potfile_path=potfile_path)
    cmd = _add_debug_mode_for_rules(cmd)
    _debug_cmd(cmd)
    hcatProcess = subprocess.Popen(cmd)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        print("Killing PID {0}...".format(str(hcatProcess.pid)))
        hcatProcess.kill()


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
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(cmd)
    hcatProcess = subprocess.Popen(cmd)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        print("Killing PID {0}...".format(str(hcatProcess.pid)))
        hcatProcess.kill()

    hcatMaskCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


# Fingerprint Attack
def hcatFingerprint(
    hcatHashType, hcatHashFile, expander_len: int = 7, run_hybrid_on_expanded: bool = False
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
    crackedAfter = 0
    while crackedBefore != crackedAfter:
        crackedBefore = lineCount(hcatHashFile + ".out")
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
            sort_proc = subprocess.Popen(["sort", "-u"], stdin=expander_stdout, stdout=dst)
            hcatProcess = sort_proc
            expander_stdout.close()
            try:
                sort_proc.wait()
                expander_proc.wait()
            except KeyboardInterrupt:
                print("Killing PID {0}...".format(str(sort_proc.pid)))
                sort_proc.kill()
                expander_proc.kill()
        hcatProcess = subprocess.Popen(
            [
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
                *shlex.split(hcatTuning),
                *([f"--potfile-path={hcatPotfilePath}"] if hcatPotfilePath else []),
            ]
        )
        try:
            hcatProcess.wait()
        except KeyboardInterrupt:
            print("Killing PID {0}...".format(str(hcatProcess.pid)))
            hcatProcess.kill()

        # Secondary attack: run hybrid on the expanded candidates (mode 6/7 variants).
        # This is intentionally optional to avoid changing the "extensive" pipeline ordering.
        if run_hybrid_on_expanded:
            hcatHybrid(hcatHashType, hcatHashFile, [f"{hcatHashFile}.expanded"])

        crackedAfter = lineCount(hcatHashFile + ".out")
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
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(cmd)
    hcatProcess = subprocess.Popen(cmd)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        print("Killing PID {0}...".format(str(hcatProcess.pid)))
        hcatProcess.kill()

    hcatCombinationCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


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
            cmd.extend(shlex.split(hcatTuning))
            _append_potfile_arg(cmd)
            hcatProcess = subprocess.Popen(cmd)
            try:
                hcatProcess.wait()
            except KeyboardInterrupt:
                print("Killing PID {0}...".format(str(hcatProcess.pid)))
                hcatProcess.kill()

        hcatHybridCount = lineCount(hcatHashFile + ".out") - hcatHashCracked


# YOLO Combination Attack
def hcatYoloCombination(hcatHashType, hcatHashFile):
    global hcatProcess
    try:
        while 1:
            hcatLeft = random.choice(os.listdir(hcatOptimizedWordlists))
            hcatRight = random.choice(os.listdir(hcatOptimizedWordlists))
            left_path = os.path.join(hcatOptimizedWordlists, hcatLeft)
            right_path = os.path.join(hcatOptimizedWordlists, hcatRight)
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
            cmd.extend(shlex.split(hcatTuning))
            _append_potfile_arg(cmd)
            hcatProcess = subprocess.Popen(cmd)
            try:
                hcatProcess.wait()
            except KeyboardInterrupt:
                print("Killing PID {0}...".format(str(hcatProcess.pid)))
                hcatProcess.kill()
                raise
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
        cmd.extend(shlex.split(hcatTuning))
        _append_potfile_arg(cmd)
        hcatProcess = subprocess.Popen(cmd)
        try:
            hcatProcess.wait()
        except KeyboardInterrupt:
            print("Killing PID {0}...".format(str(hcatProcess.pid)))
            hcatProcess.kill()
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
        cmd.extend(shlex.split(hcatTuning))
        _append_potfile_arg(cmd)
        hcatProcess = subprocess.Popen(cmd)
        try:
            hcatProcess.wait()
        except KeyboardInterrupt:
            print("Killing PID {0}...".format(str(hcatProcess.pid)))
            hcatProcess.kill()


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
                *([f"--potfile-path={hcatPotfilePath}"] if hcatPotfilePath else []),
            ]
            hcatProcess = subprocess.Popen(cmd)
            try:
                hcatProcess.wait()
            except KeyboardInterrupt:
                print("Killing PID {0}...".format(str(hcatProcess.pid)))
                hcatProcess.kill()
                raise
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
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(cmd)
    hcatProcess = subprocess.Popen(cmd)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        print("Killing PID {0}...".format(str(hcatProcess.pid)))
        hcatProcess.kill()

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
                *([f"--potfile-path={hcatPotfilePath}"] if hcatPotfilePath else []),
            ]
            hcatProcess = subprocess.Popen(cmd)
            try:
                hcatProcess.wait()
            except KeyboardInterrupt:
                print("Killing PID {0}...".format(str(hcatProcess.pid)))
                hcatProcess.kill()
                raise
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
            cmd.extend(shlex.split(hcatTuning))
            _append_potfile_arg(cmd)
            hcatProcess = subprocess.Popen(cmd)
            try:
                hcatProcess.wait()
            except KeyboardInterrupt:
                print("Killing PID {0}...".format(str(hcatProcess.pid)))
                hcatProcess.kill()
                raise
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
            cmd.extend(shlex.split(hcatTuning))
            _append_potfile_arg(cmd)
            hcatProcess = subprocess.Popen(cmd)
            hcatProcess.wait()
    except KeyboardInterrupt:
        print("Killing PID {0}...".format(str(hcatProcess.pid)))
        hcatProcess.kill()


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
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(cmd)
    hcatProcess = subprocess.Popen(cmd)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        print("Killing PID {0}...".format(str(hcatProcess.pid)))
        hcatProcess.kill()


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
    hashcat_cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(hashcat_cmd)
    hashcat_cmd = _add_debug_mode_for_rules(hashcat_cmd)
    with open(prince_base, "rb") as base:
        prince_proc = subprocess.Popen(prince_cmd, stdin=base, stdout=subprocess.PIPE)
        hcatProcess = subprocess.Popen(hashcat_cmd, stdin=prince_proc.stdout)
        prince_proc.stdout.close()
        try:
            hcatProcess.wait()
            prince_proc.wait()
        except KeyboardInterrupt:
            print("Killing PID {0}...".format(str(hcatProcess.pid)))
            hcatProcess.kill()
            prince_proc.kill()


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
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(cmd)
    cmd = _add_debug_mode_for_rules(cmd)
    hcatProcess = subprocess.Popen(cmd)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        print("Killing PID {0}...".format(str(hcatProcess.pid)))
        hcatProcess.kill()

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
    hcatProcess = subprocess.Popen(cmd)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        hcatProcess.kill()

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
    hcatProcess = subprocess.Popen(cmd)
    try:
        hcatProcess.wait()
    except KeyboardInterrupt:
        print("Killing PID {0}...".format(str(hcatProcess.pid)))
        hcatProcess.kill()

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
            cmd.extend(shlex.split(hcatTuning))
            _append_potfile_arg(cmd)
            cmd = _add_debug_mode_for_rules(cmd)
            hcatProcess = subprocess.Popen(cmd)
            try:
                hcatProcess.wait()
            except KeyboardInterrupt:
                hcatProcess.kill()


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
        if hcatHashType == "1000" and pwdump_format:
            print("\nComparing cracked hashes to original file...")
            combine_ntlm_output()
        print(
            "\nCracked passwords combined with original hashes in %s"
            % (hcatHashFileOrig + ".out")
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
                menu_options.append(("upload_cracked", "Upload Cracked Hashes from current session"))
            menu_options.append(("upload_wordlist", "Upload Wordlist"))
            menu_options.append(("download_wordlist", "Download Wordlist"))
            menu_options.append(("download_left", "Download Left Hashes (with automatic merge if found)"))
            menu_options.append(("download_found", "Download Found Hashes (with automatic split)"))
            if hcatHashFile:
                menu_options.append(("upload_hashfile_job", "Upload Hashfile and Create Job"))
            menu_options.append(("back", "Back to Main Menu"))
            
            # Display menu with dynamic numbering
            for i, (option_key, option_text) in enumerate(menu_options, 1):
                if option_key == "back":
                    print(f"\t(99) {option_text}")
                else:
                    print(f"\t({i}) {option_text}")
            
            # Create mapping of display numbers to option keys
            option_map = {}
            display_num = 1
            for option_key, _ in menu_options[:-1]:  # All except "back"
                option_map[str(display_num)] = option_key
                display_num += 1
            option_map["99"] = "back"

            choice = input("\nSelect an option: ")
            
            if choice not in option_map:
                print("Invalid option. Please try again.")
                continue
            
            option_key = option_map[choice]

            if option_key == "upload_cracked":
                # Upload cracked hashes
                if not hcatHashFile:
                    print("\n✗ Error: No hashfile is currently set. This option is not available.")
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

                api_name = wordlist_map.get(wordlist_id) if "wordlist_map" in locals() else None
                api_filename = "dynamic-all.txt.gz" if wordlist_id == 1 else api_name
                prompt_suffix = f" (API filename: {api_filename})" if api_filename else " (API filename)"
                output_file = (
                    input(
                        f"Enter output file name{prompt_suffix} or press Enter to use API filename: "
                    )
                    .strip()
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
                hashfile_path = hcatHashFileOrig  # Use original path, not the modified one
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
                    with open(hashfile_path, 'r', encoding='utf-8', errors='ignore') as f:
                        first_line = f.readline().strip()
                        if first_line:
                            # Check for pwdump format (username:hash or username:rid:lmhash:nthash)
                            parts = first_line.split(':')
                            if len(parts) >= 4:
                                # Likely pwdump format (username:rid:lmhash:nthash)
                                file_format = 0
                            elif len(parts) == 2 and not all(c in '0123456789abcdefABCDEF' for c in parts[0]):
                                # Likely user:hash format (first part is not all hex)
                                file_format = 4
                            # Otherwise default to 5 (hash_only)
                except Exception:
                    file_format = 5  # Default if detection fails
                
                print(f"\nAuto-detected file format: {file_format} ", end="")
                format_names = {0: "pwdump", 1: "NetNTLM", 2: "kerberos", 3: "shadow", 4: "user:hash", 5: "hash_only"}
                print(f"({format_names.get(file_format, 'unknown')})")

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
                            notify_email = True
                            try:
                                job_result = api_harness.create_job(
                                    job_name,
                                    result["hashfile_id"],
                                    customer_id,
                                    limit_recovered,
                                    notify_email,
                                )
                                print(
                                    f"\n✓ Success: {job_result.get('msg', 'Job created')}"
                                )
                                if "job_id" in job_result:
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
                            except Exception as e:
                                print(f"\n✗ Error creating job: {str(e)}")
                except Exception as e:
                    print(f"\n✗ Error uploading hashfile: {str(e)}")

            elif option_key == "download_left":
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

                        # List hashfiles for the customer
                        try:
                            customer_hashfiles = api_harness.get_customer_hashfiles(
                                customer_id
                            )

                            if not customer_hashfiles:
                                print(f"\nNo hashfiles found for customer ID {customer_id}")
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
                                hf_type = hf.get("hash_type") or hf.get("hashtype") or "N/A"
                                if hf_id is None:
                                    continue
                                # Truncate long names to fit within 120 columns
                                if len(str(hf_name)) > 96:
                                    hf_name = str(hf_name)[:93] + "..."
                                if debug_mode:
                                    print(f"[DEBUG] Hashfile {hf_id}: hash_type={hf.get('hash_type')}, hashtype={hf.get('hashtype')}, combined={hf_type}")
                                print(f"{hf_id:<10} {hf_type:<10} {hf_name:<96}")
                                hashfile_map[int(hf_id)] = hf_type
                            print("=" * 120)
                            print(f"Total: {len(hashfile_map)} hashfile(s)")
                        except Exception as e:
                            print(f"\nWarning: Could not list hashfiles: {e}")
                            continue

                        while True:
                            try:
                                hashfile_id_input = input("\nEnter hashfile ID: ").strip()
                                hashfile_id = int(hashfile_id_input)
                            except ValueError:
                                print("\n✗ Error: Invalid ID entered. Please enter a numeric ID.")
                                continue
                            if hashfile_id not in hashfile_map:
                                print("\n✗ Error: Hashfile ID not in the list. Please try again.")
                                continue
                            break
                        break

                    # Set output filename automatically
                    output_file = f"left_{customer_id}_{hashfile_id}.txt"

                    # Get hash type for hashcat from the hashfile map
                    selected_hash_type = hashfile_map.get(hashfile_id)
                    if debug_mode:
                        print(f"[DEBUG] selected_hash_type from map: {selected_hash_type}")
                    if not selected_hash_type or selected_hash_type == "N/A":
                        try:
                            details = api_harness.get_hashfile_details(hashfile_id)
                            selected_hash_type = details.get("hashtype")
                            if debug_mode:
                                print(f"[DEBUG] selected_hash_type from get_hashfile_details: {selected_hash_type}")
                        except Exception as e:
                            if debug_mode:
                                print(f"[DEBUG] Error fetching hashfile details: {e}")
                            selected_hash_type = None

                    # Download the left hashes
                    if debug_mode:
                        print(f"[DEBUG] Calling download_left_hashes with hash_type={selected_hash_type}")
                    download_result = api_harness.download_left_hashes(
                        customer_id, hashfile_id, output_file, hash_type=selected_hash_type
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

            elif option_key == "download_found":
                # Download found hashes
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

                        # List hashfiles for the customer
                        try:
                            customer_hashfiles = api_harness.get_customer_hashfiles(
                                customer_id
                            )

                            if not customer_hashfiles:
                                print(f"\nNo hashfiles found for customer ID {customer_id}")
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
                                hf_type = hf.get("hash_type") or hf.get("hashtype") or "N/A"
                                if hf_id is None:
                                    continue
                                # Truncate long names to fit within 120 columns
                                if len(str(hf_name)) > 96:
                                    hf_name = str(hf_name)[:93] + "..."
                                if debug_mode:
                                    print(f"[DEBUG] Hashfile {hf_id}: hash_type={hf.get('hash_type')}, hashtype={hf.get('hashtype')}, combined={hf_type}")
                                print(f"{hf_id:<10} {hf_type:<10} {hf_name:<96}")
                                hashfile_map[int(hf_id)] = hf_type
                            print("=" * 120)
                            print(f"Total: {len(hashfile_map)} hashfile(s)")
                        except Exception as e:
                            print(f"\nWarning: Could not list hashfiles: {e}")
                            continue

                        while True:
                            try:
                                hashfile_id_input = input("\nEnter hashfile ID: ").strip()
                                hashfile_id = int(hashfile_id_input)
                            except ValueError:
                                print("\n✗ Error: Invalid ID entered. Please enter a numeric ID.")
                                continue
                            if hashfile_id not in hashfile_map:
                                print("\n✗ Error: Hashfile ID not in the list. Please try again.")
                                continue
                            break
                        break

                    # Set output filename automatically
                    output_file = f"found_{customer_id}_{hashfile_id}.txt"

                    # Get hash type for hashcat from the hashfile map
                    selected_hash_type = hashfile_map.get(hashfile_id)
                    if debug_mode:
                        print(f"[DEBUG] selected_hash_type from map: {selected_hash_type}")
                    if not selected_hash_type or selected_hash_type == "N/A":
                        try:
                            details = api_harness.get_hashfile_details(hashfile_id)
                            selected_hash_type = details.get("hashtype")
                            if debug_mode:
                                print(f"[DEBUG] selected_hash_type from get_hashfile_details: {selected_hash_type}")
                        except Exception as e:
                            if debug_mode:
                                print(f"[DEBUG] Error fetching hashfile details: {e}")
                            selected_hash_type = None

                    # Download the found hashes
                    if debug_mode:
                        print(f"[DEBUG] Calling download_found_hashes with hash_type={selected_hash_type}")
                    download_result = api_harness.download_found_hashes(
                        customer_id, hashfile_id, output_file
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
                    print(f"\n✗ Error downloading found hashes: {str(e)}")

            elif option_key == "back":
                break

    except KeyboardInterrupt:
        quit_hc()
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


def bandrel_method():
    return _attacks.bandrel_method(_attack_ctx())


def loopback_attack():
    return _attacks.loopback_attack(_attack_ctx())


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
    
    print("\n" + "="*60)
    print("Rule Opcode Analyzer")
    print("="*60)
    
    # Get rule file path from user
    rule_file = input("\nEnter path to rule file: ").strip()
    
    if not rule_file:
        print("No rule file specified.")
        return
    
    # Expand user path
    rule_file = os.path.expanduser(rule_file)
    
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


def get_main_menu_options():
    """Return the mapping of main menu keys to their handler functions."""
    options = {
        "1": quick_crack,
        "2": extensive_crack,
        "3": brute_force_crack,
        "4": top_mask_crack,
        "5": fingerprint_crack,
        "6": combinator_crack,
        "7": hybrid_crack,
        "8": pathwell_crack,
        "9": prince_attack,
        "10": yolo_combination,
        "11": middle_combinator,
        "12": thorough_combinator,
        "13": bandrel_method,
        "14": loopback_attack,
        "90": download_hashmob_rules,
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
            "download-left",
            help="Download left hashes for a hashfile",
        )
        hv_download_left.add_argument(
            "--customer-id", required=True, type=int, help="Customer ID"
        )
        hv_download_left.add_argument(
            "--hashfile-id", required=True, type=int, help="Hashfile ID"
        )
        hv_download_left.add_argument(
            "--hash-type", default=None, help="Hash type for hashcat (e.g., 1000 for NTLM)"
        )

        hv_download_found = hashview_subparsers.add_parser(
            "download-found",
            help="Download found hashes for a hashfile",
        )
        hv_download_found.add_argument(
            "--customer-id", required=True, type=int, help="Customer ID"
        )
        hv_download_found.add_argument(
            "--hashfile-id", required=True, type=int, help="Hashfile ID"
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
        hv_upload_hashfile_job.add_argument(
            "--no-notify-email",
            action="store_true",
            help="Disable email notifications",
        )
        return parser, hashview_parser

    # Removed add_common_args(parser) since config items are now only set via config file
    argv = sys.argv[1:]
    
    hashview_subcommands = [
        "upload-cracked",
        "upload-wordlist",
        "download-left",
        "download-found",
        "upload-hashfile-job",
    ]
    has_hashview_flag = "--hashview" in argv
    has_hashview_subcommand = any(cmd in argv for cmd in hashview_subcommands)
    
    # Handle custom help for --hashview (without subcommand)
    if has_hashview_flag and not has_hashview_subcommand and ("--help" in argv or "-h" in argv):
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

        if args.hashview_command == "download-left":
            download_result = api_harness.download_left_hashes(
                args.customer_id,
                args.hashfile_id,
                hash_type=args.hash_type,
            )
            print(f"\n✓ Success: Downloaded {download_result['size']} bytes")
            print(f"  File: {download_result['output_file']}")
            sys.exit(0)

        if args.hashview_command == "download-found":
            download_result = api_harness.download_found_hashes(
                args.customer_id,
                args.hashfile_id,
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
                notify_email=not args.no_notify_email,
            )
            print(f"\n✓ Success: {job_result.get('msg', 'Job created')}")
            if "job_id" in job_result:
                print(f"  Job ID: {job_result['job_id']}")
            sys.exit(0)

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
        download_hashmob_rules(print_fn=print)
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
        menu_loop = True
        while menu_loop:
            print("\n" + "=" * 60)
            print("No hash file provided. What would you like to do?")
            print("=" * 60)
            print("\t(1) Hashview API")
            print("\t(2) Download wordlists from Weakpass")
            print("\t(3) Download wordlists from Hashmob.net")
            print("\t(4) Download rules from Hashmob.net")
            print("\t(5) Exit")
            choice = input("\nSelect an option: ")
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
                download_hashmob_rules(print_fn=print)
                if args.rules:
                    sys.exit(0)
                # Otherwise continue the menu loop
            elif choice == "5":
                sys.exit(0)
            else:
                if args.download_hashview or args.weakpass or args.hashmob or args.rules:
                    sys.exit(0)

    # At this point, a hashfile must be loaded
    if not hcatHashFile:
        print("\n✗ Error: No hashfile loaded. Exiting.")
        sys.exit(1)

    # Store original hashfile path if not already set (e.g., when downloaded from Hashview)
    if not hcatHashFileOrig:
        hcatHashFileOrig = hcatHashFile
    ascii_art()
    # Get Initial Input Hash Count

    # If LM or NT Mode Selected and pwdump Format Detected, Prompt For LM to NT Attack
    if hcatHashType == "1000":
        lmHashesFound = False
        pwdump_format = False
        hcatHashFileLine = open(hcatHashFile, "r").readline().strip().lstrip("\ufeff")
        if re.search(r"[a-f0-9A-F]{32}:[a-f0-9A-F]{32}:::", hcatHashFileLine):
            pwdump_format = True
            print("PWDUMP format detected...")
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
                        "LM hashes identified. Would you like to brute force the LM hashes first? (Y) "
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
            if re.search(r"^.+::.+:.+:[a-f0-9A-F]{16}:[a-f0-9A-F]{32}:[a-f0-9A-F]+$", hcatHashFileLine):
                print("NetNTLMv2-ESS format detected")
                print("Note: Hash type should be 5600 for NetNTLMv2-ESS hashes")
            else:
                print("NetNTLMv2 format detected")
                print("Note: Hash type should be 5500 for NetNTLMv2 hashes")
        else:
            print("unknown format....does it have usernames?")
            exit(1)
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
            print("\n\t(1) Quick Crack")
            print("\t(2) Extensive Pure_Hate Methodology Crack")
            print("\t(3) Brute Force Attack")
            print("\t(4) Top Mask Attack")
            print("\t(5) Fingerprint Attack")
            print("\t(6) Combinator Attack")
            print("\t(7) Hybrid Attack")
            print("\t(8) Pathwell Top 100 Mask Brute Force Crack")
            print("\t(9) PRINCE Attack")
            print("\t(10) YOLO Combinator Attack")
            print("\t(11) Middle Combinator Attack")
            print("\t(12) Thorough Combinator Attack")
            print("\t(13) Bandrel Methodology")
            print("\t(14) Loopback Attack")
            print("\n\t(90) Download rules from Hashmob.net")
            print("\n\t(91) Download wordlists from Weakpass")
            print("\t(92) Download wordlists from Hashmob.net")
            print("\t(93) Weakpass Wordlist Menu")
            if hashview_api_key:
                print("\t(94) Hashview API")
            print("\t(95) Analyze hashes with Pipal")
            print("\t(96) Export Output to Excel Format")
            print("\t(97) Display Cracked Hashes")
            print("\t(98) Display README")
            print("\t(99) Quit")
            try:
                task = input("\nSelect a task: ")
                options[task]()
            except KeyError:
                pass
    except KeyboardInterrupt:
        quit_hc()


# Boilerplate
if __name__ == "__main__":
    main()
