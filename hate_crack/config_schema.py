"""Schema of record for hate_crack configuration keys.

This module defines the full table of configuration keys hate_crack
understands, along with the coercion logic used to parse the string values
that a `.env` file (loaded via python-dotenv) hands back.

This module intentionally does NOT import ``hate_crack.main`` and does not
perform any I/O, config-file reading, or ``sys.exit()``. It is a pure,
unit-testable schema + coercion layer. The four-layer precedence (schema
default < config.json < .env < os.environ) and the decision to exit the
process on a bad value belong to the loader that consumes this module
(``config_loader.py``, added in a later task).

The ``legacy`` field of every entry is the corresponding top-level key in
``hate_crack/config.json.example``; the table's ``legacy`` key set and each
entry's ``default`` are kept in lock-step with that file by
``tests/test_config_schema.py``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Literal

CoerceType = Literal["str", "int", "float", "bool", "csv_list", "path", "charset"]

_TRUE_TOKENS = frozenset({"1", "true", "yes", "on"})
_FALSE_TOKENS = frozenset({"0", "false", "no", "off"})

# Types whose raw string can start/end with a space that is semantically
# significant (a real element, not incidental whitespace). python-dotenv
# strips unquoted values, so Task 3 must emit these quoted or a leading/
# trailing space element is silently lost on the next read.
QUOTE_REQUIRED_TYPES: frozenset[str] = frozenset({"charset"})

# Secret-bearing env keys. Their raw values must never appear in an error
# message (or anywhere else this module chooses to render a value).
SECRET_ENV_KEYS: frozenset[str] = frozenset(
    {
        "HASHVIEW_API_KEY",
        "HASHMOB_API_KEY",
        "NOTIFY_PUSHOVER_TOKEN",
        "NOTIFY_PUSHOVER_USER",
    }
)


class ConfigValueError(ValueError):
    """Raised when a raw string value cannot be coerced to its schema type.

    Carries the offending key, the raw string that failed to parse, and a
    caller-suppliable description of where the value came from (e.g. the
    path to a `.env` file). Never call ``sys.exit()`` in response to this --
    that is the loader's job, not this module's.
    """

    def __init__(self, key: str, raw: str, source: str, reason: str) -> None:
        self.key = key
        self.raw = raw
        self.source = source
        self.reason = reason
        shown = "<redacted>" if key in SECRET_ENV_KEYS else raw
        message = f"Invalid value for {key} in {source}: {shown!r} ({reason})"
        super().__init__(message)


@dataclass(frozen=True)
class ConfigKey:
    """One configuration key, describing both its .env and legacy identity.

    ``choices``, when set, is the closed set of permitted values for a
    ``str``-typed key. :func:`coerce` rejects anything outside it with a
    :class:`ConfigValueError`, which the loader turns into the same fatal,
    key-naming diagnostic a malformed ``int``/``bool`` already gets.
    """

    env: str
    legacy: str
    type: CoerceType
    default: Any
    choices: tuple[str, ...] | None = None


# ---------------------------------------------------------------------------
# The schema table. Written literally -- do NOT regenerate this from
# config.json.example at import time. This table is the schema of record and
# must survive that file's eventual deletion. Keep it in sync with
# hate_crack/config.json.example via tests/test_config_schema.py.
# ---------------------------------------------------------------------------

CONFIG_SCHEMA: tuple[ConfigKey, ...] = (
    ConfigKey("HCAT_PATH", "hcatPath", "path", "/path/to/hashcat"),
    ConfigKey("HCAT_BIN", "hcatBin", "str", "hashcat"),
    ConfigKey("HCAT_TUNING", "hcatTuning", "str", ""),
    ConfigKey(
        "HCAT_POTFILE_PATH",
        "hcatPotfilePath",
        "path",
        "~/.hashcat/hashcat.potfile",
    ),
    ConfigKey(
        "HCAT_DEBUG_LOG_PATH",
        "hcatDebugLogPath",
        "path",
        "~/.hate_crack/hashcat_debug",
    ),
    ConfigKey("HCAT_WORDLISTS", "hcatWordlists", "str", "./wordlists"),
    ConfigKey(
        "HCAT_OPTIMIZED_WORDLISTS",
        "hcatOptimizedWordlists",
        "str",
        "./optimized_wordlists",
    ),
    ConfigKey("RULES_DIRECTORY", "rules_directory", "str", "./hashcat/rules"),
    ConfigKey(
        "HCAT_DICTIONARY_WORDLIST",
        "hcatDictionaryWordlist",
        "csv_list",
        ["rockyou.txt"],
    ),
    ConfigKey(
        "HCAT_COMBINATION_WORDLIST",
        "hcatCombinationWordlist",
        "csv_list",
        ["rockyou.txt", "rockyou.txt"],
    ),
    ConfigKey("HCAT_HYBRIDLIST", "hcatHybridlist", "csv_list", ["rockyou.txt"]),
    ConfigKey(
        "HCAT_MIDDLE_COMBINATOR_MASKS",
        "hcatMiddleCombinatorMasks",
        "charset",
        ["2", "4", " ", "-", "_", "+", ",", ".", "&"],
    ),
    ConfigKey("HCAT_MIDDLE_BASE_LIST", "hcatMiddleBaseList", "str", "rockyou.txt"),
    ConfigKey(
        "HCAT_THOROUGH_COMBINATOR_MASKS",
        "hcatThoroughCombinatorMasks",
        "charset",
        [
            "0",
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
            "9",
            " ",
            "-",
            "_",
            "+",
            ",",
            "!",
            "#",
            "$",
            '"',
            "%",
            "&",
            "'",
            "(",
            ")",
            "*",
            ".",
            "/",
            ":",
            ";",
            "<",
            "=",
            ">",
            "?",
            "@",
            "[",
            "\\",
            "]",
            "^",
            "`",
            "{",
            "|",
            "}",
            "~",
        ],
    ),
    ConfigKey("HCAT_THOROUGH_BASE_LIST", "hcatThoroughBaseList", "str", "rockyou.txt"),
    ConfigKey(
        "HCAT_GOOD_MEASURE_BASE_LIST",
        "hcatGoodMeasureBaseList",
        "str",
        "rockyou.txt",
    ),
    ConfigKey("HCAT_PRINCE_BASE_LIST", "hcatPrinceBaseList", "str", "rockyou.txt"),
    ConfigKey("PIPAL_PATH", "pipalPath", "str", "/path/to/pipal"),
    ConfigKey("PIPAL_COUNT", "pipal_count", "int", 10),
    ConfigKey("BANDRELMAXRUNTIME", "bandrelmaxruntime", "int", 300),
    ConfigKey(
        "BANDREL_COMMON_BASEDWORDS",
        "bandrel_common_basedwords",
        "str",
        "welcome,password,p@ssword,p@$$word,changeme,letmein,summer,winter,"
        "spring,springtime,fall,autumn,monday,tuesday,wednesday,thursday,"
        "friday,saturday,sunday,january,february,march,april,may,june,july,"
        "august,september,october,november,december,christmas,easter,"
        "covid19",
    ),
    ConfigKey("HASHVIEW_URL", "hashview_url", "str", "http://localhost:8443"),
    ConfigKey("HASHVIEW_API_KEY", "hashview_api_key", "str", ""),
    ConfigKey("HASHMOB_API_KEY", "hashmob_api_key", "str", ""),
    ConfigKey("OLLAMA_MODEL", "ollamaModel", "str", "qwen2.5:32b"),
    ConfigKey("OLLAMA_NUM_CTX", "ollamaNumCtx", "int", 8192),
    ConfigKey("OLLAMA_TIMEOUT", "ollamaTimeout", "int", 300),
    ConfigKey("OLLAMA_MAX_SAMPLE_LINES", "ollamaMaxSampleLines", "int", 500),
    ConfigKey("OLLAMA_AUTO_RESEARCH", "ollamaAutoResearch", "bool", True),
    ConfigKey("OMEN_MAX_CANDIDATES", "omenMaxCandidates", "int", 100000000),
    ConfigKey("PCFG_RULESET", "pcfgRuleset", "str", "Default"),
    ConfigKey("PCFG_MAX_CANDIDATES", "pcfgMaxCandidates", "int", 50000000),
    ConfigKey(
        "PCFG_PRINCE_LING_MAX_CANDIDATES",
        "pcfgPrinceLingMaxCandidates",
        "int",
        10000000,
    ),
    ConfigKey("CHECK_FOR_UPDATES", "check_for_updates", "bool", True),
    ConfigKey(
        "OPTIMIZED_KERNEL_ATTACKS",
        "optimizedKernelAttacks",
        "csv_list",
        [
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
            "hcatPCFG",
        ],
    ),
    ConfigKey("NOTIFY_ENABLED", "notify_enabled", "bool", False),
    ConfigKey("NOTIFY_PUSHOVER_TOKEN", "notify_pushover_token", "str", ""),
    ConfigKey("NOTIFY_PUSHOVER_USER", "notify_pushover_user", "str", ""),
    ConfigKey("NOTIFY_PER_CRACK_ENABLED", "notify_per_crack_enabled", "bool", False),
    ConfigKey("NOTIFY_ATTACK_ALLOWLIST", "notify_attack_allowlist", "csv_list", []),
    ConfigKey(
        "NOTIFY_SUPPRESS_IN_ORCHESTRATORS",
        "notify_suppress_in_orchestrators",
        "bool",
        True,
    ),
    ConfigKey("NOTIFY_MAX_CRACKS_PER_BURST", "notify_max_cracks_per_burst", "int", 5),
    ConfigKey(
        "NOTIFY_POLL_INTERVAL_SECONDS",
        "notify_poll_interval_seconds",
        "float",
        5.0,
    ),
    # ---------------------------------------------------------------------
    # Promoted CLI preferences (Task 5). These four keys exist only in the
    # schema -- deliberately NOT in the deprecated config.json.example, which
    # is no longer the source of truth. Each one is the persisted default for
    # an argparse flag that remains available as a per-run override; see
    # main.py's resolve_flag_overrides().
    # ---------------------------------------------------------------------
    ConfigKey("DEBUG", "debug", "bool", False),
    ConfigKey("WEAKPASS_MIN_RANK", "weakpass_min_rank", "int", -1),
    ConfigKey(
        "UPDATE_CHANNEL",
        "update_channel",
        "str",
        "main",
        choices=("main", "nightly-dev"),
    ),
    ConfigKey("RESTORE_POTFILE_ON_START", "restore_potfile_on_start", "bool", False),
)

BY_ENV: dict[str, ConfigKey] = {entry.env: entry for entry in CONFIG_SCHEMA}
BY_LEGACY: dict[str, ConfigKey] = {entry.legacy: entry for entry in CONFIG_SCHEMA}


# ---------------------------------------------------------------------------
# Coercion
# ---------------------------------------------------------------------------


def _coerce_bool(entry: ConfigKey, raw: str, source: str) -> bool:
    token = raw.strip().lower()
    if token in _TRUE_TOKENS:
        return True
    if token in _FALSE_TOKENS:
        return False
    raise ConfigValueError(
        entry.env, raw, source, "expected one of 1/0/true/false/yes/no/on/off"
    )


def _coerce_int(entry: ConfigKey, raw: str, source: str) -> int:
    try:
        return int(raw.strip())
    except ValueError as exc:
        raise ConfigValueError(entry.env, raw, source, "not a valid int") from exc


def _coerce_float(entry: ConfigKey, raw: str, source: str) -> float:
    try:
        return float(raw.strip())
    except ValueError as exc:
        raise ConfigValueError(entry.env, raw, source, "not a valid float") from exc


def _coerce_path(raw: str) -> str:
    if raw == "":
        return ""
    return os.path.expanduser(raw)


def _coerce_csv_list(raw: str) -> list[str]:
    return [piece.strip() for piece in raw.split(",") if piece.strip()]


def _coerce_charset(raw: str) -> list[str]:
    """One character per element, order and duplicates preserved.

    No stripping: a leading/trailing space is a real element, not
    incidental whitespace. ``""`` -> ``[]``. This is how hashcat itself
    expresses a custom charset, and it is lossless for exactly the
    single-character mask lists that ``csv_list`` cannot represent (any
    character, including ``,`` and `` ``, is just an element).
    """
    return list(raw)


def validate_choices(entry: ConfigKey, value: Any, source: str) -> None:
    """Raise :class:`ConfigValueError` if ``value`` is outside ``entry.choices``.

    Exposed separately from :func:`coerce` because the legacy ``config.json``
    layer is checked rather than coerced (its values are typed already), and
    an out-of-range value there must fail the same way it does in `.env`.
    """
    if entry.choices is None:
        return
    if value in entry.choices:
        return
    raise ConfigValueError(
        entry.env,
        str(value),
        source,
        "expected one of " + "/".join(entry.choices),
    )


def coerce(entry: ConfigKey, raw: str, source: str = "<.env>") -> Any:
    """Coerce a raw string value according to ``entry.type``.

    ``source`` is a caller-suppliable description of where ``raw`` came from
    (e.g. a `.env` file path); it is only used to build the error message on
    a malformed ``int``/``float``/``bool``.
    """
    if entry.type == "str":
        validate_choices(entry, raw, source)
        return raw
    if entry.type == "path":
        return _coerce_path(raw)
    if entry.type == "int":
        return _coerce_int(entry, raw, source)
    if entry.type == "float":
        return _coerce_float(entry, raw, source)
    if entry.type == "bool":
        return _coerce_bool(entry, raw, source)
    if entry.type == "csv_list":
        return _coerce_csv_list(raw)
    if entry.type == "charset":
        return _coerce_charset(raw)
    raise AssertionError(f"unhandled config type: {entry.type!r}")  # pragma: no cover
