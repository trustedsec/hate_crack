"""Schema of record for hate_crack configuration keys.

This module defines the full table of configuration keys hate_crack
understands, along with the coercion logic used to parse the string values
that a `.env` file (or the real environment) hands back.

Every key has exactly one **home** file, named by its ``home`` field:

- ``home="env"`` -- third-party integration settings (Hashview, Hashmob,
  Pushover credentials, Ollama, Pipal). These live in `.env`, which is not
  tracked and can hold secrets.
- ``home="json"`` -- everything else: wordlists, masks, rules, tuning,
  potfile, hashcat paths, candidate limits, notification toggles, update
  check, and the persisted defaults for the per-run CLI preference flags.
  These live in ``config.json``, which is a permanent, first-class
  configuration file with no removal timeline.

A key found in the *other* file is ignored with a warning; the real
``os.environ`` may override any key regardless of home, because an
environment variable is an ephemeral override rather than a home. That
precedence (schema default < home file < os.environ) and the decision to
exit the process on a bad value belong to ``config_loader.py``; this module
is a pure, unit-testable schema + coercion layer and does no I/O.

The ``legacy`` field of every entry is the key name used in ``config.json``
and in ``main.py``'s ``config_parser`` dict. For ``home="json"`` entries it
is also the top-level key in ``hate_crack/config.json.example``; that file
and the ``home="json"`` subset of this table are kept in exact,
bidirectional lock-step by ``tests/test_config_schema.py``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Literal

CoerceType = Literal["str", "int", "float", "bool", "csv_list", "path", "charset"]
Home = Literal["env", "json"]

_TRUE_TOKENS = frozenset({"1", "true", "yes", "on"})
_FALSE_TOKENS = frozenset({"0", "false", "no", "off"})

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

    ``home`` names the one file the key is read from: ``"env"`` for `.env`,
    ``"json"`` for ``config.json``. It defaults to ``"json"`` because that is
    where a new hate_crack setting belongs unless it is credentials for, or
    configuration of, a third-party service -- so a row added without
    thinking about it lands in the tracked example file and the drift guard
    notices, rather than silently becoming an untracked `.env` key.
    """

    env: str
    legacy: str
    type: CoerceType
    default: Any
    choices: tuple[str, ...] | None = None
    home: Home = "json"


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
    # "auto" resolves at runtime to whatever the installed hashcat uses --
    # ~/.local/share/hashcat on 7+, ~/.hashcat on 6 -- see hashcat_paths.py.
    # Hardcoding either location here strands one of those two populations.
    ConfigKey(
        "HCAT_POTFILE_PATH",
        "hcatPotfilePath",
        "path",
        "auto",
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
    # -- Pipal (a third-party tool hate_crack does not ship): home="env".
    ConfigKey("PIPAL_PATH", "pipalPath", "path", "/path/to/pipal", home="env"),
    ConfigKey("PIPAL_COUNT", "pipal_count", "int", 10, home="env"),
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
    # -- Hashview / Hashmob / Ollama: remote services, home="env".
    ConfigKey(
        "HASHVIEW_URL", "hashview_url", "str", "http://localhost:8443", home="env"
    ),
    ConfigKey("HASHVIEW_API_KEY", "hashview_api_key", "str", "", home="env"),
    ConfigKey("HASHMOB_API_KEY", "hashmob_api_key", "str", "", home="env"),
    # Bare host:port or a full URL; main.py normalizes either into a base URL.
    # The default matches Ollama's own, and the name matches the variable
    # Ollama's tooling already reads, so an operator who exports OLLAMA_HOST
    # for the ollama CLI gets the same target here without a second setting.
    ConfigKey("OLLAMA_HOST", "ollamaHost", "str", "localhost:11434", home="env"),
    ConfigKey("OLLAMA_MODEL", "ollamaModel", "str", "qwen2.5:32b", home="env"),
    # Refuse Ollama cloud models, which the local daemon proxies to
    # ollama.com. Off by default: turning it on for everyone would break a
    # user who deliberately configured a cloud model. Worth having because
    # LLM prompts here carry recovered plaintexts and client target details.
    ConfigKey("OLLAMA_NO_CLOUD", "ollamaNoCloud", "bool", False, home="env"),
    ConfigKey("OLLAMA_NUM_CTX", "ollamaNumCtx", "int", 8192, home="env"),
    ConfigKey("OLLAMA_TIMEOUT", "ollamaTimeout", "int", 300, home="env"),
    ConfigKey(
        "OLLAMA_MAX_SAMPLE_LINES", "ollamaMaxSampleLines", "int", 500, home="env"
    ),
    ConfigKey("OLLAMA_AUTO_RESEARCH", "ollamaAutoResearch", "bool", True, home="env"),
    # Which OpenAI-compatible server the LLM attacks (menu 12) and the Rosetta
    # mask attack (menu 23) talk to, and the credential it authenticates with.
    # Deliberately separate from the OLLAMA_* keys above rather than folded
    # into them or replacing them: the OLLAMA_* keys keep owning the host,
    # model, timeout, context and sampling settings for every backend, because
    # vLLM and a generic OpenAI-compatible server want the exact same knobs
    # under the exact same names. Renaming them to something backend-neutral
    # would break every existing .env for no functional gain, so do not "tidy"
    # this by merging LLM_BACKEND/LLM_API_KEY into that block or removing the
    # OLLAMA_* prefix -- see the vLLM backend brief for the reasoning.
    ConfigKey(
        "LLM_BACKEND",
        "llmBackend",
        "str",
        "ollama",
        choices=("ollama", "vllm", "openai"),
        home="env",
    ),
    # Defaults to the literal "ollama", the placeholder Ollama's own server
    # ignores, so an existing install's request shape is unchanged.
    ConfigKey("LLM_API_KEY", "llmApiKey", "str", "ollama", home="env"),
    # Bounds the local corpus-profiling pass behind the LLM attacks. That pass
    # is pure Python at roughly 135k lines/s, so an uncapped run over a 29 GB
    # hashmob dump takes hours and grows an unbounded distinct-password set;
    # past this many lines it samples evenly across the file instead. Five
    # million is about 40 seconds and still a far larger sample than any
    # prompt could carry.
    ConfigKey("CORPUS_PROFILE_MAX_LINES", "hcatCorpusProfileMaxLines", "int", 5000000),
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
            "hcatRosettaMask",
            "hcatPathwellBruteForce",
            "hcatCorporateMasks",
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
    # Pushover credentials are third-party service secrets: home="env". The
    # notification *toggles* around them are local preferences and stay in
    # config.json, which is why this pair is interleaved with json-homed keys.
    ConfigKey("NOTIFY_PUSHOVER_TOKEN", "notify_pushover_token", "str", "", home="env"),
    ConfigKey("NOTIFY_PUSHOVER_USER", "notify_pushover_user", "str", "", home="env"),
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
    # Promoted CLI preferences. Each one is the persisted default for an
    # argparse flag that remains available as a per-run override; see
    # main.py's resolve_flag_overrides(). They are local preferences, so
    # home="json" and they appear in config.json.example like any other
    # setting.
    # ---------------------------------------------------------------------
    ConfigKey("HATE_CRACK_DEBUG", "debug", "bool", False),
    ConfigKey("WEAKPASS_MIN_RANK", "weakpass_min_rank", "int", -1),
    ConfigKey(
        "HATE_CRACK_UPDATE_CHANNEL",
        "update_channel",
        "str",
        "main",
        choices=("main", "nightly-dev"),
    ),
    ConfigKey("RESTORE_POTFILE_ON_START", "restore_potfile_on_start", "bool", False),
    ConfigKey("RULE_DEBUG_MODE_ENABLED", "rule_debug_mode_enabled", "bool", True),
)

BY_ENV: dict[str, ConfigKey] = {entry.env: entry for entry in CONFIG_SCHEMA}
BY_LEGACY: dict[str, ConfigKey] = {entry.legacy: entry for entry in CONFIG_SCHEMA}

# The one definition of the split. The loader, the writer, config.json.example
# and the drift-guard test all read these rather than re-deriving the
# membership from a hand-maintained list.
ENV_KEYS: tuple[ConfigKey, ...] = tuple(e for e in CONFIG_SCHEMA if e.home == "env")
JSON_KEYS: tuple[ConfigKey, ...] = tuple(e for e in CONFIG_SCHEMA if e.home == "json")

# Name-keyed views, for callers that only have a key name in hand.
ENV_HOMED_ENV_NAMES: frozenset[str] = frozenset(e.env for e in ENV_KEYS)
JSON_HOMED_LEGACY_NAMES: frozenset[str] = frozenset(e.legacy for e in JSON_KEYS)


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
