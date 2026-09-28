"""Non-interactive (scripted) attack entry points for hate_crack.

These helpers translate parsed argparse namespaces into calls against the
existing ``hcat*`` attack functions on the main module (passed in as ``ctx``,
the same pattern ``attacks.py`` uses).

Every subcommand is one :class:`AttackSpec` in :data:`ATTACK_SPECS`. That table
is the single source of truth: ``ATTACK_COMMANDS`` is derived from it and both
``add_attack_subparsers`` and ``_dispatch`` are driven off it. Keeping the
three in one place matters because ``main.py`` sets its ``non_interactive``
global from membership in ``ATTACK_COMMANDS`` -- a name registered as a
subparser but missing from that tuple would run the attack with every
interactive prompt still live, waiting on a stdin nobody is attached to.
"""

import os
from typing import Any, Callable, NamedTuple


class AttackSpec(NamedTuple):
    """One non-interactive subcommand.

    ``add_arguments`` receives the subparser (the shared ``hashfile`` and
    ``hashtype`` positionals are added for it). ``run`` receives ``(ctx,
    args)`` and returns a process exit code.
    """

    name: str
    help: str
    add_arguments: Callable[[Any], None] | None
    run: Callable[[Any, Any], int]


def build_rule_chains(ctx: Any, rule_tokens: list[str] | None) -> list[str]:
    """Convert CLI ``--rules`` tokens into hashcat ``-r`` chain strings.

    Each token becomes one attack pass. A token may chain multiple rule files
    with ``+`` (mirroring the interactive rule selector). Filenames resolve
    against ``ctx.rulesDirectory``. Returns ``[""]`` when no rules are given
    (equivalent to the interactive "run without rules" choice).

    Raises ``FileNotFoundError`` (with the offending filename as its argument)
    if any named rule file is missing.
    """
    if not rule_tokens:
        return [""]
    chains = []
    for token in rule_tokens:
        chain = ""
        for name in token.split("+"):
            name = name.strip()
            if not name:
                continue
            path = os.path.join(ctx.rulesDirectory, name)
            if not os.path.isfile(path):
                raise FileNotFoundError(name)
            chain = f"{chain} -r {path}".strip()
        if not chain:
            raise ValueError(f"Rule token {token!r} resolved to no rule files")
        chains.append(chain)
    return chains


SKIPPED_BY_COVERAGE = 3


def run_noninteractive(ctx: Any, args: Any) -> int:
    """Run a non-interactive attack. Returns a process exit code.

    ``ctx`` is the main module (live ``hcat*`` functions, ``rulesDirectory``,
    ``resolve_path``, ``hcatHashType``/``hcatHashFile`` already set by the
    preprocessing block in ``main()``). ``args`` is the parsed subparser
    namespace whose ``command`` selects the attack.

    Exit codes: 0 ran, 1 bad input, 2 unknown command, and -- only when
    ``--exit-code-on-skip`` is passed -- 3 for "coverage had already seen all of
    this, so nothing was launched". That is behind a flag because coverage is
    enabled by default, so returning 3 unconditionally would start failing
    existing cron and ``set -e`` harnesses the first time an attack repeated,
    without them having changed anything.
    """
    # ctx is duck-typed -- normally the main module, but tests pass a stand-in --
    # so the counters are optional rather than required of every caller.
    reset = getattr(ctx, "reset_run_counters", None)
    if callable(reset):
        reset()

    code = _dispatch(ctx, args)
    if code != 0:
        return code

    counters = getattr(ctx, "run_counters", None)
    launches, skips = counters() if callable(counters) else (0, 0)
    if getattr(args, "exit_code_on_skip", False) and skips and not launches:
        print(
            f"[coverage] every pass of `{args.command}` was already covered; "
            "nothing was launched"
        )
        return SKIPPED_BY_COVERAGE
    return code


def _dispatch(ctx: Any, args: Any) -> int:
    spec = _SPECS_BY_NAME.get(getattr(args, "command", None))
    if spec is None:
        print(f"Error: unknown non-interactive command: {args.command}")
        return 2
    return spec.run(ctx, args)


# ---------------------------------------------------------------------------
# Shared input validation
#
# Every one of these returns the resolved value or raises _BadInput, which the
# runners turn into exit 1. Validating up front rather than letting the attack
# function bail halfway matters for a scripted caller: a run that dies after
# launching looks the same as one that never started unless the exit code
# distinguishes them.
# ---------------------------------------------------------------------------


class _BadInput(Exception):
    """A CLI argument that cannot produce a usable attack."""


def _validated(fn: Callable[[Any, Any], int]) -> Callable[[Any, Any], int]:
    """Turn a _BadInput raised by a runner into exit 1 plus a message."""

    def _wrapper(ctx: Any, args: Any) -> int:
        try:
            return fn(ctx, args)
        except _BadInput as exc:
            print(f"Error: {exc}")
            return 1

    _wrapper.__name__ = fn.__name__
    _wrapper.__doc__ = fn.__doc__
    return _wrapper


def _existing_file(ctx: Any, raw: str, label: str) -> str:
    path = ctx.resolve_path(raw)
    if not path or not os.path.isfile(path):
        raise _BadInput(f"{label} not found: {raw}")
    return path


def _positive_int(value: int, label: str) -> int:
    if value <= 0:
        raise _BadInput(f"{label} must be greater than 0")
    return value


def _rule_chains(ctx: Any, tokens: list[str] | None) -> list[str]:
    try:
        return build_rule_chains(ctx, tokens)
    except (FileNotFoundError, ValueError) as exc:
        raise _BadInput(f"invalid --rules value: {exc}") from exc


def _target(ctx: Any) -> tuple[Any, Any]:
    return ctx.hcatHashType, ctx.hcatHashFile


# ---------------------------------------------------------------------------
# Runners -- the original four
# ---------------------------------------------------------------------------


@_validated
def _run_quick(ctx: Any, args: Any) -> int:
    wordlist = _existing_file(ctx, args.wordlist, "wordlist")
    for chain in _rule_chains(ctx, args.rule_files):
        ctx.hcatQuickDictionary(
            *_target(ctx), chain, wordlist, attack_name="Quick Crack"
        )
    return 0


def _run_dict(ctx: Any, args: Any) -> int:
    ctx.hcatDictionary(*_target(ctx))
    return 0


def _run_brute(ctx: Any, args: Any) -> int:
    ctx.hcatBruteForce(*_target(ctx), args.min_len, args.max_len)
    return 0


def _run_topmask(ctx: Any, args: Any) -> int:
    ctx.hcatTopMask(*_target(ctx), args.target_time * 3600)
    return 0


# ---------------------------------------------------------------------------
# Runners -- no-argument tier (#340)
# ---------------------------------------------------------------------------


@_validated
def _run_fingerprint(ctx: Any, args: Any) -> int:
    # The interactive prompt enforces 7-36 before calling; a scripted run that
    # skipped the check would hand hashcat an expander length that quietly
    # produces nothing rather than failing.
    if not 7 <= args.max_expander_len <= 36:
        raise _BadInput("--max-expander-len must be between 7 and 36")
    if args.keyspace_limit is not None and args.keyspace_limit < 0:
        raise _BadInput("--keyspace-limit must be zero (no limit) or greater")

    if args.no_dictionary_wordlist:
        # "" means skip, which is distinct from None ("fall back to config").
        dictionary_wordlist: str | None = ""
    elif args.dictionary_wordlist:
        dictionary_wordlist = _existing_file(
            ctx, args.dictionary_wordlist, "dictionary wordlist"
        )
    else:
        dictionary_wordlist = None

    ctx.hcatFingerprint(
        *_target(ctx),
        max_expander_len=args.max_expander_len,
        run_hybrid_on_expanded=args.run_hybrid_on_expanded,
        dictionary_wordlist=dictionary_wordlist,
        keyspace_limit=args.keyspace_limit,
    )
    return 0


def _run_bare(func_name: str) -> Callable[[Any, Any], int]:
    """Runner for an attack taking only hashtype + hashfile."""

    def _run(ctx: Any, args: Any) -> int:
        getattr(ctx, func_name)(*_target(ctx))
        return 0

    return _run


def _run_smartmask(ctx: Any, args: Any) -> int:
    if args.keyspace_limit is not None and args.keyspace_limit < 0:
        print("Error: --keyspace-limit must be zero (no limit) or greater")
        return 1
    ctx.hcatSmartMask(*_target(ctx), keyspace_limit=args.keyspace_limit)
    return 0


def _run_corporate(ctx: Any, args: Any) -> int:
    # Passed only when set, so hcatCorporateMasks applies its own documented
    # defaults (and its own clamping to the 8-14 corporate range) rather than
    # this module duplicating those constants.
    kwargs = {}
    if args.min_len is not None:
        kwargs["minLen"] = args.min_len
    if args.max_len is not None:
        kwargs["maxLen"] = args.max_len
    ctx.hcatCorporateMasks(*_target(ctx), **kwargs)
    return 0


def _wordlist_runner(func_name: str, minimum: int) -> Callable[[Any, Any], int]:
    """Runner for an attack whose wordlists default to a configured list.

    ``None`` is the sentinel both hcatCombination and hcatHybrid use for "fall
    back to config", so an unset --wordlist must pass None rather than [].
    """

    @_validated
    def _run(ctx: Any, args: Any) -> int:
        if not args.wordlists:
            wordlists = None
        else:
            if len(args.wordlists) < minimum:
                raise _BadInput(
                    f"--wordlist needs at least {minimum} entries for this attack"
                )
            wordlists = [_existing_file(ctx, w, "wordlist") for w in args.wordlists]
        getattr(ctx, func_name)(*_target(ctx), wordlists=wordlists)
        return 0

    return _run


@_validated
def _run_combinator(ctx: Any, args: Any) -> int:
    """Concatenate two or more wordlists.

    Three different attack functions back this, and picking between them is
    not optional: ``hcatCombination`` slices to ``wordlists[:2]``, so handing
    it three would silently drop the third. The routing mirrors
    ``attacks.combinator_crack`` -- two and no separator go to
    ``hcatCombination``, exactly three and no separator to
    ``hcatCombinator3``, and everything else to ``hcatCombinatorX``, which is
    the only one of the three that can insert a separator at all.
    """
    if not args.wordlists:
        # No --wordlist: fall back to the configured combinator list, which is
        # a pair, so hcatCombination is the right destination.
        ctx.hcatCombination(*_target(ctx), wordlists=None)
        return 0

    if len(args.wordlists) < 2:
        raise _BadInput("--wordlist needs at least 2 entries for a combinator attack")
    wordlists = [_existing_file(ctx, w, "wordlist") for w in args.wordlists]
    separator = args.separator

    if len(wordlists) == 2 and not separator:
        ctx.hcatCombination(*_target(ctx), wordlists=wordlists)
    elif len(wordlists) == 3 and not separator:
        ctx.hcatCombinator3(*_target(ctx), wordlists)
    else:
        ctx.hcatCombinatorX(*_target(ctx), wordlists, separator or None)
    return 0


# ---------------------------------------------------------------------------
# Runners -- one-argument tier (#340)
# ---------------------------------------------------------------------------


@_validated
def _run_bandrel(ctx: Any, args: Any) -> int:
    # Validated against the comma-split, which is what hcatBandrel actually
    # consumes -- "," is non-blank but contributes no basewords at all.
    names = [part.strip() for part in args.company.split(",") if part.strip()]
    if not names:
        raise _BadInput("--company must name at least one company")
    ctx.hcatBandrel(*_target(ctx), company_name=",".join(names))
    return 0


@_validated
def _run_permute(ctx: Any, args: Any) -> int:
    ctx.hcatPermute(*_target(ctx), _existing_file(ctx, args.wordlist, "wordlist"))
    return 0


def _increment_bound(raw: str, flag: str) -> str:
    """Validate one --increment-min/--increment-max value.

    Bounds stay strings so a blank one reaches the command builder blank --
    an omitted bound is hashcat's own default, not a number to invent here.
    Mirrors ``attacks._prompt_length``, which re-asks until the answer is a
    positive whole number or empty.
    """
    raw = (raw or "").strip()
    if not raw:
        return ""
    if not raw.isdigit() or int(raw) <= 0:
        raise _BadInput(f"{flag} must be a positive whole number")
    return raw


def _checked_mask(ctx: Any, raw: str) -> str:
    """Return the mask, refusing a mask *file* that does not exist.

    hashcat takes either a literal mask or a path to a .hcmask file in the
    same slot, and treats a path it cannot open as a literal mask -- so a
    typo'd filename enumerates one nonsense candidate and exits 0, which a
    scripted caller reads as "ran, found nothing". The interactive path checks
    os.path.isfile before calling, and so does this.
    """
    looks_like_a_path = os.sep in raw or raw.lower().endswith(".hcmask")
    if looks_like_a_path and not os.path.isfile(raw):
        raise _BadInput(f"mask file not found: {raw}")
    return raw


@_validated
def _run_adhocmask(ctx: Any, args: Any) -> int:
    mask = _checked_mask(ctx, args.mask)
    inc_min = _increment_bound(args.increment_min, "--increment-min")
    inc_max = _increment_bound(args.increment_max, "--increment-max")
    # Either bound implies increment, but --increment alone is also valid:
    # it is how the interactive path reaches "increment over the full
    # keyspace of the mask", which no combination of bounds can express.
    increment = bool(args.increment or inc_min or inc_max)
    if inc_min and inc_max and int(inc_min) > int(inc_max):
        raise _BadInput("--increment-min must not exceed --increment-max")
    ctx.hcatAdHocMask(
        *_target(ctx),
        mask,
        increment=increment,
        increment_min=inc_min or "",
        increment_max=inc_max or "",
    )
    return 0


@_validated
def _run_ngram(ctx: Any, args: Any) -> int:
    corpus = _existing_file(ctx, args.corpus, "corpus")
    ctx.hcatNgramX(
        *_target(ctx), corpus, group_size=_positive_int(args.group_size, "--group-size")
    )
    return 0


#: combipow enumerates 2^n-1 combinations, so the interactive path refuses a
#: wordlist over this many lines. The scripted path refuses too rather than
#: launching a run that cannot finish.
COMBIPOW_MAX_LINES = 63


@_validated
def _run_combipow(ctx: Any, args: Any) -> int:
    wordlist = _existing_file(ctx, args.wordlist, "wordlist")
    with ctx._open_wordlist(wordlist) as fh:
        line_count = sum(1 for _ in fh)
    if line_count > COMBIPOW_MAX_LINES:
        raise _BadInput(
            f"wordlist has {line_count} lines (max {COMBIPOW_MAX_LINES}); "
            "combipow generates 2^n-1 combinations"
        )
    ctx.hcatCombipow(*_target(ctx), wordlist, not args.no_spaces)
    return 0


@_validated
def _run_spoonman(ctx: Any, args: Any) -> int:
    corpus = _existing_file(ctx, args.corpus, "corpus")
    ctx.hcatSpoonman(
        *_target(ctx),
        corpus,
        coverage=args.rule_coverage,
        baseword_cap=args.baseword_cap,
    )
    return 0


@_validated
def _run_omen(ctx: Any, args: Any) -> int:
    max_candidates = _positive_int(args.max_candidates, "--max-candidates")
    # The interactive handler offers to train a model here. Training needs its
    # own corpus and runs for a long time, so a scripted caller that asked for
    # an attack gets an error rather than a surprise training run.
    if not ctx._omen_model_is_valid(ctx._omen_model_dir()):
        raise _BadInput(
            "no valid OMEN model found; train one from the interactive menu "
            "(option 13) before running this subcommand"
        )
    ctx.hcatOmen(*_target(ctx), max_candidates)
    return 0


@_validated
def _run_loopback(ctx: Any, args: Any) -> int:
    """Re-run rules against the plaintexts already cracked for this hash file.

    Mirrors ``attacks.loopback_attack``: an empty wordlist plus
    ``hcatQuickDictionary(loopback=True)``, which makes hashcat feed its own
    potfile back in. It deliberately does not call ``hcatRecycle`` -- that
    function's third argument is a count of newly cracked passwords used as an
    internal gate by ``extensive_crack``, and has no meaning for a caller
    choosing to run a loopback pass.
    """
    chains = _rule_chains(ctx, args.rule_files)

    empty_wordlist = os.path.join(ctx.hcatWordlists, "empty.txt")
    os.makedirs(ctx.hcatWordlists, exist_ok=True)
    if not os.path.exists(empty_wordlist):
        with open(empty_wordlist, "w"):
            pass

    # Primed once against the combined coverage of every selected rule file, so
    # the skip decision reflects the whole batch rather than the first chain's
    # numbers alone -- same reason attacks.loopback_attack does it.
    coverage_decision = ctx._prime_coverage_decision(
        ctx.hcatHashFile, chains, empty_wordlist, "Loopback", loopback=True
    )
    for chain in chains:
        ctx.hcatQuickDictionary(
            *_target(ctx),
            chain,
            empty_wordlist,
            loopback=True,
            attack_name="Loopback",
            coverage_decision=coverage_decision,
        )
    return 0


# ---------------------------------------------------------------------------
# Argument builders
# ---------------------------------------------------------------------------


def _add_rules(p) -> None:
    p.add_argument(
        "--rules",
        nargs="*",
        default=[],
        dest="rule_files",
        metavar="RULE",
        help="Rule filename(s) from the rules directory. Chain with '+' "
        "(e.g. best64.rule+d3ad0ne.rule). Omit to run without rules.",
    )


def _add_keyspace_limit(p, subject: str) -> None:
    p.add_argument(
        "--keyspace-limit",
        type=int,
        default=None,
        dest="keyspace_limit",
        help=f"Skip a {subject} that would exceed this many candidates "
        "(0 for no limit; omit for the built-in default of 50,000,000,000).",
    )


#: The only coverage percentages rulegen derives capped rule files for
#: (``rulegen.generate(cover=...)``). Any other value would miss the cache on
#: every run -- so the expensive derivation repeats -- and then fall back to
#: the full rule set, silently handing an operator who asked for a small rule
#: set the largest one instead.
SPOONMAN_RULE_COVERAGES = (50, 75, 95, 99)


def _combinator_args(p) -> None:
    _add_wordlists(p, "combinator attack (at least two)")
    p.add_argument(
        "--separator",
        default="",
        help="String to insert between words. Any separator routes the attack "
        "through combinatorX, the only variant that supports one.",
    )


def _add_wordlists(p, subject: str) -> None:
    p.add_argument(
        "--wordlist",
        nargs="+",
        default=[],
        dest="wordlists",
        metavar="PATH",
        help=f"Wordlist(s) for the {subject}. Omit to use the configured "
        "default from config.json.",
    )


def _quick_args(p) -> None:
    p.add_argument("--wordlist", required=True, help="Path to wordlist file")
    _add_rules(p)


def _brute_args(p) -> None:
    p.add_argument(
        "--min", type=int, default=1, dest="min_len", help="Minimum length (default 1)"
    )
    p.add_argument(
        "--max", type=int, default=7, dest="max_len", help="Maximum length (default 7)"
    )


def _topmask_args(p) -> None:
    p.add_argument(
        "--target-time",
        type=int,
        default=4,
        dest="target_time",
        help="Target completion time in hours (default 4)",
    )


def _fingerprint_args(p) -> None:
    p.add_argument(
        "--max-expander-len",
        type=int,
        default=21,
        dest="max_expander_len",
        help="Maximum expander fragment length to escalate to, 7-36 (default 21)",
    )
    p.add_argument(
        "--run-hybrid-on-expanded",
        action="store_true",
        dest="run_hybrid_on_expanded",
        help="Also run hybrid passes over the expanded fragments. NOTE: menu "
        "option 5 always does this; the default here is off, matching "
        "hcatFingerprint's own default, so a bare `fingerprint` runs a "
        "narrower attack than the menu entry of the same name.",
    )
    p.add_argument(
        "--dictionary-wordlist",
        default=None,
        dest="dictionary_wordlist",
        help="Wordlist to combine expanded fragments against. Omit to use the "
        "configured default.",
    )
    p.add_argument(
        "--no-dictionary-wordlist",
        action="store_true",
        dest="no_dictionary_wordlist",
        help="Skip the fragment/wordlist combination step entirely, rather "
        "than falling back to the configured wordlist.",
    )
    _add_keyspace_limit(p, "combination step")


def _smartmask_args(p) -> None:
    _add_keyspace_limit(p, "template")


def _corporate_args(p) -> None:
    p.add_argument(
        "--min",
        type=int,
        default=None,
        dest="min_len",
        help="Minimum mask length (clamped to the corporate 8-14 range)",
    )
    p.add_argument(
        "--max",
        type=int,
        default=None,
        dest="max_len",
        help="Maximum mask length (clamped to the corporate 8-14 range)",
    )


def _bandrel_args(p) -> None:
    p.add_argument(
        "--company",
        required=True,
        help="Company name(s), comma separated for multiples",
    )


def _permute_args(p) -> None:
    p.add_argument(
        "--wordlist",
        required=True,
        help="Path to a short targeted wordlist (scales as N! per word)",
    )


def _adhocmask_args(p) -> None:
    p.add_argument(
        "--mask",
        required=True,
        help="A hashcat mask (e.g. ?u?l?l?l?d?d) or a path to a .hcmask file",
    )
    p.add_argument(
        "--increment",
        action="store_true",
        dest="increment",
        help="Increment the mask length. Implied by either bound below; pass "
        "it alone to increment over the full keyspace of the mask.",
    )
    p.add_argument(
        "--increment-min",
        default="",
        dest="increment_min",
        help="Enable mask increment starting at this length",
    )
    p.add_argument(
        "--increment-max",
        default="",
        dest="increment_max",
        help="Enable mask increment stopping at this length",
    )


def _ngram_args(p) -> None:
    p.add_argument("--corpus", required=True, help="Path to the corpus file")
    p.add_argument(
        "--group-size",
        type=int,
        default=3,
        dest="group_size",
        help="N-gram group size (default 3)",
    )


def _combipow_args(p) -> None:
    p.add_argument(
        "--wordlist",
        required=True,
        help=f"Path to a wordlist of at most {COMBIPOW_MAX_LINES} lines",
    )
    p.add_argument(
        "--no-spaces",
        action="store_true",
        dest="no_spaces",
        help="Join words directly instead of separating them with spaces",
    )


def _spoonman_args(p) -> None:
    p.add_argument(
        "--corpus",
        required=True,
        help="Path to a password corpus to derive basewords and rules from",
    )
    p.add_argument(
        "--rule-coverage",
        type=int,
        default=None,
        dest="rule_coverage",
        choices=SPOONMAN_RULE_COVERAGES,
        help="Use the capped rule file reaching this percent of the corpus; "
        "omit for the full rule set.",
    )
    p.add_argument(
        "--baseword-cap",
        type=int,
        default=None,
        dest="baseword_cap",
        help="Keep at most this many derived basewords",
    )


def _omen_args(p) -> None:
    p.add_argument(
        "--max-candidates",
        type=int,
        required=True,
        dest="max_candidates",
        help="Maximum number of candidates for OMEN to enumerate",
    )


# ---------------------------------------------------------------------------
# The table
# ---------------------------------------------------------------------------

ATTACK_SPECS: tuple[AttackSpec, ...] = (
    AttackSpec(
        "quick",
        "Non-interactive quick crack (single wordlist + optional rules)",
        _quick_args,
        _run_quick,
    ),
    AttackSpec(
        "dict",
        "Non-interactive dictionary methodology (uses configured wordlists)",
        None,
        _run_dict,
    ),
    AttackSpec(
        "brute", "Non-interactive brute force (mask) attack", _brute_args, _run_brute
    ),
    AttackSpec(
        "topmask", "Non-interactive top-mask attack", _topmask_args, _run_topmask
    ),
    # --- no-argument tier ---
    AttackSpec(
        "fingerprint",
        "Fingerprint attack (expand cracked plaintexts into fragments)",
        _fingerprint_args,
        _run_fingerprint,
    ),
    AttackSpec(
        "combinator",
        "Combinator attack (concatenate two or more wordlists)",
        _combinator_args,
        _run_combinator,
    ),
    AttackSpec(
        "hybrid",
        "Hybrid attack (wordlist + mask, hashcat modes 6 and 7)",
        lambda p: _add_wordlists(p, "hybrid attack"),
        _wordlist_runner("hcatHybrid", minimum=1),
    ),
    AttackSpec(
        "pathwell",
        "Pathwell top-100 mask brute force",
        None,
        _run_bare("hcatPathwellBruteForce"),
    ),
    AttackSpec("prince", "PRINCE attack", None, _run_bare("hcatPrince")),
    AttackSpec("pcfg", "PCFG attack", None, _run_bare("hcatPCFG")),
    AttackSpec("princeling", "PRINCE-LING attack", None, _run_bare("hcatPrinceLing")),
    AttackSpec(
        "smartmask",
        "Smart mask attack (masks derived from cracked plaintext patterns)",
        _smartmask_args,
        _run_smartmask,
    ),
    AttackSpec(
        "corporate",
        "Corporate masks brute force (statistical 8-14 character masks)",
        _corporate_args,
        _run_corporate,
    ),
    # --- one-argument tier ---
    AttackSpec(
        "bandrel",
        "Bandrel methodology (company-name basewords plus masks)",
        _bandrel_args,
        _run_bandrel,
    ),
    AttackSpec(
        "permute",
        "Permutation attack (all character permutations of each word)",
        _permute_args,
        _run_permute,
    ),
    AttackSpec("adhocmask", "Ad-hoc mask attack", _adhocmask_args, _run_adhocmask),
    AttackSpec(
        "ngram",
        "N-gram attack (candidates generated from a corpus)",
        _ngram_args,
        _run_ngram,
    ),
    AttackSpec(
        "combipow",
        "Combipow passphrase attack (all combinations of a short wordlist)",
        _combipow_args,
        _run_combipow,
    ),
    AttackSpec(
        "spoonman",
        "Spoonman attack (basewords and rules derived from a corpus)",
        _spoonman_args,
        _run_spoonman,
    ),
    AttackSpec(
        "omen", "OMEN attack (Ordered Markov ENumerator)", _omen_args, _run_omen
    ),
    AttackSpec(
        "loopback",
        "Loopback attack (re-run rules against already-cracked plaintexts)",
        _add_rules,
        _run_loopback,
    ),
)

ATTACK_COMMANDS: tuple[str, ...] = tuple(spec.name for spec in ATTACK_SPECS)

_SPECS_BY_NAME: dict[str, AttackSpec] = {spec.name: spec for spec in ATTACK_SPECS}


def add_attack_subparsers(subparsers) -> None:
    """Register the non-interactive attack subcommands on an argparse
    subparsers object (the same one used for ``hashview``).

    Each subcommand carries its own required ``hashfile`` + ``hashtype``
    positionals plus attack-specific flags.
    """
    for spec in ATTACK_SPECS:
        parser = subparsers.add_parser(spec.name, help=spec.help)
        parser.add_argument("hashfile", help="Path to hash file to crack")
        parser.add_argument("hashtype", help="Hashcat hash type (e.g. 1000 for NTLM)")
        if spec.add_arguments is not None:
            spec.add_arguments(parser)
