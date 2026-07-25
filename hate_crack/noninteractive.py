"""Non-interactive (scripted) attack entry points for hate_crack.

These helpers translate parsed argparse namespaces into calls against the
existing ``hcat*`` attack functions on the main module (passed in as ``ctx``,
the same pattern ``attacks.py`` uses). See
``docs/superpowers/specs/2026-07-24-cli-noninteractive-design.md``.
"""

import os
from typing import Any

ATTACK_COMMANDS = ("quick", "dict", "brute", "topmask")


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


def run_noninteractive(ctx: Any, args: Any) -> int:
    """Run a non-interactive attack. Returns a process exit code.

    ``ctx`` is the main module (live ``hcat*`` functions, ``rulesDirectory``,
    ``resolve_path``, ``hcatHashType``/``hcatHashFile`` already set by the
    preprocessing block in ``main()``). ``args`` is the parsed subparser
    namespace whose ``command`` selects the attack.
    """
    command = args.command

    if command == "quick":
        wordlist = ctx.resolve_path(args.wordlist)
        if not wordlist or not os.path.isfile(wordlist):
            print(f"Error: wordlist not found: {args.wordlist}")
            return 1
        try:
            chains = build_rule_chains(ctx, args.rule_files)
        except (FileNotFoundError, ValueError) as exc:
            print(f"Error: invalid --rules value: {exc}")
            return 1
        for chain in chains:
            ctx.hcatQuickDictionary(
                ctx.hcatHashType,
                ctx.hcatHashFile,
                chain,
                wordlist,
                attack_name="Quick Crack",
            )
        return 0

    if command == "dict":
        ctx.hcatDictionary(ctx.hcatHashType, ctx.hcatHashFile)
        return 0

    if command == "brute":
        ctx.hcatBruteForce(
            ctx.hcatHashType, ctx.hcatHashFile, args.min_len, args.max_len
        )
        return 0

    if command == "topmask":
        ctx.hcatTopMask(ctx.hcatHashType, ctx.hcatHashFile, args.target_time * 3600)
        return 0

    print(f"Error: unknown non-interactive command: {command}")
    return 2


def add_attack_subparsers(subparsers) -> None:
    """Register the non-interactive attack subcommands on an argparse
    subparsers object (the same one used for ``hashview``).

    Each subcommand carries its own required ``hashfile`` + ``hashtype``
    positionals plus attack-specific flags.
    """

    def _add_target(p):
        p.add_argument("hashfile", help="Path to hash file to crack")
        p.add_argument("hashtype", help="Hashcat hash type (e.g. 1000 for NTLM)")

    quick = subparsers.add_parser(
        "quick", help="Non-interactive quick crack (single wordlist + optional rules)"
    )
    _add_target(quick)
    quick.add_argument("--wordlist", required=True, help="Path to wordlist file")
    quick.add_argument(
        "--rules",
        nargs="*",
        default=[],
        dest="rule_files",
        metavar="RULE",
        help="Rule filename(s) from the rules directory. Chain with '+' "
        "(e.g. best64.rule+d3ad0ne.rule). Omit to run without rules.",
    )

    dictp = subparsers.add_parser(
        "dict",
        help="Non-interactive dictionary methodology (uses configured wordlists)",
    )
    _add_target(dictp)

    brute = subparsers.add_parser(
        "brute", help="Non-interactive brute force (mask) attack"
    )
    _add_target(brute)
    brute.add_argument(
        "--min", type=int, default=1, dest="min_len", help="Minimum length (default 1)"
    )
    brute.add_argument(
        "--max", type=int, default=7, dest="max_len", help="Maximum length (default 7)"
    )

    topmask = subparsers.add_parser("topmask", help="Non-interactive top-mask attack")
    _add_target(topmask)
    topmask.add_argument(
        "--target-time",
        type=int,
        default=4,
        dest="target_time",
        help="Target completion time in hours (default 4)",
    )
