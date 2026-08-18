import glob
import os
import readline
from collections.abc import Callable
from typing import Any

from hate_crack import notify as _notify
from hate_crack.api import (
    download_hashmob_rules,
    download_hashmob_wordlists,
    weakpass_wordlist_menu,
)
from hate_crack.formatting import print_multicolumn_list
from hate_crack.hashcat_paths import hashcat_major_version
from hate_crack.llm import clean_research_field
from hate_crack.menu import interactive_menu


def _configure_readline(completer):
    readline.set_completer_delims(" \t\n;")
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
    readline.set_completer(completer)


def _select_rules(ctx) -> list[str] | None:
    """Prompt user to select rules. Returns list of rule chain strings, or None if cancelled."""
    rule_choice = None
    selected_rules = []

    rules_dir = ctx.rulesDirectory
    rule_files = ctx.list_rule_files(rules_dir)
    if not rule_files:
        download_rules = (
            input("\nNo rules found. Download rules from Hashmob now? (Y/n): ")
            .strip()
            .lower()
        )
        if download_rules in ("", "y", "yes"):
            download_hashmob_rules(print_fn=print, rules_dir=rules_dir)
            rule_files = ctx.list_rule_files(rules_dir)

    if not rule_files:
        print("No rules available. Proceeding without rules.")
        return [""]

    print("\nWhich rule(s) would you like to run?")
    rule_entries = ["0) To run without any rules"]
    rule_entries.extend([f"{i}) {file}" for i, file in enumerate(rule_files, start=1)])
    rule_entries.append("98) YOLO...run all of the rules")
    rule_entries.append("99) Back to Main Menu")
    max_rule_len = max((len(e) for e in rule_entries), default=26)
    print_multicolumn_list(
        "Available Rules",
        rule_entries,
        min_col_width=max_rule_len,
        max_col_width=max_rule_len,
    )

    example_line = ""
    if len(rule_files) >= 2:
        example_line = f"For example 1+1 will run {rule_files[0]} chained twice and 1,2 would run {rule_files[0]} and then {rule_files[1]} sequentially.\n"
    elif len(rule_files) == 1:
        example_line = f"For example 1+1 will run {rule_files[0]} chained twice.\n"

    while rule_choice is None:
        raw_choice = input(
            "Enter Comma separated list of rules you would like to run. To run rules chained use the + symbol.\n"
            f"{example_line}"
            "Choose wisely: "
        )
        if raw_choice.strip() == "99":
            return None
        if raw_choice != "":
            tokens = raw_choice.split(",")
            expanded = []
            for tok in tokens:
                tok = tok.strip()
                if "+" not in tok and "-" in tok:
                    parts = tok.split("-", 1)
                    try:
                        start, end = int(parts[0]), int(parts[1])
                        if start <= end:
                            expanded.extend(str(i) for i in range(start, end + 1))
                            continue
                    except ValueError:
                        pass
                expanded.append(tok)
            rule_choice = expanded

    if "99" in rule_choice:
        return None
    if "98" in rule_choice:
        for rule in rule_files:
            selected_rules.append(f"-r {os.path.join(rules_dir, rule)}")
    elif "0" in rule_choice:
        selected_rules = [""]
    else:
        for choice in rule_choice:
            if "+" in choice:
                combined_choice = ""
                choices = choice.split("+")
                for rule in choices:
                    try:
                        rule_path = os.path.join(rules_dir, rule_files[int(rule) - 1])
                        combined_choice = f"{combined_choice} -r {rule_path}"
                    except Exception:
                        continue
                selected_rules.append(combined_choice)
            else:
                try:
                    rule_path = os.path.join(rules_dir, rule_files[int(choice) - 1])
                    selected_rules.append(f"-r {rule_path}")
                except (IndexError, ValueError):
                    continue

    return selected_rules


def quick_crack(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("Quick Crack")
    wordlist_choice = None
    list_dir = ctx.hcatWordlists
    default_dir = ctx.hcatOptimizedWordlists

    wordlist_entries_meta = ctx.list_wordlist_entries(list_dir)
    # A trailing "/" is the marker, matching how the tab-completers already
    # render a directory. Colour is applied by print_multicolumn_list, which
    # pads on visible width; putting an escape sequence in the string here
    # would break its ljust() and its truncation.
    wordlist_entries = [
        f"{i}) {entry.name}/" if entry.is_dir else f"{i}) {entry.name}"
        for i, entry in enumerate(wordlist_entries_meta, start=1)
    ]
    entry_styles = [
        "\033[36m" if entry.is_dir else None for entry in wordlist_entries_meta
    ]
    max_entry_len = max((len(e) for e in wordlist_entries), default=24)
    print_multicolumn_list(
        "Wordlists (entries ending in / are directories: hashcat reads every file inside)",
        wordlist_entries,
        min_col_width=max_entry_len,
        max_col_width=max_entry_len,
        styles=entry_styles,
    )

    def path_completer(text, state):
        base = list_dir
        if not text:
            pattern = os.path.join(base, "*")
            matches = glob.glob(pattern)
        else:
            text = os.path.expanduser(text)
            if text.startswith(("/", "./", "../", "~")):
                matches = glob.glob(text + "*")
            else:
                pattern = os.path.join(base, text + "*")
                matches = glob.glob(pattern)
        matches = [m + "/" if os.path.isdir(m) else m for m in matches]
        try:
            return matches[state]
        except IndexError:
            return None

    _configure_readline(path_completer)

    while wordlist_choice is None:
        try:
            raw_choice = input(
                "\nEnter path of wordlist or wordlist directory (tab to autocomplete).\n"
                f"Press Enter for default wordlist directory [{default_dir}]: "
            )
            raw_choice = raw_choice.strip()
            if raw_choice == "":
                wordlist_choice = default_dir
            elif raw_choice.isdigit() and 1 <= int(raw_choice) <= len(
                wordlist_entries_meta
            ):
                chosen = os.path.join(
                    list_dir, wordlist_entries_meta[int(raw_choice) - 1].name
                )
                if os.path.exists(chosen):
                    wordlist_choice = chosen
                    print(wordlist_choice)
            elif os.path.exists(raw_choice):
                wordlist_choice = raw_choice
            else:
                wordlist_choice = None
                print("Please enter a valid wordlist or wordlist directory.")
        except ValueError:
            print("Please enter a valid number.")
    readline.set_completer(None)

    selected_rules = _select_rules(ctx)
    if selected_rules is None:
        return

    for chain in selected_rules:
        ctx.hcatQuickDictionary(
            ctx.hcatHashType,
            ctx.hcatHashFile,
            chain,
            wordlist_choice,
            attack_name="Quick Crack",
        )


def loopback_attack(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("Loopback")
    empty_wordlist = os.path.join(ctx.hcatWordlists, "empty.txt")
    os.makedirs(ctx.hcatWordlists, exist_ok=True)
    if not os.path.exists(empty_wordlist):
        with open(empty_wordlist, "w"):
            pass

    print(f"\nUsing loopback attack with wordlist: {empty_wordlist}")

    selected_rules = _select_rules(ctx)
    if selected_rules is None:
        return

    for chain in selected_rules:
        ctx.hcatQuickDictionary(
            ctx.hcatHashType,
            ctx.hcatHashFile,
            chain,
            empty_wordlist,
            loopback=True,
            attack_name="Loopback",
        )


def extensive_crack(ctx: Any) -> None:
    # Orchestrator attack: chains ~14 primitives. We suppress each primitive's
    # own notifications and fire exactly one "Extensive Crack complete" at the
    # end with the aggregate delta. This both prevents notification spam and
    # gives the user an actually-useful summary.
    _notify.prompt_notify_for_attack("Extensive Crack")
    out_path = ctx.hcatHashFile + ".out"
    cracked_before = ctx.lineCount(out_path) if os.path.exists(out_path) else 0
    with _notify.suppressed_notifications():
        ctx.hcatBruteForce(ctx.hcatHashType, ctx.hcatHashFile, "1", "7")
        ctx.hcatRecycle(ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatBruteCount)
        ctx.hcatDictionary(ctx.hcatHashType, ctx.hcatHashFile)
        ctx.hcatRecycle(ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatDictionaryCount)
        hcatTargetTime = 4 * 60 * 60
        ctx.hcatTopMask(ctx.hcatHashType, ctx.hcatHashFile, hcatTargetTime)
        ctx.hcatRecycle(ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatMaskCount)
        ctx.hcatFingerprint(
            ctx.hcatHashType,
            ctx.hcatHashFile,
            max_expander_len=21,
            run_hybrid_on_expanded=False,
            unattended=True,
        )
        ctx.hcatRecycle(ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatFingerprintCount)
        ctx.hcatCombination(ctx.hcatHashType, ctx.hcatHashFile)
        ctx.hcatRecycle(ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatCombinationCount)
        ctx.hcatHybrid(ctx.hcatHashType, ctx.hcatHashFile)
        ctx.hcatRecycle(ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatHybridCount)
        ctx.hcatGoodMeasure(ctx.hcatHashType, ctx.hcatHashFile)
        ctx.hcatRecycle(ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatExtraCount)
    cracked_after = ctx.lineCount(out_path) if os.path.exists(out_path) else 0
    _notify.notify_job_done("Extensive Crack", cracked_after, ctx.hcatHashFile)
    # Note: ``cracked_before`` is tracked for potential future per-orchestrator
    # delta reporting, but today the notify message uses the absolute count
    # because that matches what single-attack notifications already report.
    _ = cracked_before


def brute_force_crack(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("Brute Force")
    hcatMinLen = int(
        input("\nEnter the minimum password length to brute force (1): ") or 1
    )
    hcatMaxLen = int(
        input("\nEnter the maximum password length to brute force (7): ") or 7
    )
    ctx.hcatBruteForce(ctx.hcatHashType, ctx.hcatHashFile, hcatMinLen, hcatMaxLen)


def top_mask_crack(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("Top Mask")
    hcatTargetTime = int(
        input("\nEnter a target time for completion in hours (4): ") or 4
    )
    hcatTargetTime = hcatTargetTime * 60 * 60
    ctx.hcatTopMask(ctx.hcatHashType, ctx.hcatHashFile, hcatTargetTime)


def fingerprint_crack(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("Fingerprint")
    while True:
        raw = input("\nEnter max expander length to escalate to (7-36) (21): ").strip()
        if raw == "":
            max_expander_len = 21
            break
        try:
            max_expander_len = int(raw)
        except ValueError:
            print("Please enter an integer between 7 and 36.")
            continue
        if 7 <= max_expander_len <= 36:
            break
        print("Please enter an integer between 7 and 36.")

    wordlist_raw = input(
        "\nEnter a wordlist to combine expanded fragments against (blank to skip): "
    ).strip()

    ctx.hcatFingerprint(
        ctx.hcatHashType,
        ctx.hcatHashFile,
        max_expander_len=max_expander_len,
        run_hybrid_on_expanded=True,
        dictionary_wordlist=wordlist_raw or None,
    )


def combinator_crack(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("Combinator")
    print("\n" + "=" * 60)
    print("COMBINATOR ATTACK")
    print("=" * 60)
    print(
        "Combines 2-8 wordlists. 2 uses hashcat native mode; 3+ use external binaries."
    )
    print("=" * 60)

    use_default = (
        input("\nUse default combinator wordlists from config? (Y/n): ").strip().lower()
    )

    if use_default != "n":
        base = ctx.hcatCombinationWordlist
        wordlists = base if isinstance(base, list) else [base]
        wordlists = [
            ctx._resolve_wordlist_path(wl, ctx.hcatWordlists) for wl in wordlists
        ]
        if len(wordlists) < 2:
            print("\n[!] Config does not have at least 2 wordlists.")
            print("Set hcatCombinationWordlist to a list of 2+ paths in config.json.")
            print("Aborting combinator attack.")
            return
        separator = ""
    else:
        print("\nEnter 2-8 wordlists. Enter a blank line when done.")
        wordlists = _prompt_wordlist_paths(ctx, max_count=8)
        if len(wordlists) < 2:
            print("\n[!] Combinator attack requires at least 2 wordlists.")
            print("Aborting combinator attack.")
            return
        separator = input(
            "\nEnter separator between words (leave blank for none): "
        ).strip()

    if len(wordlists) == 2 and not separator:
        ctx.hcatCombination(ctx.hcatHashType, ctx.hcatHashFile, wordlists)
    elif len(wordlists) == 3 and not separator:
        ctx.hcatCombinator3(ctx.hcatHashType, ctx.hcatHashFile, wordlists)
    else:
        ctx.hcatCombinatorX(
            ctx.hcatHashType, ctx.hcatHashFile, wordlists, separator or None
        )


def hybrid_crack(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("Hybrid")
    print("\n" + "=" * 60)
    print("HYBRID ATTACK")
    print("=" * 60)
    print("This attack combines wordlists with masks to generate candidates.")
    print("Examples:")
    print("  - Mode 6: wordlist + mask (e.g., 'password' + '123')")
    print("  - Mode 7: mask + wordlist (e.g., '123' + 'password')")
    print("=" * 60)

    use_default = (
        input("\nUse default hybrid wordlist from config? (Y/n): ").strip().lower()
    )

    if use_default != "n":
        print("\nUsing default wordlist(s) from config:")
        if isinstance(ctx.hcatHybridlist, list):
            for wl in ctx.hcatHybridlist:
                print(f"  - {wl}")
            wordlists = ctx.hcatHybridlist
        else:
            print(f"  - {ctx.hcatHybridlist}")
            wordlists = [ctx.hcatHybridlist]
    else:
        print("\nSelect wordlist(s) for hybrid attack.")
        print("You can enter:")
        print("  - A single file path")
        print("  - Multiple paths separated by commas")
        print("  - Press TAB to autocomplete file paths")

        selection = ctx.select_file_with_autocomplete(
            "Enter wordlist file(s) (comma-separated for multiple)",
            allow_multiple=True,
            base_dir=ctx.hcatWordlists,
        )

        if not selection:
            print("No wordlist selected. Aborting hybrid attack.")
            return

        if isinstance(selection, str):
            wordlists = [selection]
        else:
            wordlists = selection

        valid_wordlists = []
        for wl in wordlists:
            resolved = ctx._resolve_wordlist_path(wl, ctx.hcatWordlists)
            if os.path.isfile(resolved):
                valid_wordlists.append(resolved)
                print(f"✓ Found: {resolved}")
            else:
                print(f"✗ Not found: {resolved}")

        if not valid_wordlists:
            print("\nNo valid wordlists found. Aborting hybrid attack.")
            return

        wordlists = valid_wordlists
    wordlists = [ctx._resolve_wordlist_path(wl, ctx.hcatWordlists) for wl in wordlists]

    print(f"\nStarting hybrid attack with {len(wordlists)} wordlist(s)...")
    print(f"Hash type: {ctx.hcatHashType}")
    print(f"Hash file: {ctx.hcatHashFile}")

    ctx.hcatHybrid(ctx.hcatHashType, ctx.hcatHashFile, wordlists)


def pathwell_crack(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("Pathwell Brute Force")
    ctx.hcatPathwellBruteForce(ctx.hcatHashType, ctx.hcatHashFile)


def corporate_masks_crack(ctx: Any) -> None:
    """Run Corporate Masks attack with user-selected length range.

    Corporate Masks are statistical 8-14 character hashcat masks derived from
    analysis of 3.2M NTLM hashes cracked on real engagements. Longer lengths
    cost exponentially more keyspace.
    """
    print("\n" + "=" * 60)
    print("CORPORATE MASKS ATTACK")
    print("=" * 60)
    print("Statistical masks (8-14 chars) derived from 3.2M NTLM hashes")
    print("cracked on real engagements. Longer lengths cost dramatically")
    print("more keyspace.")
    print("=" * 60)

    ceiling = ctx.CORPORATE_MASK_MAX_LEN

    def _prompt_length(label: str, floor: int, default: int) -> int:
        """Prompt for a mask length in *floor*..*ceiling*, until it's valid."""
        while True:
            raw = input(f"\nEnter {label} length ({floor}-{ceiling}) ({default}): ")
            raw = raw.strip()
            if raw == "":
                return default
            try:
                value = int(raw)
            except ValueError:
                print(f"Please enter an integer between {floor} and {ceiling}.")
                continue
            if floor <= value <= ceiling:
                return value
            print(f"Please enter an integer between {floor} and {ceiling}.")

    min_len = _prompt_length(
        "minimum", ctx.CORPORATE_MASK_MIN_LEN, ctx.CORPORATE_MASK_MIN_LEN
    )
    # The maximum's floor is the minimum just chosen, and the offered default
    # rises with it. Offering a default that the same prompt would then reject
    # is worse than offering a narrower range.
    max_len = _prompt_length(
        "maximum", min_len, max(min_len, ctx.CORPORATE_MASK_DEFAULT_MAX_LEN)
    )

    _notify.prompt_notify_for_attack("Corporate Masks")
    ctx.hcatCorporateMasks(ctx.hcatHashType, ctx.hcatHashFile, min_len, max_len)


def prince_attack(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("PRINCE")
    ctx.hcatPrince(ctx.hcatHashType, ctx.hcatHashFile)


def pcfg_attack(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("PCFG")
    ctx.hcatPCFG(ctx.hcatHashType, ctx.hcatHashFile)


def prince_ling_attack(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("PRINCE-LING")
    ctx.hcatPrinceLing(ctx.hcatHashType, ctx.hcatHashFile)


def spoonman_attack(ctx: Any) -> None:
    """Derive basewords + rules from a password corpus, then crack with them.

    Contributed as issue #169 by @Spoonman1091.
    """
    print("\n" + "=" * 60)
    print("SPOONMAN ATTACK")
    print("=" * 60)
    print("Derives a baseword list and hashcat rules from a corpus of known")
    print("passwords, such as a previous engagement's cracked output. The rule")
    print("file is sorted most-productive-first, so a capped set gets most of")
    print("the coverage for a fraction of the keyspace.")
    print("Coverage is long-tailed: the last few percent typically costs orders")
    print("of magnitude more rules than the first half, so the smallest tier is")
    print("usually the right choice.")
    print("=" * 60)

    def _prompt_for_corpus_path() -> str:
        return ctx.select_file_with_autocomplete(
            "\n[*] Enter path to password corpus", base_dir=ctx.hcatWordlists
        ).strip()

    # Cracked-password mode is only offered when this session actually has
    # plaintexts to derive from, matching ollama_attack's has_cracked check.
    # An operator with no cracked output yet must see exactly today's
    # behaviour: no menu, straight to the path prompt.
    out_path = f"{ctx.hcatHashFile}.out"
    has_cracked = os.path.isfile(out_path) and os.path.getsize(out_path) > 0

    if has_cracked:
        corpus = _offer_cracked_or(
            out_path,
            "\nSpoonman Attack — corpus source",
            "Password corpus file",
            _prompt_for_corpus_path,
        )
    else:
        corpus = _prompt_for_corpus_path()

    if not corpus:
        print("[!] No corpus specified.")
        return
    if not os.path.isfile(corpus):
        print(f"[!] Corpus not found: {corpus}")
        return

    items = [
        ("1", "Top 50% coverage (smallest, most productive rules)"),
        ("2", "Top 75% coverage"),
        ("3", "Top 95% coverage"),
        ("4", "Top 99% coverage"),
        ("5", "Full rule set (largest; can be millions of rules)"),
        ("99", "Back to Main Menu"),
    ]
    choice = interactive_menu(items, title="\nRule set size:")
    if choice is None or choice == "99":
        return
    coverage = {"1": 50, "2": 75, "3": 95, "4": 99, "5": None}.get(choice)

    _notify.prompt_notify_for_attack("Spoonman")
    ctx.hcatSpoonman(ctx.hcatHashType, ctx.hcatHashFile, corpus, coverage=coverage)


def _prompt_positive_int(prompt: str, default: int | None) -> int | None:
    """Prompt for a positive integer. Blank keeps *default*, 0 means unlimited."""
    while True:
        raw = input(prompt).strip()
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError:
            print("[!] Enter a number.")
            continue
        if value < 0:
            print("[!] Enter zero or a positive number.")
            continue
        return value or None


def _select_debug_logs(ctx) -> list[str] | None:
    """Pick the hashcat --debug-mode 5 logs to mine. None if cancelled."""
    logs = ctx.rosetta_debug_logs()
    items = []
    for idx, path in enumerate(logs[:20], 1):
        # Size rather than a line count: these logs routinely reach hundreds of
        # megabytes, and stat'ing 20 of them must stay instant. A log can also
        # be rotated away between the listing and the stat, which is not worth
        # aborting the menu over.
        try:
            label = (
                f"{os.path.basename(path)} ({os.path.getsize(path) / 1048576:.1f} MB)"
            )
        except OSError:
            label = f"{os.path.basename(path)} (unreadable)"
        items.append((str(idx), label))
    if logs:
        items.append(("a", "All logs listed above"))
    items.append(("p", "Enter a debug log path manually"))
    items.append(("99", "Back to Main Menu"))

    title = f"\nDebug logs in {ctx.hcatDebugLogPath}:"
    if not logs:
        title = f"\nNo debug logs found in {ctx.hcatDebugLogPath}."
    choice = interactive_menu(items, title=title)
    if choice is None or choice == "99":
        return None
    if choice == "a":
        return logs[:20]
    if choice == "p":
        path = ctx.select_file_with_autocomplete(
            "\n[*] Enter path to hashcat debug log", base_dir=ctx.hcatDebugLogPath
        ).strip()
        if not path:
            print("[!] No debug log specified.")
            return None
        if not os.path.isfile(path):
            print(f"[!] Debug log not found: {path}")
            return None
        return [path]
    if choice.isdigit() and 1 <= int(choice) <= len(logs[:20]):
        return [logs[int(choice) - 1]]
    print("[!] Invalid selection.")
    return None


def rosetta_attack(ctx: Any) -> None:
    """Mine debug-mode logs for winning rules/basewords, or run an LLM mask attack."""
    print("\n" + "=" * 60)
    print("ROSETTA ATTACK")
    print("=" * 60)

    items = [
        ("1", "Application frequency (rules applied most often)"),
        ("2", "Baseword spread (rules that worked across the most basewords)"),
        ("3", "Candidate variety (rules producing the most unique candidates)"),
        ("4", "LLM Mask Attack (natural language -> hcmask)"),
        ("99", "Back to Main Menu"),
    ]
    choice = interactive_menu(items, title="\nSelect Rosetta mode:")
    if choice is None or choice == "99":
        return

    if choice == "4":
        description = input(
            "\n[*] Describe the passwords you expect (patterns, length, "
            "symbols, etc.): "
        ).strip()
        if not description:
            print("[!] Description cannot be empty.")
            return
        _notify.prompt_notify_for_attack("Rosetta Mask")
        ctx.hcatRosettaMask(ctx.hcatHashType, ctx.hcatHashFile, description)
        return

    print("Mines hashcat --debug-mode 5 logs, which hate_crack writes for every")
    print("rule-based attack, for the basewords and rules that actually cracked")
    print("something. Those are then run as a full cross product: each winning")
    print("rule gets tried against every winning baseword, not just the one it")
    print("was originally paired with.")
    print("=" * 60)

    metric = {"1": "frequency", "2": "basewords", "3": "candidates"}.get(choice)
    if metric is None:
        print("[!] Invalid selection.")
        return

    debug_files = _select_debug_logs(ctx)
    if not debug_files:
        return

    top_rules = _prompt_positive_int(
        "\n[*] Number of top rules to keep [default all, 0 for all]: ", None
    )
    top_basewords = _prompt_positive_int(
        "[*] Number of top basewords to keep [default all, 0 for all]: ", None
    )

    _notify.prompt_notify_for_attack("Rosetta")
    ctx.hcatRosetta(
        ctx.hcatHashType,
        ctx.hcatHashFile,
        debug_files,
        metric=metric,
        top_rules=top_rules,
        top_basewords=top_basewords,
    )


def yolo_combination(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("YOLO Combination")
    ctx.hcatYoloCombination(ctx.hcatHashType, ctx.hcatHashFile)


def thorough_combinator(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("Thorough Combinator")
    ctx.hcatThoroughCombinator(ctx.hcatHashType, ctx.hcatHashFile)


def middle_combinator(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("Middle Combinator")
    ctx.hcatMiddleCombinator(ctx.hcatHashType, ctx.hcatHashFile)


def _prompt_wordlist_paths(ctx, max_count: int) -> list[str]:
    """Prompt for wordlist paths one at a time with tab-autocomplete.

    Stops when a blank line is entered or max_count paths have been collected.
    Returns a list of resolved, valid file paths.
    """

    def path_completer(text, state):
        base = ctx.hcatWordlists
        if not text:
            pattern = os.path.join(base, "*")
            matches = glob.glob(pattern)
        else:
            expanded = os.path.expanduser(text)
            if expanded.startswith(("/", "./", "../", "~")):
                matches = glob.glob(expanded + "*")
            else:
                pattern = os.path.join(base, expanded + "*")
                matches = glob.glob(pattern)
        matches = [m + "/" if os.path.isdir(m) else m for m in matches]
        try:
            return matches[state]
        except IndexError:
            return None

    _configure_readline(path_completer)

    collected: list[str] = []
    count = 1
    while len(collected) < max_count:
        raw = input(
            f"\nWordlist #{count} (tab to autocomplete, blank to finish): "
        ).strip()
        if not raw:
            break
        resolved = ctx._resolve_wordlist_path(raw, ctx.hcatWordlists)
        if os.path.isfile(resolved):
            collected.append(resolved)
            print(f"Added: {resolved}")
            count += 1
        else:
            print(f"Not found: {resolved}")
    readline.set_completer(None)
    return collected


def bandrel_method(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("Bandrel")
    ctx.hcatBandrel(ctx.hcatHashType, ctx.hcatHashFile)


def _research_target_suggestions(ctx: Any, company: str) -> dict[str, str]:
    """Ask the local model for industry/location/parent-company suggestions for *company*.

    Returns a dict of cleaned suggestion strings (values may be ''). Research is
    a convenience only, so any failure is swallowed here as well as in
    ``hcatOllamaResearchTarget``: the operator still gets blank prompts and the
    attack proceeds.
    """
    if not company:
        return {}

    try:
        raw = ctx.hcatOllamaResearchTarget(company)
    except Exception as e:
        print(f"Note: target research unavailable ({e}) — enter the details manually.")
        return {}

    suggestions = {}
    if isinstance(raw, dict):
        for key in ("industry", "location", "parent_company"):
            value = clean_research_field(raw.get(key, ""))
            if value:
                suggestions[key] = value

    if suggestions:
        print(
            "\n[!] The values in parentheses below are the local model's GUESSES, "
            "not verified OSINT."
        )
        print("    Press Enter to accept, or type your own value to override.")
    return suggestions


def _prompt_with_default(label: str, default: Any) -> str:
    """Prompt for *label*, showing *default* in parentheses when there is one."""
    suggestion = clean_research_field(default)
    if suggestion:
        return input(f"{label} ({suggestion}): ").strip() or suggestion
    return input(f"{label}: ").strip()


def _offer_cracked_or(
    cracked_path: str,
    title: str,
    fallback_label: str,
    fallback: Callable[[], str | None],
) -> str | None:
    """Offer *cracked_path* as a source, falling back to *fallback* on request.

    Shared by the LLM pattern picker and Spoonman: both present "cracked
    passwords from this session" as option 1 and a mode-specific fallback as
    option 2, because plaintexts already recovered from this target reveal
    its real conventions — a generic corpus only reveals the internet's.
    Only called when the caller has already confirmed cracked output exists;
    it does not itself decide availability.
    """
    items = [
        ("1", "Cracked passwords (current session)"),
        ("2", fallback_label),
        ("99", "Cancel"),
    ]
    while True:
        choice = interactive_menu(items, title=title, prompt="\n\tSelect source: ")
        if choice is None or choice == "99":
            return None
        if choice == "1":
            return cracked_path
        if choice == "2":
            return fallback()
        print("\t[!] Invalid selection.")


def _pick_pattern_source(ctx: Any, cracked_path: str | None):
    """Pick the corpus the LLM infers patterns from. Returns a path or None.

    Cracked passwords are offered first and only when *cracked_path* is set,
    because plaintexts already recovered from this target reveal its real
    conventions — a generic wordlist only reveals the internet's.
    """
    if cracked_path:
        return _offer_cracked_or(
            cracked_path,
            "\nLLM Pattern Rules — pattern source",
            "Sample wordlist",
            lambda: _pick_training_wordlist(ctx, title="LLM Pattern Source Wordlists"),
        )

    return _pick_training_wordlist(ctx, title="LLM Pattern Source Wordlists")


def ollama_attack(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("LLM")
    # Cracked-password mode is only offered when this session actually has
    # plaintexts to learn from, matching _markov_pick_training_source.
    out_path = f"{ctx.hcatHashFile}.out"
    has_cracked = os.path.isfile(out_path) and os.path.getsize(out_path) > 0

    items: list[tuple[str, str]] = [
        ("1", "Target info (company / industry / location)"),
        ("2", "Wordlist (generate basewords from a sample wordlist)"),
    ]
    if has_cracked:
        items.append(("3", "Cracked passwords (current session)"))
    # Deliberately "4" whether or not "3" was offered: renumbering it per
    # session would move the option under an operator between runs.
    items.append(("4", "Pattern rules (LLM generates basewords and hashcat rules)"))
    items.append(("99", "Cancel"))

    while True:
        choice = interactive_menu(
            items, title="\nLLM Attack", prompt="\n\tSelect generation mode: "
        )
        if choice is None or choice == "99":
            return
        if choice == "1":
            company = input("Company name: ").strip()
            suggestions = _research_target_suggestions(ctx, company)
            industry = _prompt_with_default("Industry", suggestions.get("industry"))
            location = _prompt_with_default("Location", suggestions.get("location"))
            parent_company = _prompt_with_default(
                "Parent company / acquired by", suggestions.get("parent_company")
            )
            ctx.hcatOllama(
                ctx.hcatHashType,
                ctx.hcatHashFile,
                "target",
                {
                    "company": company,
                    "industry": industry,
                    "location": location,
                    "parent_company": parent_company,
                },
            )
            return
        elif choice == "2":
            path = _pick_training_wordlist(ctx, title="LLM Sample Wordlists")
            if not path:
                return
            ctx.hcatOllama(ctx.hcatHashType, ctx.hcatHashFile, "wordlist", path)
            return
        elif choice == "3" and has_cracked:
            ctx.hcatOllama(ctx.hcatHashType, ctx.hcatHashFile, "cracked", out_path)
            return
        elif choice == "4":
            source = _pick_pattern_source(ctx, out_path if has_cracked else None)
            if not source:
                return
            # No rule prompt: the model writes the rule file too, which is the
            # point of the mode — see hcatOllamaPatterns.
            ctx.hcatOllamaPatterns(ctx.hcatHashType, ctx.hcatHashFile, source)
            return
        else:
            # Without this the menu just silently redraws and the user cannot
            # tell a rejected key from a repainted prompt.
            print("\t[!] Invalid selection.")


def _pick_training_wordlist(ctx: Any, title: str = "Training Wordlists"):
    """Show wordlist picker. Returns path or None (user cancelled with 'q')."""
    entries_meta = ctx.list_wordlist_entries(ctx.hcatWordlists)
    # Print the grid once, outside the retry loop: a wordlists directory can
    # hold dozens of entries, and repainting the whole thing after every typo
    # buries the error message.
    if entries_meta:
        entries = [
            f"{i}) {entry.name}/" if entry.is_dir else f"{i}) {entry.name}"
            for i, entry in enumerate(entries_meta, start=1)
        ]
        entry_styles = ["\033[36m" if entry.is_dir else None for entry in entries_meta]
        max_len = max((len(e) for e in entries), default=24)
        print_multicolumn_list(
            title,
            entries,
            min_col_width=max_len,
            max_col_width=max_len,
            styles=entry_styles,
        )
    print("\tp. Enter a custom path")
    print("\tq. Cancel")
    while True:
        sel = input("\n\tSelect wordlist: ").strip()
        if sel.lower() == "q":
            return None
        if sel.lower() == "p":
            path = ctx.select_file_with_autocomplete(
                "\tPath to wordlist (tab to autocomplete)"
            )
            return path.strip() if path else None
        try:
            idx = int(sel)
            if 1 <= idx <= len(entries_meta):
                entry = entries_meta[idx - 1]
                if entry.is_dir:
                    # Training takes one corpus file. Refusing here beats
                    # failing inside hcatOmenTrain/hcatMarkovTrain, where the
                    # error names a path and not the mistake.
                    print(
                        f"\t[!] {entry.name}/ is a directory. "
                        "Pick a single file, or use 'p' for a path."
                    )
                    continue
                return os.path.join(ctx.hcatWordlists, entry.name)
        except (ValueError, IndexError):
            pass
        print("\t[!] Invalid selection.")


def omen_attack(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("OMEN")
    print("\n\tOMEN Attack (Ordered Markov ENumerator)")
    omen_dir = os.path.join(ctx.hate_path, "omen")
    create_bin = os.path.join(omen_dir, ctx.hcatOmenCreateBin)
    enum_bin = os.path.join(omen_dir, ctx.hcatOmenEnumBin)
    if not os.path.isfile(create_bin) or not os.path.isfile(enum_bin):
        print("\n\tOMEN binaries not found. Build them with:")
        print(f"\t  cd {omen_dir} && make")
        return

    model_dir = ctx._omen_model_dir()
    model_valid = ctx._omen_model_is_valid(model_dir)
    need_training = True

    if model_valid:
        info = ctx._omen_model_info(model_dir)
        trained_with = info.get("training_file", "unknown") if info else "unknown"
        print(f"\n\tOMEN model found (trained with: {trained_with})")
        model_items = [
            ("1", "Use existing model"),
            ("2", "Train new model (overwrites existing)"),
            ("99", "Cancel"),
        ]
        while True:
            choice = interactive_menu(
                model_items,
                title="\nOMEN Attack (Ordered Markov ENumerator)",
                prompt="\n\tChoice: ",
            )
            if choice is None or choice == "99":
                return
            if choice == "1":
                need_training = False
                break
            elif choice == "2":
                break
    else:
        print("\n\tNo valid OMEN model found. Training is required.")

    if need_training:
        training_file = _pick_training_wordlist(ctx)
        if not training_file:
            return
        if not ctx.hcatOmenTrain(training_file):
            print("\n\t[!] Training failed. Aborting OMEN attack.")
            return

    max_candidates = input(
        f"\n\tMax candidates to generate ({ctx.omenMaxCandidates}): "
    ).strip()
    if not max_candidates:
        max_candidates = str(ctx.omenMaxCandidates)

    selected_rules = _select_rules(ctx)
    if selected_rules is None:
        return

    for chain in selected_rules:
        ctx.hcatOmen(ctx.hcatHashType, ctx.hcatHashFile, int(max_candidates), chain)


def _markov_pick_training_source(ctx: Any):
    """Prompt user to select markov training source. Returns file path or None (user cancelled with 'q')."""
    out_path = f"{ctx.hcatHashFile}.out"
    has_cracked = os.path.isfile(out_path) and os.path.getsize(out_path) > 0

    entries_meta = ctx.list_wordlist_entries(ctx.hcatWordlists)
    # Print the grid once, outside the retry loop — see _pick_training_wordlist.
    entries = []
    entry_styles = []
    if has_cracked:
        entries.append("0) Cracked passwords (current session)")
        entry_styles.append(None)
    entries.extend(
        f"{i}) {entry.name}/" if entry.is_dir else f"{i}) {entry.name}"
        for i, entry in enumerate(entries_meta, start=1)
    )
    entry_styles.extend("\033[36m" if entry.is_dir else None for entry in entries_meta)
    if entries:
        max_len = max((len(e) for e in entries), default=24)
        print_multicolumn_list(
            "Markov Training Source",
            entries,
            min_col_width=max_len,
            max_col_width=max_len,
            styles=entry_styles,
        )
    print("\tp. Enter a custom path")
    print("\tq. Cancel")
    while True:
        sel = input("\n\tSelect training source: ").strip()
        if sel.lower() == "q":
            return None
        if sel == "0" and has_cracked:
            return out_path
        if sel.lower() == "p":
            path = ctx.select_file_with_autocomplete(
                "\tPath to training file (tab to autocomplete)"
            )
            return path.strip() if path else None
        try:
            idx = int(sel)
            if 1 <= idx <= len(entries_meta):
                entry = entries_meta[idx - 1]
                if entry.is_dir:
                    # Training takes one corpus file. Refusing here beats
                    # failing inside hcatOmenTrain/hcatMarkovTrain, where the
                    # error names a path and not the mistake.
                    print(
                        f"\t[!] {entry.name}/ is a directory. "
                        "Pick a single file, or use 'p' for a path."
                    )
                    continue
                return os.path.join(ctx.hcatWordlists, entry.name)
        except (ValueError, IndexError):
            pass
        print("\t[!] Invalid selection.")


# hashcat <= 6 has -1 through -4; hashcat 7 added -5 through -8.
_CLASSIC_CHARSET_SLOTS = ("1", "2", "3", "4")
_EXTENDED_CHARSET_SLOTS = ("5", "6", "7", "8")
_EXTENDED_CHARSET_MAJOR = 7


def _custom_charset_slots(mask: str) -> list[int]:
    """Return the `?1`-`?8` slots a mask references, ascending and deduplicated.

    Scans token by token rather than substring-matching, because `??` is
    hashcat's escape for a literal `?`: in `??1` the `1` is a literal
    character, not a reference to charset 1.
    """
    slots: set[int] = set()
    i = 0
    while i < len(mask) - 1:
        if mask[i] == "?":
            code = mask[i + 1]
            if code in _CLASSIC_CHARSET_SLOTS + _EXTENDED_CHARSET_SLOTS:
                slots.add(int(code))
            # Skip the token character too, so an escaped `??` cannot let the
            # second `?` open a token with whatever follows it.
            i += 2
            continue
        i += 1
    return sorted(slots)


def _hashcat_major(ctx: Any) -> int | None:
    """Best-effort major version of the hashcat this run will invoke."""
    hcat_bin = getattr(ctx, "hcatBin", None)
    if not isinstance(hcat_bin, str) or not hcat_bin:
        return None
    return hashcat_major_version(hcat_bin)


def _extended_charsets_available(ctx: Any) -> bool:
    """Whether ?5-?8 can be used. Unknown versions are assumed too old."""
    major = _hashcat_major(ctx)
    return major is not None and major >= _EXTENDED_CHARSET_MAJOR


def _warn_if_extended_unsupported(ctx: Any, slots: list[int]) -> None:
    """Say so when a mask uses ?5-?8 on a hashcat known to predate them.

    Only a *known* older version warns: if the version could not be read, the
    mask goes through and hashcat reports the problem itself, which beats
    refusing a mask that would have worked.
    """
    if not any(slot > len(_CLASSIC_CHARSET_SLOTS) for slot in slots):
        return
    major = _hashcat_major(ctx)
    if major is None or major >= _EXTENDED_CHARSET_MAJOR:
        return
    print(
        f"\t[!] ?5-?8 need hashcat 7 or newer; this is hashcat {major}. "
        "The mask will be rejected."
    )


def _prompt_increment() -> tuple[bool, str, str]:
    """Ask whether to run the mask incrementally, and for optional bounds.

    Returns ``(increment, min, max)`` with the bounds as strings so that a
    blank answer stays blank all the way down to the command builder — an
    omitted bound is hashcat's own default, not a number to invent here.
    """
    if input("\nIncrement mask length? (y/N): ").strip().lower() not in ("y", "yes"):
        return False, "", ""

    print("\tLeave both blank to increment over the full keyspace of the mask.")
    low = _prompt_length("\tIncrement min [blank for full keyspace]: ")
    while True:
        high = _prompt_length("\tIncrement max [blank for full keyspace]: ")
        if low and high and int(high) < int(low):
            print(f"\t[!] Increment max must be at least {low}.")
            continue
        return True, low, high


def _prompt_length(prompt: str) -> str:
    """Read an optional positive integer, re-asking until the answer is one."""
    while True:
        answer = input(prompt).strip()
        if not answer:
            return ""
        if answer.isdigit() and int(answer) > 0:
            return answer
        print("\t[!] Enter a positive whole number, or leave blank.")


def adhoc_mask_crack(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("Ad-hoc Mask")
    print("\n\tAd-hoc Mask Attack")
    print("\t1. Type a mask")
    print("\t2. Use a mask file (.hcmask)")
    choice = input("\tSelect [1]: ").strip() or "1"

    if choice == "2":
        masks_dir = os.path.join(ctx.hate_path, "masks")
        mask = ctx.select_file_with_autocomplete(
            "\tPath to mask file (tab to autocomplete)",
            base_dir=masks_dir,
        )
        mask = mask.strip() if mask else ""
        if not mask:
            return
        if not os.path.isfile(mask):
            print(f"\t[!] Mask file not found: {mask}")
            return
        increment, inc_min, inc_max = _prompt_increment()
        ctx.hcatAdHocMask(
            ctx.hcatHashType,
            ctx.hcatHashFile,
            mask,
            "",
            increment=increment,
            increment_min=inc_min,
            increment_max=inc_max,
        )
        return

    custom_range = "?1-?8" if _extended_charsets_available(ctx) else "?1-?4"
    print(
        "\nEnter a hashcat mask. Tokens: ?l=lower ?u=upper ?d=digit ?s=special "
        f"?a=all ?b=binary {custom_range}=custom"
    )
    mask = input("Mask (e.g. ?u?l?l?l?d?d): ").strip()
    if not mask:
        return

    slots = _custom_charset_slots(mask)
    _warn_if_extended_unsupported(ctx, slots)

    charset_flags = []
    for i in slots:
        cs = input(f"Custom charset -{i} [leave blank to skip]: ").strip()
        if cs:
            charset_flags.extend([f"-{i}", cs])
        else:
            # A blank answer skips this slot only: a mask may use ?1 and ?3
            # without defining ?2 (issue #205). Since the slot was only asked
            # about because the mask uses it, say what skipping costs.
            print(
                f"\t[!] ?{i} is used in the mask but left undefined - "
                "hashcat will reject the mask."
            )

    increment, inc_min, inc_max = _prompt_increment()

    ctx.hcatAdHocMask(
        ctx.hcatHashType,
        ctx.hcatHashFile,
        mask,
        " ".join(charset_flags),
        increment=increment,
        increment_min=inc_min,
        increment_max=inc_max,
    )


def markov_brute_force(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("Markov Brute Force")
    print("\n\tMarkov Brute Force Attack")
    hcstat2_path = f"{ctx.hcatHashFile}.hcstat2"
    need_training = True

    if os.path.isfile(hcstat2_path):
        print(f"\n\tMarkov table found: {hcstat2_path}")
        print("\t1. Use existing table")
        print("\t2. Generate new table (overwrites existing)")
        print("\t3. Cancel")
        choice = input("\n\tChoice: ").strip()
        if choice == "1":
            need_training = False
        elif choice == "3":
            return
        elif choice != "2":
            return
    else:
        print("\n\tNo markov table found. Generation is required.")

    if need_training:
        source = _markov_pick_training_source(ctx)
        if not source:
            return
        if not ctx.hcatMarkovTrain(source, ctx.hcatHashFile):
            print("\n\t[!] Markov table generation failed. Aborting.")
            return

    hcatMinLen = int(
        input("\nEnter the minimum password length to brute force (1): ") or 1
    )
    hcatMaxLen = int(
        input("\nEnter the maximum password length to brute force (7): ") or 7
    )
    ctx.hcatMarkovBruteForce(ctx.hcatHashType, ctx.hcatHashFile, hcatMinLen, hcatMaxLen)


def combipow_crack(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("Combipow")
    wordlist = None
    while wordlist is None:
        path = ctx.select_file_with_autocomplete(
            "Enter path to wordlist (max 63 lines recommended, tab to autocomplete)"
        )
        path = path.strip() if path else ""
        if not path:
            continue
        if not os.path.isfile(path):
            print(f"[!] File not found: {path}")
            continue
        with ctx._open_wordlist(path) as fh:
            line_count = sum(1 for _ in fh)
        if line_count > 63:
            print(
                f"[!] Wordlist has {line_count} lines (max 63). combipow generates 2^n-1 combinations."
            )
            return
        if line_count > 20:
            print(
                f"[*] Warning: {line_count} lines will generate a large number of combinations."
            )
        wordlist = path
    use_space_sep = input("\nAdd spaces between words? (Y/n): ").strip().lower() != "n"
    ctx.hcatCombipow(ctx.hcatHashType, ctx.hcatHashFile, wordlist, use_space_sep)


def generate_rules_crack(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("Random Rules")
    print("\n" + "=" * 60)
    print("RANDOM RULES ATTACK")
    print("=" * 60)
    print("Generates random hashcat mutation rules and applies them to a wordlist.")
    print(
        "Use when known rulesets are exhausted - a chaos mode for rule-space exploration."
    )
    print("=" * 60)

    raw_count = input("\nNumber of random rules to generate (65536): ").strip()
    try:
        rule_count = int(raw_count) if raw_count else 65536
        if rule_count < 1:
            print("[!] Rule count must be at least 1.")
            return
    except ValueError:
        print("[!] Invalid rule count.")
        return

    entries_meta = ctx.list_wordlist_entries(ctx.hcatWordlists)
    wordlist_entries = [
        f"{i}) {entry.name}/" if entry.is_dir else f"{i}) {entry.name}"
        for i, entry in enumerate(entries_meta, start=1)
    ]
    entry_styles = ["\033[36m" if entry.is_dir else None for entry in entries_meta]
    max_entry_len = max((len(e) for e in wordlist_entries), default=24)
    print_multicolumn_list(
        "Wordlists",
        wordlist_entries,
        min_col_width=max_entry_len,
        max_col_width=max_entry_len,
        styles=entry_styles,
    )

    def path_completer(text, state):
        base = ctx.hcatWordlists
        if not text:
            pattern = os.path.join(base, "*")
            matches = glob.glob(pattern)
        else:
            text = os.path.expanduser(text)
            if text.startswith(("/", "./", "../", "~")):
                matches = glob.glob(text + "*")
            else:
                pattern = os.path.join(base, text + "*")
                matches = glob.glob(pattern)
        matches = [m + "/" if os.path.isdir(m) else m for m in matches]
        try:
            return matches[state]
        except IndexError:
            return None

    _configure_readline(path_completer)

    wordlist_choice = None
    while wordlist_choice is None:
        try:
            raw_choice = input(
                "\nEnter path of wordlist (tab to autocomplete).\n"
                f"Press Enter for default wordlist directory [{ctx.hcatWordlists}]: "
            )
            raw_choice = raw_choice.strip()
            if raw_choice == "":
                wordlist_choice = ctx.hcatWordlists
            elif raw_choice.isdigit() and 1 <= int(raw_choice) <= len(entries_meta):
                chosen = os.path.join(
                    ctx.hcatWordlists, entries_meta[int(raw_choice) - 1].name
                )
                if os.path.isdir(chosen) or os.path.isfile(chosen):
                    wordlist_choice = chosen
                    print(wordlist_choice)
                else:
                    print(f"[!] {chosen} no longer exists.")
            elif os.path.exists(raw_choice):
                wordlist_choice = raw_choice
            else:
                print("[!] Wordlist not found. Please enter a valid path.")
                readline.set_completer(None)
                return
        except ValueError:
            print("Please enter a valid number.")
    readline.set_completer(None)

    ctx.hcatGenerateRules(
        ctx.hcatHashType, ctx.hcatHashFile, rule_count, wordlist_choice
    )


def restore_potfile_output(ctx: Any) -> None:
    print("\n" + "=" * 60)
    print("REGENERATE .out FROM POT FILE")
    print("=" * 60)
    print("Rebuilds <hashfile>.out from the hashcat POT file, replacing its")
    print("current contents. Useful when the output file has been truncated or")
    print("lost but the POT file still holds the cracked hashes.")
    print("=" * 60 + "\n")

    ctx.restore_from_potfile()


def ngram_attack(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("N-gram")
    print("\n" + "=" * 60)
    print("NGRAM ATTACK")
    print("=" * 60)
    print("Generates n-gram candidates from a corpus file via ngramX.bin.")
    print("Gzip-compressed corpus files are auto-detected and decompressed.")
    print("=" * 60)

    corpus = ctx.select_file_with_autocomplete(
        "Select corpus file (tab to autocomplete)",
        base_dir=ctx.hcatWordlists,
    )
    if not corpus:
        print("No corpus selected. Aborting ngram attack.")
        return

    group_size_raw = input("\nEnter n-gram group size (3): ").strip()
    try:
        group_size = int(group_size_raw) if group_size_raw else 3
    except ValueError:
        print("[!] Invalid group size. Using default of 3.")
        group_size = 3

    ctx.hcatNgramX(ctx.hcatHashType, ctx.hcatHashFile, corpus, group_size)


def permute_crack(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("Permute")
    print("\n" + "=" * 60)
    print("PERMUTATION ATTACK")
    print("=" * 60)
    print("Generates ALL character permutations of each word in a targeted wordlist.")
    print(
        "WARNING: Scales as N! per word. Only practical for words up to ~8 characters."
    )
    print("Best for: short targeted wordlists (names, abbreviations, known fragments).")
    print("=" * 60)

    def path_completer(text, state):
        base = ctx.hcatWordlists
        if not text:
            pattern = os.path.join(base, "*")
            matches = glob.glob(pattern)
        else:
            text = os.path.expanduser(text)
            if text.startswith(("/", "./", "../", "~")):
                matches = glob.glob(text + "*")
            else:
                pattern = os.path.join(base, text + "*")
                matches = glob.glob(pattern)
        matches = [m + "/" if os.path.isdir(m) else m for m in matches]
        try:
            return matches[state]
        except IndexError:
            return None

    _configure_readline(path_completer)

    wordlist_path = None
    while wordlist_path is None:
        raw = input("\nEnter path to a wordlist FILE (tab to autocomplete): ").strip()
        if not raw:
            continue
        if not os.path.exists(raw):
            print(f"[!] Path not found: {raw}")
            continue
        if os.path.isdir(raw):
            print("[!] A directory was provided. Please enter a single wordlist file.")
            continue
        wordlist_path = raw
    readline.set_completer(None)

    ctx.hcatPermute(ctx.hcatHashType, ctx.hcatHashFile, wordlist_path)


def combinator_submenu(ctx: Any) -> None:
    items = [
        ("1", "Combinator Attack (2-8 wordlists)"),
        ("2", "YOLO Combinator Attack"),
        ("3", "Middle Combinator Attack"),
        ("4", "Thorough Combinator Attack"),
        ("99", "Back to Main Menu"),
    ]
    while True:
        choice = interactive_menu(items, title="\nCombinator Attacks:")
        if choice is None or choice == "99":
            break
        elif choice == "1":
            combinator_crack(ctx)
        elif choice == "2":
            yolo_combination(ctx)
        elif choice == "3":
            middle_combinator(ctx)
        elif choice == "4":
            thorough_combinator(ctx)


def _rule_select_file(ctx: Any, prompt: str = "Rule file: ") -> str:
    """Prompt for a rule file path with tab-autocomplete."""
    import glob as _glob

    def rule_completer(text: str, state: int) -> str | None:
        base = ctx.rulesDirectory
        if not text:
            pattern = os.path.join(base, "*")
        else:
            text = os.path.expanduser(text)
            if text.startswith(("/", "./", "../", "~")):
                pattern = text + "*"
            else:
                pattern = os.path.join(base, text + "*")
        # Glob once per branch, on the same resolved pattern, then filter and
        # mark from that single candidate list -- deriving directory markers
        # from a separately hardcoded join broke the free-path branches
        # (./..., ../...), since os.path.join only discards `base` when the
        # second argument is absolute.
        candidates = _glob.glob(pattern)
        matches = [
            entry + "/" if os.path.isdir(entry) else entry
            for entry in candidates
            # Directories are always offered -- you have to be able to walk
            # into one. Files are limited to *.rule, matching the empty-input
            # case, so typing a character does not surface notes or backups
            # the empty prompt hides. Filtering post-glob (rather than baking
            # ".rule" into the glob pattern) keeps incremental completion
            # working once the typed text reaches the extension itself, e.g.
            # "best64.r" still matches "best64.rule".
            if os.path.isdir(entry) or entry.endswith(".rule")
        ]
        matches = sorted(set(matches))
        try:
            return matches[state]
        except IndexError:
            return None

    _configure_readline(rule_completer)
    try:
        return input(prompt).strip()
    finally:
        readline.set_completer(None)


def rule_cleanup_handler(ctx: Any) -> None:
    """Clean a rule file using cleanup-rules.bin."""
    print("\nClean rule file - removes invalid and duplicate rules.")
    print("Reads an input rule file and writes cleaned rules to an output file.\n")
    infile = _rule_select_file(ctx, "Input rule file (tab to autocomplete): ")
    if not infile or not os.path.isfile(infile):
        print(f"[!] File not found: {infile}")
        return
    outfile = ctx.select_file_with_autocomplete(
        "Output file path (tab to autocomplete)"
    )
    outfile = outfile.strip() if outfile else ""
    if not outfile:
        print("[!] Output path required.")
        return
    print(f"\nCleaning {infile} -> {outfile}")
    if ctx.rules_cleanup(infile, outfile):
        print("[+] Done.")
    else:
        print("[!] Cleanup failed.")


def rule_optimize_handler(ctx: Any) -> None:
    """Optimize a rule file using rules_optimize.bin."""
    print("\nOptimize rule file - consolidates redundant operations.")
    infile = _rule_select_file(ctx, "Input rule file: ")
    if not infile or not os.path.isfile(infile):
        print(f"[!] File not found: {infile}")
        return
    outfile = ctx.select_file_with_autocomplete(
        "Output file path (tab to autocomplete)"
    )
    outfile = outfile.strip() if outfile else ""
    if not outfile:
        print("[!] Output path required.")
        return
    print(f"\nOptimizing {infile} -> {outfile}")
    if ctx.rules_optimize(infile, outfile):
        print("[+] Done.")
    else:
        print("[!] Optimize failed.")


def rule_cleanup_and_optimize_handler(ctx: Any) -> None:
    """Clean then optimize a rule file."""
    import tempfile

    print("\nClean and optimize rule file (both operations in sequence).")
    infile = _rule_select_file(ctx, "Input rule file: ")
    if not infile or not os.path.isfile(infile):
        print(f"[!] File not found: {infile}")
        return
    outfile = ctx.select_file_with_autocomplete(
        "Output file path (tab to autocomplete)"
    )
    outfile = outfile.strip() if outfile else ""
    if not outfile:
        print("[!] Output path required.")
        return
    with tempfile.NamedTemporaryFile(suffix=".rule", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        print(f"\nStep 1/2: Cleaning {infile}...")
        if not ctx.rules_cleanup(infile, tmp_path):
            print("[!] Cleanup failed.")
            return
        print(f"Step 2/2: Optimizing -> {outfile}...")
        if ctx.rules_optimize(tmp_path, outfile):
            print("[+] Done.")
        else:
            print("[!] Optimize failed.")
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def rule_tools_submenu(ctx: Any) -> None:
    from hate_crack.menu import interactive_menu

    items = [
        ("1", "Clean rule file (remove invalid/duplicate rules)"),
        ("2", "Optimize rule file (consolidate redundant operations)"),
        ("3", "Clean and optimize rule file (both)"),
        ("4", "Download rules from Hashmob.net"),
        ("5", "Analyze Hashcat rules (opcode statistics)"),
        ("99", "Back to Main Menu"),
    ]
    while True:
        choice = interactive_menu(items, title="\nRule File Tools:")
        if choice is None or choice == "99":
            break
        elif choice == "1":
            rule_cleanup_handler(ctx)
        elif choice == "2":
            rule_optimize_handler(ctx)
        elif choice == "3":
            rule_cleanup_and_optimize_handler(ctx)
        elif choice == "4":
            download_hashmob_rules(print_fn=print, rules_dir=ctx.rulesDirectory)
        elif choice == "5":
            ctx.analyze_rules()


def wordlist_filter_length(ctx: Any) -> None:
    """Prompt for paths and lengths, then filter wordlist by word length."""
    infile = ctx.select_file_with_autocomplete(
        "\n[*] Enter path to input wordlist", base_dir=ctx.hcatWordlists
    ).strip()
    if not os.path.isfile(infile):
        print(f"[!] File not found: {infile}")
        return
    outfile = ctx.select_file_with_autocomplete(
        "[*] Enter path to output wordlist"
    ).strip()
    if not outfile:
        print("[!] Output path cannot be empty.")
        return
    min_len = int(input("Minimum length: ").strip() or "0")
    max_len = int(input("Maximum length: ").strip() or "0")
    if ctx.wordlist_filter_len(infile, outfile, min_len, max_len):
        print(f"\n[*] Filtered wordlist written to: {outfile}")
    else:
        print("[!] Filter failed.")


def wordlist_filter_charclass_include(ctx: Any) -> None:
    """Prompt for paths and mask, then keep only words matching required char classes."""
    infile = ctx.select_file_with_autocomplete(
        "\n[*] Enter path to input wordlist", base_dir=ctx.hcatWordlists
    ).strip()
    if not os.path.isfile(infile):
        print(f"[!] File not found: {infile}")
        return
    outfile = ctx.select_file_with_autocomplete(
        "[*] Enter path to output wordlist"
    ).strip()
    if not outfile:
        print("[!] Output path cannot be empty.")
        return
    print(
        "[*] Char class mask: 1=lowercase, 2=uppercase, 4=digit, 8=symbol (additive, e.g. 3=lower+upper)"
    )
    mask = int(input("Mask value: ").strip() or "0")
    if ctx.wordlist_filter_req_include(infile, outfile, mask):
        print(f"\n[*] Filtered wordlist written to: {outfile}")
    else:
        print("[!] Filter failed.")


def wordlist_filter_charclass_exclude(ctx: Any) -> None:
    """Prompt for paths and mask, then remove words containing excluded char classes."""
    infile = ctx.select_file_with_autocomplete(
        "\n[*] Enter path to input wordlist", base_dir=ctx.hcatWordlists
    ).strip()
    if not os.path.isfile(infile):
        print(f"[!] File not found: {infile}")
        return
    outfile = ctx.select_file_with_autocomplete(
        "[*] Enter path to output wordlist"
    ).strip()
    if not outfile:
        print("[!] Output path cannot be empty.")
        return
    print("[*] Char class mask: 1=lowercase, 2=uppercase, 4=digit, 8=symbol (additive)")
    mask = int(input("Mask value: ").strip() or "0")
    if ctx.wordlist_filter_req_exclude(infile, outfile, mask):
        print(f"\n[*] Filtered wordlist written to: {outfile}")
    else:
        print("[!] Filter failed.")


def wordlist_cut_substring(ctx: Any) -> None:
    """Prompt for paths, offset, and optional length, then extract substring from each word."""
    infile = ctx.select_file_with_autocomplete(
        "\n[*] Enter path to input wordlist", base_dir=ctx.hcatWordlists
    ).strip()
    if not os.path.isfile(infile):
        print(f"[!] File not found: {infile}")
        return
    outfile = ctx.select_file_with_autocomplete(
        "[*] Enter path to output wordlist"
    ).strip()
    if not outfile:
        print("[!] Output path cannot be empty.")
        return
    offset = int(input("Byte offset to start from: ").strip() or "0")
    raw_length = input("Length (leave blank for rest of line): ").strip()
    length = int(raw_length) if raw_length else None
    if ctx.wordlist_cutb(infile, outfile, offset, length):
        print(f"\n[*] Output written to: {outfile}")
    else:
        print("[!] Cut failed.")


def wordlist_split_by_length(ctx: Any) -> None:
    """Prompt for input wordlist and output directory, then split by word length."""
    infile = ctx.select_file_with_autocomplete(
        "\n[*] Enter path to input wordlist", base_dir=ctx.hcatWordlists
    ).strip()
    if not os.path.isfile(infile):
        print(f"[!] File not found: {infile}")
        return
    outdir = ctx.select_file_with_autocomplete(
        "[*] Enter output directory path"
    ).strip()
    if not outdir:
        print("[!] Output directory cannot be empty.")
        return
    os.makedirs(outdir, exist_ok=True)
    if ctx.wordlist_splitlen(infile, outdir):
        print(f"\n[*] Split wordlists written to: {outdir}")
    else:
        print("[!] Split failed.")


def wordlist_subtract_words(ctx: Any) -> None:
    """Prompt for mode then remove matching lines from a wordlist."""
    print("\n[*] Subtract mode:")
    print("    1. Single remove file (rli2 - faster for one file)")
    print("    2. Multiple remove files (rli)")
    mode = input("Choose mode (1/2): ").strip()

    if mode == "1":
        infile = ctx.select_file_with_autocomplete(
            "[*] Enter path to input wordlist", base_dir=ctx.hcatWordlists
        ).strip()
        if not os.path.isfile(infile):
            print(f"[!] File not found: {infile}")
            return
        remove_file = ctx.select_file_with_autocomplete(
            "[*] Enter path to wordlist to subtract", base_dir=ctx.hcatWordlists
        ).strip()
        if not os.path.isfile(remove_file):
            print(f"[!] File not found: {remove_file}")
            return
        outfile = ctx.select_file_with_autocomplete(
            "[*] Enter path to output wordlist"
        ).strip()
        if not outfile:
            print("[!] Output path cannot be empty.")
            return
        if ctx.wordlist_subtract_single(infile, remove_file, outfile):
            print(f"\n[*] Result written to: {outfile}")
        else:
            print("[!] Subtraction failed.")
    elif mode == "2":
        infile = ctx.select_file_with_autocomplete(
            "[*] Enter path to input wordlist", base_dir=ctx.hcatWordlists
        ).strip()
        if not os.path.isfile(infile):
            print(f"[!] File not found: {infile}")
            return
        outfile = ctx.select_file_with_autocomplete(
            "[*] Enter path to output wordlist"
        ).strip()
        if not outfile:
            print("[!] Output path cannot be empty.")
            return
        raw = ctx.select_file_with_autocomplete(
            "[*] Enter remove file paths",
            allow_multiple=True,
            base_dir=ctx.hcatWordlists,
        ).strip()
        remove_files = [r.strip() for r in raw.split(",") if r.strip()]
        if not remove_files:
            print("[!] No remove files provided.")
            return
        if ctx.wordlist_subtract(infile, outfile, *remove_files):
            print(f"\n[*] Deduplicated wordlist written to: {outfile}")
        else:
            print("[!] Subtraction failed.")
    else:
        print("[!] Invalid mode.")


def wordlist_shard(ctx: Any) -> None:
    """Prompt for input/output base path and shard count, then write all N part files."""
    infile = ctx.select_file_with_autocomplete(
        "\n[*] Enter path to input wordlist", base_dir=ctx.hcatWordlists
    ).strip()
    if not os.path.isfile(infile):
        print(f"[!] File not found: {infile}")
        return
    outbase = ctx.select_file_with_autocomplete(
        "[*] Enter output base path (part numbers are appended, e.g. wl.001)"
    ).strip()
    if not outbase:
        print("[!] Output path cannot be empty.")
        return
    mod = int(input("Shard count (e.g. 4 to split into 4 parts): ").strip() or "0")
    if mod < 2:
        print("[!] Shard count must be at least 2.")
        return
    width = max(3, len(str(mod)))
    written = []
    for offset in range(mod):
        outfile = f"{outbase}.{offset + 1:0{width}d}"
        if ctx.wordlist_gate(infile, outfile, mod, offset):
            written.append(outfile)
        else:
            print(f"[!] Shard failed at part {offset + 1}: {outfile}")
            return
    print(f"\n[*] Wrote {len(written)} shard(s):")
    for path in written:
        print(f"    {path}")


def wordlist_optimize(ctx: Any) -> None:
    """Prompt for input wordlists and output directory, then optimize."""
    raw = ctx.select_file_with_autocomplete(
        "\n[*] Enter input wordlist paths (comma-separated files or directories)",
        base_dir=ctx.hcatWordlists,
    ).strip()
    raw_entries = [p.strip() for p in raw.split(",") if p.strip()]
    if not raw_entries:
        print("[!] No input wordlists provided.")
        return
    inputs: list[str] = []
    not_found: list[str] = []
    for entry in raw_entries:
        if os.path.isfile(entry):
            inputs.append(entry)
        elif os.path.isdir(entry):
            files = [os.path.join(entry, f) for f in ctx.list_wordlist_files(entry)]
            if not files:
                print(f"[!] No wordlist files found in: {entry}")
                return
            inputs.extend(files)
        else:
            not_found.append(entry)
    if not_found:
        print("[!] Not found (not a file or directory):")
        for p in not_found:
            print(f"    {p}")
        return
    outdir = ctx.select_file_with_autocomplete(
        "[*] Enter output directory path"
    ).strip()
    if not outdir:
        print("[!] Output directory cannot be empty.")
        return
    if ctx.wordlist_optimize(inputs, outdir):
        print(f"\n[*] Optimized wordlists written to: {outdir}")
    else:
        print("[!] Optimization failed.")


def wordlist_tools_submenu(ctx: Any) -> None:
    """Display the Wordlist Tools submenu and dispatch to the selected handler."""
    items = [
        ("1", "Filter by Length"),
        ("2", "Require Character Classes"),
        ("3", "Exclude Character Classes"),
        ("4", "Extract Substring"),
        ("5", "Split by Length"),
        ("6", "Subtract Wordlist"),
        ("7", "Shard Wordlist"),
        ("8", "Optimize Wordlists"),
        ("9", "Download wordlists from Hashmob.net"),
        ("10", "Download wordlists from Weakpass"),
        ("99", "Back to Main Menu"),
    ]
    while True:
        choice = interactive_menu(items, title="\nWordlist Tools:")
        if choice is None or choice == "99":
            break
        elif choice == "1":
            wordlist_filter_length(ctx)
        elif choice == "2":
            wordlist_filter_charclass_include(ctx)
        elif choice == "3":
            wordlist_filter_charclass_exclude(ctx)
        elif choice == "4":
            wordlist_cut_substring(ctx)
        elif choice == "5":
            wordlist_split_by_length(ctx)
        elif choice == "6":
            wordlist_subtract_words(ctx)
        elif choice == "7":
            wordlist_shard(ctx)
        elif choice == "8":
            wordlist_optimize(ctx)
        elif choice == "9":
            download_hashmob_wordlists(print_fn=print)
        elif choice == "10":
            weakpass_wordlist_menu()
