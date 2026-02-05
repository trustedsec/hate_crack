import glob
import os
import readline
from typing import Any

from hate_crack.api import download_hashmob_rules
from hate_crack.formatting import print_multicolumn_list


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


def quick_crack(ctx: Any) -> None:
    wordlist_choice = None
    rule_choice = None
    selected_hcatRules = []

    wordlist_files = sorted(
        f for f in os.listdir(ctx.hcatWordlists) if f != ".DS_Store"
    )
    wordlist_entries = [
        f"{i}. {file}" for i, file in enumerate(wordlist_files, start=1)
    ]
    max_entry_len = max((len(e) for e in wordlist_entries), default=24)
    print_multicolumn_list(
        "Wordlists",
        wordlist_entries,
        min_col_width=max_entry_len,
        max_col_width=max_entry_len,
    )

    def path_completer(text, state):
        if not text:
            text = "./"
        text = os.path.expanduser(text)
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
                f"Press Enter for default optimized wordlists [{ctx.hcatOptimizedWordlists}]: "
            )
            raw_choice = raw_choice.strip()
            if raw_choice == "":
                wordlist_choice = ctx.hcatOptimizedWordlists
            elif raw_choice.isdigit() and 1 <= int(raw_choice) <= len(wordlist_files):
                chosen = os.path.join(
                    ctx.hcatWordlists, wordlist_files[int(raw_choice) - 1]
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

    rule_files = sorted(
        f for f in os.listdir(ctx.rulesDirectory) if f != ".DS_Store"
    )
    if not rule_files:
        download_rules = (
            input("\nNo rules found. Download rules from Hashmob now? (Y/n): ")
            .strip()
            .lower()
        )
        if download_rules in ("", "y", "yes"):
            download_hashmob_rules(print_fn=print)
            rule_files = sorted(os.listdir(ctx.rulesDirectory))

    if not rule_files:
        print("No rules available. Proceeding without rules.")
        rule_choice = ["0"]
    else:
        print("\nWhich rule(s) would you like to run?")
        rule_entries = ["0. To run without any rules"]
        rule_entries.extend(
            [f"{i}. {file}" for i, file in enumerate(rule_files, start=1)]
        )
        rule_entries.append("98. YOLO...run all of the rules")
        rule_entries.append("99. Back to Main Menu")
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
            return
        if raw_choice != "":
            rule_choice = raw_choice.split(",")

    if "99" in rule_choice:
        return
    if "98" in rule_choice:
        for rule in rule_files:
            selected_hcatRules.append(f"-r {ctx.rulesDirectory}/{rule}")
    elif "0" in rule_choice:
        selected_hcatRules = [""]
    else:
        for choice in rule_choice:
            if "+" in choice:
                combined_choice = ""
                choices = choice.split("+")
                for rule in choices:
                    try:
                        combined_choice = f"{combined_choice} -r {ctx.rulesDirectory}/{rule_files[int(rule) - 1]}"
                    except Exception:
                        continue
                selected_hcatRules.append(combined_choice)
            else:
                try:
                    selected_hcatRules.append(
                        f"-r {ctx.rulesDirectory}/{rule_files[int(choice) - 1]}"
                    )
                except IndexError:
                    continue

    for chain in selected_hcatRules:
        ctx.hcatQuickDictionary(
            ctx.hcatHashType, ctx.hcatHashFile, chain, wordlist_choice
        )


def extensive_crack(ctx: Any) -> None:
    ctx.hcatBruteForce(ctx.hcatHashType, ctx.hcatHashFile, "1", "7")
    ctx.hcatRecycle(ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatBruteCount)
    ctx.hcatDictionary(ctx.hcatHashType, ctx.hcatHashFile)
    ctx.hcatRecycle(ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatDictionaryCount)
    hcatTargetTime = 4 * 60 * 60
    ctx.hcatTopMask(ctx.hcatHashType, ctx.hcatHashFile, hcatTargetTime)
    ctx.hcatRecycle(ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatMaskCount)
    ctx.hcatFingerprint(ctx.hcatHashType, ctx.hcatHashFile)
    ctx.hcatRecycle(ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatFingerprintCount)
    ctx.hcatCombination(ctx.hcatHashType, ctx.hcatHashFile)
    ctx.hcatRecycle(ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatCombinationCount)
    ctx.hcatHybrid(ctx.hcatHashType, ctx.hcatHashFile)
    ctx.hcatRecycle(ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatHybridCount)
    ctx.hcatGoodMeasure(ctx.hcatHashType, ctx.hcatHashFile)
    ctx.hcatRecycle(ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatExtraCount)


def brute_force_crack(ctx: Any) -> None:
    hcatMinLen = int(
        input("\nEnter the minimum password length to brute force (1): ") or 1
    )
    hcatMaxLen = int(
        input("\nEnter the maximum password length to brute force (7): ") or 7
    )
    ctx.hcatBruteForce(ctx.hcatHashType, ctx.hcatHashFile, hcatMinLen, hcatMaxLen)


def top_mask_crack(ctx: Any) -> None:
    hcatTargetTime = int(
        input("\nEnter a target time for completion in hours (4): ") or 4
    )
    hcatTargetTime = hcatTargetTime * 60 * 60
    ctx.hcatTopMask(ctx.hcatHashType, ctx.hcatHashFile, hcatTargetTime)


def fingerprint_crack(ctx: Any) -> None:
    ctx.hcatFingerprint(ctx.hcatHashType, ctx.hcatHashFile)


def combinator_crack(ctx: Any) -> None:
    ctx.hcatCombination(ctx.hcatHashType, ctx.hcatHashFile)


def hybrid_crack(ctx: Any) -> None:
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
            "Enter wordlist file(s) (comma-separated for multiple)", allow_multiple=True
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
    ctx.hcatPathwellBruteForce(ctx.hcatHashType, ctx.hcatHashFile)


def prince_attack(ctx: Any) -> None:
    ctx.hcatPrince(ctx.hcatHashType, ctx.hcatHashFile)


def yolo_combination(ctx: Any) -> None:
    ctx.hcatYoloCombination(ctx.hcatHashType, ctx.hcatHashFile)


def thorough_combinator(ctx: Any) -> None:
    ctx.hcatThoroughCombinator(ctx.hcatHashType, ctx.hcatHashFile)


def middle_combinator(ctx: Any) -> None:
    ctx.hcatMiddleCombinator(ctx.hcatHashType, ctx.hcatHashFile)


def bandrel_method(ctx: Any) -> None:
    ctx.hcatBandrel(ctx.hcatHashType, ctx.hcatHashFile)
