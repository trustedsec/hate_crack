import glob
import os
import readline
from typing import Any

from hate_crack.api import download_hashmob_rules
from hate_crack.formatting import print_multicolumn_list
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
    rule_files = sorted(f for f in os.listdir(rules_dir) if f != ".DS_Store")
    if not rule_files:
        download_rules = (
            input("\nNo rules found. Download rules from Hashmob now? (Y/n): ")
            .strip()
            .lower()
        )
        if download_rules in ("", "y", "yes"):
            download_hashmob_rules(print_fn=print, rules_dir=rules_dir)
            rule_files = sorted(os.listdir(rules_dir))

    if not rule_files:
        print("No rules available. Proceeding without rules.")
        return [""]

    print("\nWhich rule(s) would you like to run?")
    rule_entries = ["0. To run without any rules"]
    rule_entries.extend([f"{i}. {file}" for i, file in enumerate(rule_files, start=1)])
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
            return None
        if raw_choice != "":
            rule_choice = raw_choice.split(",")

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
                except IndexError:
                    continue

    return selected_rules


def quick_crack(ctx: Any) -> None:
    wordlist_choice = None

    wordlist_files = ctx.list_wordlist_files(ctx.hcatWordlists)
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

    while wordlist_choice is None:
        try:
            raw_choice = input(
                "\nEnter path of wordlist or wordlist directory (tab to autocomplete).\n"
                f"Press Enter for default wordlist directory [{ctx.hcatWordlists}]: "
            )
            raw_choice = raw_choice.strip()
            if raw_choice == "":
                wordlist_choice = ctx.hcatWordlists
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

    selected_rules = _select_rules(ctx)
    if selected_rules is None:
        return

    for chain in selected_rules:
        ctx.hcatQuickDictionary(
            ctx.hcatHashType, ctx.hcatHashFile, chain, wordlist_choice
        )


def loopback_attack(ctx: Any) -> None:
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
        )


def extensive_crack(ctx: Any) -> None:
    ctx.hcatBruteForce(ctx.hcatHashType, ctx.hcatHashFile, "1", "7")
    ctx.hcatRecycle(ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatBruteCount)
    ctx.hcatDictionary(ctx.hcatHashType, ctx.hcatHashFile)
    ctx.hcatRecycle(ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatDictionaryCount)
    hcatTargetTime = 4 * 60 * 60
    ctx.hcatTopMask(ctx.hcatHashType, ctx.hcatHashFile, hcatTargetTime)
    ctx.hcatRecycle(ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatMaskCount)
    ctx.hcatFingerprint(
        ctx.hcatHashType, ctx.hcatHashFile, 7, run_hybrid_on_expanded=False
    )
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
    while True:
        raw = input("\nEnter expander max length (7-36) (7): ").strip()
        if raw == "":
            expander_len = 7
            break
        try:
            expander_len = int(raw)
        except ValueError:
            print("Please enter an integer between 7 and 36.")
            continue
        if 7 <= expander_len <= 36:
            break
        print("Please enter an integer between 7 and 36.")

    ctx.hcatFingerprint(
        ctx.hcatHashType,
        ctx.hcatHashFile,
        expander_len,
        run_hybrid_on_expanded=True,
    )


def combinator_crack(ctx: Any) -> None:
    print("\n" + "=" * 60)
    print("COMBINATOR ATTACK")
    print("=" * 60)
    print("This attack combines two wordlists to generate candidates.")
    print("Example: wordlist1='password' + wordlist2='123' = 'password123'")
    print("=" * 60)

    use_default = (
        input("\nUse default combinator wordlists from config? (Y/n): ").strip().lower()
    )

    if use_default != "n":
        print("\nUsing default wordlist(s) from config:")
        if isinstance(ctx.hcatCombinationWordlist, list):
            for wl in ctx.hcatCombinationWordlist:
                print(f"  - {wl}")
            wordlists = ctx.hcatCombinationWordlist
        else:
            print(f"  - {ctx.hcatCombinationWordlist}")
            wordlists = [ctx.hcatCombinationWordlist]
    else:
        print("\nSelect wordlists for combinator attack.")
        print("You need to provide exactly 2 wordlists.")
        print("You can enter:")
        print("  - Two file paths separated by commas")
        print("  - Press TAB to autocomplete file paths")

        selection = ctx.select_file_with_autocomplete(
            "Enter 2 wordlist files (comma-separated)",
            allow_multiple=True,
            base_dir=ctx.hcatWordlists,
        )

        if not selection:
            print("No wordlists selected. Aborting combinator attack.")
            return

        if isinstance(selection, str):
            wordlists = [selection]
        else:
            wordlists = selection

        if len(wordlists) < 2:
            print("\n[!] Combinator attack requires at least 2 wordlists.")
            print("Aborting combinator attack.")
            return

        valid_wordlists = []
        for wl in wordlists[:2]:  # Only use first 2
            resolved = ctx._resolve_wordlist_path(wl, ctx.hcatWordlists)
            if os.path.isfile(resolved):
                valid_wordlists.append(resolved)
                print(f"✓ Found: {resolved}")
            else:
                print(f"✗ Not found: {resolved}")

        if len(valid_wordlists) < 2:
            print("\nCould not find 2 valid wordlists. Aborting combinator attack.")
            return

        wordlists = valid_wordlists

    wordlists = [
        ctx._resolve_wordlist_path(wl, ctx.hcatWordlists) for wl in wordlists[:2]
    ]

    if len(wordlists) < 2:
        print("\n[!] Combinator attack requires 2 wordlists but only 1 is configured.")
        print("Set hcatCombinationWordlist to a list of 2 paths in config.json.")
        print("Aborting combinator attack.")
        return

    print("\nStarting combinator attack with 2 wordlists:")
    print(f"  Wordlist 1: {wordlists[0]}")
    print(f"  Wordlist 2: {wordlists[1]}")
    print(f"Hash type: {ctx.hcatHashType}")
    print(f"Hash file: {ctx.hcatHashFile}")

    ctx.hcatCombination(ctx.hcatHashType, ctx.hcatHashFile, wordlists)


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
    ctx.hcatPathwellBruteForce(ctx.hcatHashType, ctx.hcatHashFile)


def prince_attack(ctx: Any) -> None:
    ctx.hcatPrince(ctx.hcatHashType, ctx.hcatHashFile)


def yolo_combination(ctx: Any) -> None:
    ctx.hcatYoloCombination(ctx.hcatHashType, ctx.hcatHashFile)


def thorough_combinator(ctx: Any) -> None:
    ctx.hcatThoroughCombinator(ctx.hcatHashType, ctx.hcatHashFile)


def middle_combinator(ctx: Any) -> None:
    ctx.hcatMiddleCombinator(ctx.hcatHashType, ctx.hcatHashFile)


def combinator3_crack(ctx: Any) -> None:
    print("\n" + "=" * 60)
    print("COMBINATOR3 ATTACK")
    print("=" * 60)
    print("This attack combines three wordlists to generate candidates.")
    print("=" * 60)

    use_default = (
        input("\nUse default combinator wordlists from config? (Y/n): ").strip().lower()
    )

    if use_default != "n":
        base = ctx.hcatCombinationWordlist
        wordlists = base if isinstance(base, list) else [base]
        if len(wordlists) < 3:
            print("\n[!] Config does not have 3 wordlists for combinator3.")
            print("Set hcatCombinationWordlist to a list of 3 paths in config.json.")
            print("Aborting combinator3 attack.")
            return
    else:
        raw = input(
            "\nEnter 3 wordlist file paths (comma-separated): "
        ).strip()
        if not raw:
            print("No wordlists provided. Aborting combinator3 attack.")
            return

        entries = [p.strip() for p in raw.split(",") if p.strip()]
        if len(entries) < 3:
            print("\n[!] Combinator3 attack requires exactly 3 wordlists.")
            print("Aborting combinator3 attack.")
            return

        valid = []
        for p in entries[:3]:
            resolved = ctx._resolve_wordlist_path(p, ctx.hcatWordlists)
            if os.path.isfile(resolved):
                valid.append(resolved)
                print(f"Found: {resolved}")
            else:
                print(f"Not found: {resolved}")

        if len(valid) < 3:
            print("\nCould not find 3 valid wordlists. Aborting combinator3 attack.")
            return

        wordlists = valid

    ctx.hcatCombinator3(ctx.hcatHashType, ctx.hcatHashFile, wordlists)


def combinatorX_crack(ctx: Any) -> None:
    print("\n" + "=" * 60)
    print("COMBINATORX ATTACK")
    print("=" * 60)
    print("This attack combines 2-8 wordlists with an optional separator.")
    print("=" * 60)

    use_default = (
        input("\nUse default combinator wordlists from config? (Y/n): ").strip().lower()
    )

    if use_default != "n":
        base = ctx.hcatCombinationWordlist
        wordlists = base if isinstance(base, list) else [base]
        if len(wordlists) < 2:
            print("\n[!] Config does not have at least 2 wordlists for combinatorX.")
            print("Set hcatCombinationWordlist to a list of 2+ paths in config.json.")
            print("Aborting combinatorX attack.")
            return
        separator = ""
    else:
        raw = input(
            "\nEnter 2-8 wordlist file paths (comma-separated): "
        ).strip()
        if not raw:
            print("No wordlists provided. Aborting combinatorX attack.")
            return

        entries = [p.strip() for p in raw.split(",") if p.strip()]
        if len(entries) < 2:
            print("\n[!] CombinatorX attack requires at least 2 wordlists.")
            print("Aborting combinatorX attack.")
            return

        valid = []
        for p in entries[:8]:
            resolved = ctx._resolve_wordlist_path(p, ctx.hcatWordlists)
            if os.path.isfile(resolved):
                valid.append(resolved)
                print(f"Found: {resolved}")
            else:
                print(f"Not found: {resolved}")

        if len(valid) < 2:
            print("\nCould not find 2 valid wordlists. Aborting combinatorX attack.")
            return

        wordlists = valid
        separator = input("\nEnter separator between words (leave blank for none): ").strip()

    ctx.hcatCombinatorX(ctx.hcatHashType, ctx.hcatHashFile, wordlists, separator or None)


def bandrel_method(ctx: Any) -> None:
    ctx.hcatBandrel(ctx.hcatHashType, ctx.hcatHashFile)


def ollama_attack(ctx: Any) -> None:
    print("\n\tLLM Attack")
    company = input("Company name: ").strip()
    industry = input("Industry: ").strip()
    location = input("Location: ").strip()
    target_info = {
        "company": company,
        "industry": industry,
        "location": location,
    }
    ctx.hcatOllama(ctx.hcatHashType, ctx.hcatHashFile, "target", target_info)


def _omen_pick_training_wordlist(ctx: Any):
    """Show wordlist picker for OMEN training. Returns path or None."""
    wordlist_files = ctx.list_wordlist_files(ctx.hcatWordlists)
    if wordlist_files:
        entries = [f"{i}. {f}" for i, f in enumerate(wordlist_files, start=1)]
        max_len = max((len(e) for e in entries), default=24)
        print_multicolumn_list(
            "Training Wordlists",
            entries,
            min_col_width=max_len,
            max_col_width=max_len,
        )
    print("\tp. Enter a custom path")
    sel = input("\n\tSelect wordlist for training: ").strip()
    if sel.lower() == "p":
        path = input("\n\tPath to training wordlist: ").strip()
        return path if path else None
    try:
        idx = int(sel)
        if 1 <= idx <= len(wordlist_files):
            return os.path.join(ctx.hcatWordlists, wordlist_files[idx - 1])
    except (ValueError, IndexError):
        pass
    print("\t[!] Invalid selection.")
    return None


def omen_attack(ctx: Any) -> None:
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
        print("\t1. Use existing model")
        print("\t2. Train new model (overwrites existing)")
        print("\t3. Cancel")
        choice = input("\n\tChoice: ").strip()
        if choice == "1":
            need_training = False
        elif choice == "3":
            return
        elif choice != "2":
            return
    else:
        print("\n\tNo valid OMEN model found. Training is required.")

    if need_training:
        training_file = _omen_pick_training_wordlist(ctx)
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
    """Prompt user to select markov training source. Returns file path or None."""
    out_path = f"{ctx.hcatHashFile}.out"
    has_cracked = os.path.isfile(out_path) and os.path.getsize(out_path) > 0

    wordlist_files = ctx.list_wordlist_files(ctx.hcatWordlists)
    entries = []
    if has_cracked:
        entries.append("0. Cracked passwords (current session)")
    entries.extend([f"{i}. {f}" for i, f in enumerate(wordlist_files, start=1)])
    if entries:
        max_len = max((len(e) for e in entries), default=24)
        print_multicolumn_list(
            "Markov Training Source",
            entries,
            min_col_width=max_len,
            max_col_width=max_len,
        )
    print("\tp. Enter a custom path")
    sel = input("\n\tSelect training source: ").strip()
    if sel == "0" and has_cracked:
        return out_path
    if sel.lower() == "p":
        path = input("\n\tPath to training file: ").strip()
        return path if path else None
    try:
        idx = int(sel)
        if 1 <= idx <= len(wordlist_files):
            return os.path.join(ctx.hcatWordlists, wordlist_files[idx - 1])
    except (ValueError, IndexError):
        pass
    print("\t[!] Invalid selection.")
    return None


def adhoc_mask_crack(ctx: Any) -> None:
    print(
        "\nEnter a hashcat mask. Tokens: ?l=lower ?u=upper ?d=digit ?s=special ?a=all ?b=binary ?1-?4=custom"
    )
    mask = input("Mask (e.g. ?u?l?l?l?d?d): ").strip()
    if not mask:
        return

    charset_flags = []
    for i in range(1, 5):
        cs = input(f"Custom charset -{i} [leave blank to skip]: ").strip()
        if cs:
            charset_flags.extend([f"-{i}", cs])
        else:
            break

    ctx.hcatAdHocMask(
        ctx.hcatHashType,
        ctx.hcatHashFile,
        mask,
        " ".join(charset_flags),
    )


def markov_brute_force(ctx: Any) -> None:
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


def combinator_submenu(ctx: Any) -> None:
    items = [
        ("1", "Combinator Attack"),
        ("2", "YOLO Combinator Attack"),
        ("3", "Middle Combinator Attack"),
        ("4", "Thorough Combinator Attack"),
        ("5", "Combinator3 Attack (3-way)"),
        ("6", "CombinatorX Attack (N-way, 2-8 wordlists)"),
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
        elif choice == "5":
            combinator3_crack(ctx)
        elif choice == "6":
            combinatorX_crack(ctx)
