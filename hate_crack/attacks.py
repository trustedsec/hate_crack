import glob
import gzip
import os
import readline
from typing import Any

from hate_crack import notify as _notify
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
    _notify.prompt_notify_for_attack("Quick Crack")
    wordlist_choice = None
    default_dir = ctx.hcatOptimizedWordlists

    wordlist_files = ctx.list_wordlist_files(default_dir)
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
        base = default_dir
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
            elif raw_choice.isdigit() and 1 <= int(raw_choice) <= len(wordlist_files):
                chosen = os.path.join(
                    default_dir, wordlist_files[int(raw_choice) - 1]
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
            ctx.hcatHashType, ctx.hcatHashFile, 7, run_hybrid_on_expanded=False
        )
        ctx.hcatRecycle(ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatFingerprintCount)
        ctx.hcatCombination(ctx.hcatHashType, ctx.hcatHashFile)
        ctx.hcatRecycle(ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatCombinationCount)
        ctx.hcatHybrid(ctx.hcatHashType, ctx.hcatHashFile)
        ctx.hcatRecycle(ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatHybridCount)
        ctx.hcatGoodMeasure(ctx.hcatHashType, ctx.hcatHashFile)
        ctx.hcatRecycle(ctx.hcatHashType, ctx.hcatHashFile, ctx.hcatExtraCount)
    cracked_after = ctx.lineCount(out_path) if os.path.exists(out_path) else 0
    _notify.notify_job_done(
        "Extensive Crack", cracked_after, ctx.hcatHashFile
    )
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
    _notify.prompt_notify_for_attack("Combinator")
    print("\n" + "=" * 60)
    print("COMBINATOR ATTACK")
    print("=" * 60)
    print("Combines 2-8 wordlists. 2 uses hashcat native mode; 3+ use external binaries.")
    print("=" * 60)

    use_default = (
        input("\nUse default combinator wordlists from config? (Y/n): ").strip().lower()
    )

    if use_default != "n":
        base = ctx.hcatCombinationWordlist
        wordlists = base if isinstance(base, list) else [base]
        wordlists = [ctx._resolve_wordlist_path(wl, ctx.hcatWordlists) for wl in wordlists]
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
        separator = input("\nEnter separator between words (leave blank for none): ").strip()

    if len(wordlists) == 2 and not separator:
        ctx.hcatCombination(ctx.hcatHashType, ctx.hcatHashFile, wordlists)
    elif len(wordlists) == 3 and not separator:
        ctx.hcatCombinator3(ctx.hcatHashType, ctx.hcatHashFile, wordlists)
    else:
        ctx.hcatCombinatorX(ctx.hcatHashType, ctx.hcatHashFile, wordlists, separator or None)


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


def prince_attack(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("PRINCE")
    ctx.hcatPrince(ctx.hcatHashType, ctx.hcatHashFile)


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
    return collected


def combinator3_crack(ctx: Any) -> None:
    """3-way combinator attack (delegates to unified combinator_crack)."""
    combinator_crack(ctx)


def combinatorX_crack(ctx: Any) -> None:
    """N-way combinator attack (delegates to unified combinator_crack)."""
    combinator_crack(ctx)


def combinator_3plus_crack(ctx: Any) -> None:
    """3+ wordlist combinator (delegates to unified combinator_crack)."""
    combinator_crack(ctx)


def bandrel_method(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("Bandrel")
    ctx.hcatBandrel(ctx.hcatHashType, ctx.hcatHashFile)


def ollama_attack(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("LLM")
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
    _notify.prompt_notify_for_attack("Ad-hoc Mask")
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
        path = input("\n[*] Enter path to wordlist (max 63 lines recommended): ").strip()
        if not path:
            continue
        if not os.path.isfile(path):
            print(f"[!] File not found: {path}")
            continue
        with (gzip.open(path, "rb") if path.endswith(".gz") else open(path, "rb")) as fh:
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
    use_space_sep = input("[*] Add spaces between words? (Y/n): ").strip().lower() != "n"
    ctx.hcatCombipow(ctx.hcatHashType, ctx.hcatHashFile, wordlist, use_space_sep)


def generate_rules_crack(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("Random Rules")
    print("\n" + "=" * 60)
    print("RANDOM RULES ATTACK")
    print("=" * 60)
    print("Generates random hashcat mutation rules and applies them to a wordlist.")
    print("Use when known rulesets are exhausted - a chaos mode for rule-space exploration.")
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
                print("[!] Wordlist not found. Please enter a valid path.")
                return
        except ValueError:
            print("Please enter a valid number.")

    ctx.hcatGenerateRules(ctx.hcatHashType, ctx.hcatHashFile, rule_count, wordlist_choice)


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

    group_size_raw = input("\nEnter n-gram group size (default 3): ").strip()
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
    print("WARNING: Scales as N! per word. Only practical for words up to ~8 characters.")
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
        raw = input(
            "\nEnter path to a wordlist FILE (tab to autocomplete): "
        ).strip()
        if not raw:
            continue
        if not os.path.exists(raw):
            print(f"[!] Path not found: {raw}")
            continue
        if os.path.isdir(raw):
            print("[!] A directory was provided. Please enter a single wordlist file.")
            continue
        wordlist_path = raw

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
            pattern = os.path.join(base, "*.rule")
        else:
            text = os.path.expanduser(text)
            if text.startswith(("/", "./", "../", "~")):
                pattern = text + "*"
            else:
                pattern = os.path.join(base, text + "*")
        matches = _glob.glob(pattern)
        try:
            return matches[state]
        except IndexError:
            return None

    _configure_readline(rule_completer)
    return input(prompt).strip()


def rule_cleanup_handler(ctx: Any) -> None:
    """Clean a rule file using cleanup-rules.bin."""
    print("\nClean rule file - removes invalid and duplicate rules.")
    print("Reads an input rule file and writes cleaned rules to an output file.\n")
    infile = _rule_select_file(ctx, "Input rule file (tab to autocomplete): ")
    if not infile or not os.path.isfile(infile):
        print(f"[!] File not found: {infile}")
        return
    outfile = input("Output file path: ").strip()
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
    outfile = input("Output file path: ").strip()
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
    outfile = input("Output file path: ").strip()
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


def wordlist_filter_length(ctx: Any) -> None:
    """Prompt for paths and lengths, then filter wordlist by word length."""
    infile = ctx.select_file_with_autocomplete(
        "\n[*] Enter path to input wordlist", base_dir=ctx.hcatWordlists
    ).strip()
    if not os.path.isfile(infile):
        print(f"[!] File not found: {infile}")
        return
    outfile = ctx.select_file_with_autocomplete("[*] Enter path to output wordlist").strip()
    if not outfile:
        print("[!] Output path cannot be empty.")
        return
    min_len = int(input("[*] Minimum length: ").strip() or "0")
    max_len = int(input("[*] Maximum length: ").strip() or "0")
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
    outfile = ctx.select_file_with_autocomplete("[*] Enter path to output wordlist").strip()
    if not outfile:
        print("[!] Output path cannot be empty.")
        return
    print("[*] Char class mask: 1=lowercase, 2=uppercase, 4=digit, 8=symbol (additive, e.g. 3=lower+upper)")
    mask = int(input("[*] Enter mask value: ").strip() or "0")
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
    outfile = ctx.select_file_with_autocomplete("[*] Enter path to output wordlist").strip()
    if not outfile:
        print("[!] Output path cannot be empty.")
        return
    print("[*] Char class mask: 1=lowercase, 2=uppercase, 4=digit, 8=symbol (additive)")
    mask = int(input("[*] Enter mask value: ").strip() or "0")
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
    outfile = ctx.select_file_with_autocomplete("[*] Enter path to output wordlist").strip()
    if not outfile:
        print("[!] Output path cannot be empty.")
        return
    offset = int(input("[*] Byte offset to start from: ").strip() or "0")
    raw_length = input("[*] Length (leave blank for rest of line): ").strip()
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
    outdir = ctx.select_file_with_autocomplete("[*] Enter output directory path").strip()
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
    mode = input("[*] Choose mode (1/2): ").strip()

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
        outfile = ctx.select_file_with_autocomplete("[*] Enter path to output wordlist").strip()
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
        outfile = ctx.select_file_with_autocomplete("[*] Enter path to output wordlist").strip()
        if not outfile:
            print("[!] Output path cannot be empty.")
            return
        raw = ctx.select_file_with_autocomplete(
            "[*] Enter remove file paths", allow_multiple=True, base_dir=ctx.hcatWordlists
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
    """Prompt for input/output paths, modulus, and offset, then shard the wordlist."""
    infile = ctx.select_file_with_autocomplete(
        "\n[*] Enter path to input wordlist", base_dir=ctx.hcatWordlists
    ).strip()
    if not os.path.isfile(infile):
        print(f"[!] File not found: {infile}")
        return
    outfile = ctx.select_file_with_autocomplete("[*] Enter path to output wordlist").strip()
    if not outfile:
        print("[!] Output path cannot be empty.")
        return
    mod = int(input("[*] Modulus (shard count, e.g. 4 for 4 shards): ").strip() or "0")
    if mod < 2:
        print("[!] Modulus must be at least 2.")
        return
    offset = int(input("[*] Offset (shard index, 0-based, e.g. 0 for first shard): ").strip() or "0")
    if offset >= mod:
        print(f"[!] Offset must be less than modulus ({mod}).")
        return
    if ctx.wordlist_gate(infile, outfile, mod, offset):
        print(f"\n[*] Shard written to: {outfile}")
    else:
        print("[!] Shard failed.")


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
