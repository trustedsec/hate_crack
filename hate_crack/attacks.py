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

    rule_files = sorted(f for f in os.listdir(ctx.rulesDirectory) if f != ".DS_Store")
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


def loopback_attack(ctx: Any) -> None:
    empty_wordlist = os.path.join(ctx.hcatWordlists, "empty.txt")
    os.makedirs(ctx.hcatWordlists, exist_ok=True)
    if not os.path.exists(empty_wordlist):
        with open(empty_wordlist, "w"):
            pass

    print(f"\nUsing loopback attack with wordlist: {empty_wordlist}")

    rule_choice = None
    selected_hcatRules = []

    rule_files = sorted(f for f in os.listdir(ctx.rulesDirectory) if f != ".DS_Store")
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
            "Enter 2 wordlist files (comma-separated)", allow_multiple=True
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


def omen_attack(ctx: Any) -> None:
    print("\n\tOMEN Attack (Ordered Markov ENumerator)")
    omen_dir = os.path.join(ctx.hate_path, "omen")
    create_bin = os.path.join(omen_dir, ctx.hcatOmenCreateBin)
    enum_bin = os.path.join(omen_dir, ctx.hcatOmenEnumBin)
    if not os.path.isfile(create_bin) or not os.path.isfile(enum_bin):
        print("\n\tOMEN binaries not found. Build them with:")
        print(f"\t  cd {omen_dir} && make")
        return
    model_dir = os.path.join(os.path.expanduser("~"), ".hate_crack", "omen")
    model_exists = os.path.isfile(os.path.join(model_dir, "createConfig"))
    if not model_exists:
        print("\n\tNo OMEN model found. Training is required before generation.")
        training_source = input(
            "\n\tTraining source (path to password list, or press Enter for default): "
        ).strip()
        if not training_source:
            training_source = ctx.omenTrainingList
        ctx.hcatOmenTrain(training_source)
    max_candidates = input(
        f"\n\tMax candidates to generate ({ctx.omenMaxCandidates}): "
    ).strip()
    if not max_candidates:
        max_candidates = str(ctx.omenMaxCandidates)
    ctx.hcatOmen(ctx.hcatHashType, ctx.hcatHashFile, int(max_candidates))


def passgpt_attack(ctx: Any) -> None:
    print("\n\tPassGPT Attack (ML Password Generator)")
    if not ctx.HAS_ML_DEPS:
        print("\n\tPassGPT requires ML dependencies. Install them with:")
        print('\t  uv pip install -e ".[ml]"')
        return

    # Build model choices: default HF model + any local fine-tuned models
    default_model = ctx.passgptModel
    models = [(default_model, f"{default_model} (default)")]

    model_dir = ctx._passgpt_model_dir()
    if os.path.isdir(model_dir):
        for entry in sorted(os.listdir(model_dir)):
            entry_path = os.path.join(model_dir, entry)
            if os.path.isdir(entry_path) and os.path.isfile(
                os.path.join(entry_path, "config.json")
            ):
                models.append((entry_path, f"{entry} (local)"))

    print("\n\tSelect a model:")
    for i, (_, label) in enumerate(models, 1):
        print(f"\t  ({i}) {label}")
    print("\t  (T) Train a new model")

    choice = input("\n\tChoice: ").strip()

    if choice.upper() == "T":
        print("\n\tTrain a new PassGPT model")
        training_file = ctx.select_file_with_autocomplete(
            "Select training wordlist", base_dir=ctx.hcatWordlists
        )
        if not training_file:
            print("\n\tNo training file selected. Aborting.")
            return
        if isinstance(training_file, list):
            training_file = training_file[0]
        base = input(f"\n\tBase model ({default_model}): ").strip()
        if not base:
            base = default_model
        result = ctx.hcatPassGPTTrain(training_file, base)
        if result is None:
            print("\n\tTraining failed. Returning to menu.")
            return
        model_name = result
    else:
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(models):
                model_name = models[idx][0]
            else:
                print("\n\tInvalid selection.")
                return
        except ValueError:
            print("\n\tInvalid selection.")
            return

    max_candidates = input(
        f"\n\tMax candidates to generate ({ctx.passgptMaxCandidates}): "
    ).strip()
    if not max_candidates:
        max_candidates = str(ctx.passgptMaxCandidates)
    ctx.hcatPassGPT(
        ctx.hcatHashType,
        ctx.hcatHashFile,
        int(max_candidates),
        model_name=model_name,
        batch_size=ctx.passgptBatchSize,
    )
