#!/usr/bin/env -S uv run --project .
import sys

from hate_crack import main as _main

# Re-export symbols for tests and legacy imports.
for _name, _value in _main.__dict__.items():
    if _name.startswith("__") and _name not in {
        "__all__",
        "__doc__",
        "__name__",
        "__package__",
        "__loader__",
        "__spec__",
    }:
        continue
    globals().setdefault(_name, _value)

# Snapshot of the import-time values above, so _sync_globals_to_main() can
# tell "this global was actually changed on the shim" apart from "this global
# still holds the stale copy we grabbed at import." Without this, syncing a
# name that main() later assigns a real value to (e.g. hcatHashFile) would
# clobber that real value with the shim's stale import-time copy.
_IMPORT_TIME_SNAPSHOT = {
    name: globals()[name]
    for name in (
        "hcatHashType",
        "pipal_count",
        "hcatHashFile",
        "hcatHashFileOrig",
        "pipalPath",
        "debug_mode",
        "hcatUsernamePrefix",
    )
    if name in globals()
}


def __getattr__(name):
    return getattr(_main, name)


def _sync_globals_to_main():
    # Keep commonly-mutated globals aligned for tests and wrappers, but only
    # push a name whose current shim value differs from its import-time
    # snapshot — otherwise a stale shim copy would clobber a real value that
    # main() itself set (see _IMPORT_TIME_SNAPSHOT above).
    for name in (
        "hcatHashType",
        "pipal_count",
        "hcatHashFile",
        "hcatHashFileOrig",
        "pipalPath",
        "debug_mode",
        "hcatUsernamePrefix",
    ):
        if name in globals() and globals()[name] != _IMPORT_TIME_SNAPSHOT.get(
            name, object()
        ):
            setattr(_main, name, globals()[name])


def _sync_callables_to_main():
    for name in (
        "weakpass_wordlist_menu",
        "download_hashmob_wordlists",
        "download_hashmob_rules",
        "hashview_api",
        "export_excel",
        "show_results",
        "show_readme",
        "quit_hc",
    ):
        if name in globals():
            setattr(_main, name, globals()[name])


def cli_main():
    _sync_globals_to_main()
    _sync_callables_to_main()
    return _main.main()


def main():
    _sync_globals_to_main()
    _sync_callables_to_main()
    return _main.main()


def pipal():
    _sync_globals_to_main()
    return _main.pipal()


def get_main_menu_items():
    return _main.get_main_menu_items()


def get_main_menu_options():
    options = {
        "1": _attacks.quick_crack,
        "2": _attacks.extensive_crack,
        "3": _attacks.brute_force_crack,
        "4": _attacks.top_mask_crack,
        "5": _attacks.fingerprint_crack,
        "6": _attacks.combinator_submenu,
        "7": _attacks.hybrid_crack,
        "8": _attacks.pathwell_crack,
        "9": _attacks.prince_attack,
        "10": _attacks.bandrel_method,
        "11": _attacks.loopback_attack,
        "12": _attacks.ollama_attack,
        "13": _attacks.omen_attack,
        "14": _attacks.adhoc_mask_crack,
        "15": _attacks.markov_brute_force,
        "16": _attacks.ngram_attack,
        "17": _attacks.permute_crack,
        "18": _attacks.generate_rules_crack,
        "19": _attacks.combipow_crack,
        "20": _attacks.pcfg_attack,
        "21": _attacks.prince_ling_attack,
        "22": _attacks.spoonman_attack,
        "23": _attacks.rosetta_attack,
        "80": _attacks.wordlist_tools_submenu,
        "81": _attacks.rule_tools_submenu,
        "82": notifications_submenu,
        "93": _attacks.restore_potfile_output,
        "95": pipal,
        "96": export_excel,
        "97": show_results,
        "98": show_readme,
        "99": quit_hc,
    }
    # Only show Hashview API when configured.
    if globals().get("hashview_api_key"):
        options["94"] = hashview_api
    return options


if __name__ == "__main__":
    sys.exit(main())
