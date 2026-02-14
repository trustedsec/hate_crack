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


def __getattr__(name):
    return getattr(_main, name)


def _sync_globals_to_main():
    # Keep commonly-mutated globals aligned for tests and wrappers.
    for name in (
        "hcatHashType",
        "pipal_count",
        "hcatHashFile",
        "hcatHashFileOrig",
        "pipalPath",
        "debug_mode",
    ):
        if name in globals():
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


def get_main_menu_options():
    options = {
        "1": _attacks.quick_crack,
        "2": _attacks.extensive_crack,
        "3": _attacks.brute_force_crack,
        "4": _attacks.top_mask_crack,
        "5": _attacks.fingerprint_crack,
        "6": _attacks.combinator_crack,
        "7": _attacks.hybrid_crack,
        "8": _attacks.pathwell_crack,
        "9": _attacks.prince_attack,
        "10": _attacks.yolo_combination,
        "11": _attacks.middle_combinator,
        "12": _attacks.thorough_combinator,
        "13": _attacks.bandrel_method,
        "14": _attacks.loopback_attack,
        "15": _attacks.ollama_attack,
        "90": download_hashmob_rules,
        "91": weakpass_wordlist_menu,
        "92": download_hashmob_wordlists,
        "93": weakpass_wordlist_menu,
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
