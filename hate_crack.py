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

# NOTE: globals().setdefault() above copies main's import-time values into
# this shim's module dict, which shadows __getattr__ for those names. Reading
# e.g. hate_crack.hcatHashFile therefore returns this frozen copy rather than
# proxying to main's live value. Latent today because nothing reads these
# names that way and the snapshot guard below prevents the stale copy from
# ever being pushed back onto main, but it will bite the first caller that
# expects live-attribute semantics here.
#
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
        "download_hashmob_masks",
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


# Shim-level names the menu depends on, with the value each held at import
# time. get_main_menu_options() uses these to tell "replaced on the shim" apart
# from "still the stale import-time copy" (same idea as _IMPORT_TIME_SNAPSHOT).
_MENU_SHIM_ORIGINALS = {
    name: globals().get(name)
    for name in (
        "notifications_submenu",
        "pipal",
        "weakpass_wordlist_menu",
        "download_hashmob_wordlists",
        "download_hashmob_rules",
        "download_hashmob_masks",
        "hashview_api",
        "hashview_api_key",
        "export_excel",
        "show_results",
        "show_readme",
        "quit_hc",
    )
}
# name -> what main held before we pushed a shim replacement onto it.
_MENU_PUSHED_FROM = {}


def _mirror_menu_overrides():
    """Make main see shim-level replacements, and undo them once reverted.

    The menu is defined once, in hate_crack.menu_registry, and resolved against
    main at call time. A replacement made on this shim (a test patch, or a
    legacy caller) must therefore be visible on main while it is in force.
    Only names that differ from their import-time value are pushed, and a push
    is reverted when the shim value goes back, so a patch never outlives itself
    on the session-shared main module.
    """
    for name, original in _MENU_SHIM_ORIGINALS.items():
        current = globals().get(name, original)
        if current is not original:
            if name not in _MENU_PUSHED_FROM:
                _MENU_PUSHED_FROM[name] = getattr(_main, name, None)
            setattr(_main, name, current)
        elif name in _MENU_PUSHED_FROM:
            setattr(_main, name, _MENU_PUSHED_FROM.pop(name))


def get_main_menu_options():
    _mirror_menu_overrides()
    return _main.get_main_menu_options()


if __name__ == "__main__":
    sys.exit(main())
