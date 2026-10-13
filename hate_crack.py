#!/usr/bin/env -S uv run --project .
import sys

from hate_crack import main as _main
from hate_crack import menu_registry as _menu_registry

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


# Snapshot of this shim's namespace once every import-time copy from main is in
# place, so _ShimOverlay can tell "replaced on the shim" from "stale copy".
_SHIM_SNAPSHOT = dict(globals())


class _ShimOverlay:
    """Read-only view for menu_registry: a name replaced on the shim (a test
    patch or legacy caller) resolves there; anything else resolves against
    main's live value. main is never mutated, so nothing can leak."""

    def __getattr__(self, name):
        missing = object()
        current = globals().get(name, missing)
        if current is not missing and current is not _SHIM_SNAPSHOT.get(name, missing):
            return current
        return getattr(_main, name)


def get_main_menu_items():
    return _menu_registry.menu_items(_ShimOverlay())


def get_main_menu_options():
    return _menu_registry.menu_options(_ShimOverlay())


if __name__ == "__main__":
    sys.exit(main())
