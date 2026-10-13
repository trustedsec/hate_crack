#!/usr/bin/env -S uv run --project .
import sys

from hate_crack import main as _main
from hate_crack import menu_registry as _menu_registry

# This shim deliberately holds NO import-time copies of main's names. Reading
# e.g. hate_crack.hcatHashFile falls through __getattr__ to main's live value,
# and a name present in this module's own namespace therefore means exactly
# one thing: it was assigned here after import (a test patch or a legacy
# caller). That presence test is what _ShimOverlay and the _sync_* helpers
# rely on, and it holds for interned values ("", None, True, small ints) where
# an identity comparison against a snapshot cannot.
#
# Snapshot of main's import-time values for the synced globals, so
# _sync_globals_to_main() can tell "this global was actually changed on the
# shim" apart from "still main's value." Without this, syncing a name that
# main() later assigns a real value to (e.g. hcatHashFile) would clobber it.
_IMPORT_TIME_SNAPSHOT = {
    name: getattr(_main, name)
    for name in (
        "hcatHashType",
        "pipal_count",
        "hcatHashFile",
        "hcatHashFileOrig",
        "pipalPath",
        "debug_mode",
        "hcatUsernamePrefix",
    )
    if hasattr(_main, name)
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


# The shim's own definitions (main, pipal, helpers, imports). These exist from
# the start, so presence proves nothing for them; they are modules and
# functions, never interned values, so identity against this snapshot is a
# sound "was it replaced" test. Any other name in globals() was assigned.
_SHIM_NATIVES = dict(globals())


class _ShimOverlay:
    """Read-only view for menu_registry: a name assigned on the shim (a test
    patch or legacy caller) resolves there; anything else resolves against
    main's live value. main is never mutated, so nothing can leak.

    The shim keeps no copies of main's names, so for those, presence in its
    namespace is itself proof of assignment (correct for interned values too).
    Only the shim's own definitions need an identity check."""

    def __getattr__(self, name):
        if name in globals():
            current = globals()[name]
            if name not in _SHIM_NATIVES or current is not _SHIM_NATIVES[name]:
                return current
        return getattr(_main, name)


def get_main_menu_items():
    return _menu_registry.menu_items(_ShimOverlay())


def get_main_menu_options():
    return _menu_registry.menu_options(_ShimOverlay())


if __name__ == "__main__":
    sys.exit(main())
