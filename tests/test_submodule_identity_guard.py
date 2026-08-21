"""Self-tests for the `_guard_submodule_identity` conftest fixture (#276).

hate_crack/main.py sets __path__ so it looks like a package to the import
system. A string-target patch -- mock.patch("hate_crack.main.llm.X") -- is
therefore resolved by pkgutil.resolve_name by *importing*
hate_crack.main.llm: a second, independent execution of llm.py. The import
machinery rebinds hate_crack.main's `llm` attribute to that duplicate, and it
stays rebound for the rest of the pytest session, even after the `with`
block that did the patching exits.

These tests are kept out of the files that were cleaned up (converted to
mock.patch.object) so the proof that the guard actually works doesn't live
next to code that no longer exercises the bug it guards against.

These tests deliberately do NOT bind ``hate_crack.main`` at import time
(e.g. ``from hate_crack import main as hc_main`` at module scope). Some
other test modules in this suite (see tests/test_random_rules_attack.py)
legitimately pop and re-import ``hate_crack.main``/``hate_crack`` from
``sys.modules`` to get a fresh CLI module -- a documented, unrelated
pattern -- which replaces the module object for the rest of the session. A
collection-time binding here would go stale relative to that (pytest
imports every test module up front during collection, before any test
runs), making these tests silently check the wrong module object depending
on test order. Instead, each test looks up ``hate_crack.main`` from
``sys.modules`` fresh, exactly like ``_corrupted_submodule_references``
itself does.
"""

import sys
from types import ModuleType
from unittest import mock

from hate_crack import llm


def _current_hc_main():
    return sys.modules["hate_crack.main"]


def test_string_target_patch_corrupts_and_is_detected_and_repaired():
    """Provoke the bad pattern, confirm corruption, then confirm the check
    function both detects and repairs it -- proving the guard is live, not
    decorative."""
    from tests.conftest import _corrupted_submodule_references

    hc_main = _current_hc_main()
    original_llm = hc_main.llm
    assert original_llm is llm

    try:
        with mock.patch("hate_crack.main.llm.CloudDestinationRefused"):
            # Inside the `with` block, hate_crack.main.llm has already been
            # rebound to a freshly-imported duplicate module.
            assert hc_main.llm is not llm

        # The corruption outlives the `with` block: mock's teardown only
        # restores the attribute on the duplicate, not the rebinding itself.
        assert hc_main.llm is not llm, (
            "expected the string-target patch to leave hate_crack.main.llm "
            "corrupted after teardown -- if this fails, the reproduction "
            "no longer demonstrates the bug this guard exists for"
        )
        assert hc_main.llm.CloudDestinationRefused is not llm.CloudDestinationRefused

        # Call the check function directly (not through the autouse fixture)
        # to confirm it both detects and repairs the corruption.
        reports = _corrupted_submodule_references()
        assert reports, "expected the corruption to be detected and reported"
        assert any("hate_crack.main.llm" in r for r in reports)

        # The module reference is back to identity with the canonical module.
        assert hc_main.llm is llm
        assert hc_main.llm.CloudDestinationRefused is llm.CloudDestinationRefused
    finally:
        hc_main.llm = original_llm
        sys.modules.pop("hate_crack.main.llm", None)


def test_repair_also_clears_the_duplicate_from_sys_modules():
    """The repair must clear sys.modules, not just rebind the attribute --
    otherwise a later import of "hate_crack.main.llm" would hand back the
    stale duplicate instead of re-resolving to the real module."""
    from tests.conftest import _corrupted_submodule_references

    hc_main = _current_hc_main()

    try:
        with mock.patch("hate_crack.main.llm.CloudDestinationRefused"):
            pass

        assert "hate_crack.main.llm" in sys.modules, (
            "expected the string-target patch to have registered a duplicate "
            "submodule in sys.modules -- if this fails, the reproduction no "
            "longer demonstrates the bug this guard exists for"
        )

        reports = _corrupted_submodule_references()
        assert reports

        assert "hate_crack.main.llm" not in sys.modules
    finally:
        hc_main.llm = llm
        sys.modules.pop("hate_crack.main.llm", None)


def test_recommended_idiom_produces_zero_corruption():
    """Positive control: mock.patch.object(hc_main.llm, ...) -- the idiom all
    57 converted call sites now use -- must not trip the guard at all.
    Without this, the guard could be passing merely because it detects
    nothing, ever."""
    from tests.conftest import _corrupted_submodule_references

    hc_main = _current_hc_main()

    with mock.patch.object(hc_main.llm, "CloudDestinationRefused"):
        assert hc_main.llm is llm

    assert hc_main.llm is llm
    assert "hate_crack.main.llm" not in sys.modules

    reports = _corrupted_submodule_references()
    assert reports == []


def test_canonical_name_is_derived_for_an_arbitrarily_nested_module():
    """A duplicate whose real path has more than one dotted component below
    ``hate_crack.main`` (e.g. a hypothetical ``hate_crack.progress.spinner``)
    must resolve to the full nested canonical name, not just its last
    segment.

    No such nested module exists as a main.py attribute today, so this
    constructs synthetic module objects to exercise
    ``_corrupted_submodule_references``'s name derivation in isolation --
    truncating to the last segment would compute ``hate_crack.spinner``
    here instead of ``hate_crack.progress.spinner`` and silently miss (or
    misreport) the duplicate."""
    from tests.conftest import _corrupted_submodule_references

    hc_main = _current_hc_main()

    canonical = ModuleType("hate_crack.progress.spinner")
    duplicate = ModuleType("hate_crack.main.progress.spinner")
    assert canonical is not duplicate

    had_attr = hasattr(hc_main, "spinner")
    original_attr = getattr(hc_main, "spinner", None)
    had_canonical_in_sys_modules = "hate_crack.progress.spinner" in sys.modules
    original_canonical = sys.modules.get("hate_crack.progress.spinner")

    try:
        sys.modules["hate_crack.progress.spinner"] = canonical
        hc_main.spinner = duplicate

        reports = _corrupted_submodule_references()

        assert any("hate_crack.progress.spinner" in r for r in reports), (
            f"expected a report naming the full nested canonical path, got: {reports}"
        )
        assert hc_main.spinner is canonical
    finally:
        if had_attr:
            hc_main.spinner = original_attr
        else:
            if hasattr(hc_main, "spinner"):
                delattr(hc_main, "spinner")
        if had_canonical_in_sys_modules:
            sys.modules["hate_crack.progress.spinner"] = original_canonical
        else:
            sys.modules.pop("hate_crack.progress.spinner", None)
