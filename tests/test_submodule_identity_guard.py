"""Self-tests for the `_guard_submodule_identity` conftest fixture (#276, #298).

hate_crack/main.py used to set __path__ so it looked like a package to the
import system. That made a string-target patch --
mock.patch("hate_crack.main.llm.X") -- get resolved by pkgutil.resolve_name by
*importing* hate_crack.main.llm: a second, independent execution of llm.py.
The import machinery rebound hate_crack.main's `llm` attribute to that
duplicate, and it stayed rebound for the rest of the pytest session, even
after the `with` block that did the patching exited.

#298 removed the `__path__` shim, which fixes the corruption at its root:
"hate_crack.main.llm" is no longer a name the import system can resolve as a
distinct module, so pkgutil.resolve_name falls through to attribute lookup on
the real `hate_crack.main.llm` reference instead of importing a duplicate.
`test_string_target_patch_no_longer_corrupts_module_identity` below pins that
directly. The remaining tests in this file keep `_guard_submodule_identity`
exercised as a belt-and-braces net -- see its docstring in conftest.py -- for
any future regression that reintroduces a way to fool `pkgutil.resolve_name`,
even though the specific `__path__` mechanism is gone.

These tests are kept out of the files that were cleaned up (converted to
mock.patch.object) so the proof that the guard actually works doesn't live
next to code that no longer exercises the bug it used to guard against.

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


def test_string_target_patch_no_longer_corrupts_module_identity():
    """Pins the #298 fix at its root: with the `__path__` shim removed,
    mock.patch("hate_crack.main.llm.X") no longer causes pkgutil.resolve_name
    to import a duplicate llm module. Before #298, this exact `with` block
    left hate_crack.main.llm permanently rebound to a second, independent
    module object for the rest of the pytest session (see the module
    docstring and the old version of this test in history). Now it must
    resolve straight to the real attribute and leave no trace behind."""
    from tests.conftest import _corrupted_submodule_references

    hc_main = _current_hc_main()
    original_llm = hc_main.llm
    assert original_llm is llm

    with mock.patch("hate_crack.main.llm.CloudDestinationRefused"):
        # No duplicate: the patch resolves to the real, shared llm module.
        assert hc_main.llm is llm

    # Still the same module object after teardown, and nothing was left
    # registered under the bogus "hate_crack.main.llm" name.
    assert hc_main.llm is llm
    assert hc_main.llm.CloudDestinationRefused is llm.CloudDestinationRefused
    assert "hate_crack.main.llm" not in sys.modules

    # The guard function itself confirms there is nothing to detect or repair.
    reports = _corrupted_submodule_references()
    assert reports == [], (
        "expected no corruption once the __path__ shim is gone -- if this "
        "fails, the fix regressed and hate_crack.main.llm.X is being "
        "resolved as an importable submodule again"
    )


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
