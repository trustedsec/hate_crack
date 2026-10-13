"""Single source of truth for the main menu.

The menu used to be described three times (``main.get_main_menu_items``,
``main.get_main_menu_options`` and a duplicate pair in the ``hate_crack.py``
shim). It is now one ordered tuple, ``MAIN_MENU``.

Handlers and availability are resolved at CALL time, by name, against the live
``hate_crack.main`` module. The shim's ``_sync_callables_to_main()`` replaces
several functions on ``main`` after import, and ``hashview_api_key`` is set
during startup; capturing function objects or values at import time would make
both silently stop taking effect.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


class _LateHandler:
    """Handler that looks ``name`` up on a main module each time it is called.

    ``bind(module)`` pins it to a specific module object. There is deliberately
    no lookup by name in ``sys.modules``: the test suite purges
    ``hate_crack.main`` between tests, so a menu must dispatch against the
    module it was built for, not whichever is newest.
    """

    def __init__(self, name: str) -> None:
        self.__name__ = self.__qualname__ = name

    def bind(self, module: Any) -> Callable[[], Any]:
        name = self.__name__

        def handler() -> Any:
            return getattr(module, name)()

        handler.__name__ = handler.__qualname__ = name
        return handler


class _LateTruthy:
    """Availability predicate: is ``name`` set (truthy) on a main module?"""

    def __init__(self, name: str) -> None:
        self.name = name

    def bind(self, module: Any) -> Callable[[], bool]:
        return lambda: bool(getattr(module, self.name, ""))


def _late(name: str) -> _LateHandler:
    return _LateHandler(name)


_hashview_configured = _LateTruthy("hashview_api_key")


@dataclass(frozen=True)
class MenuAction:
    key: str
    label: str
    handler: Callable[[], Any] | _LateHandler
    available: Callable[[], bool] | _LateTruthy = lambda: True


MAIN_MENU: tuple[MenuAction, ...] = (
    MenuAction("1", "Quick Crack", _late("quick_crack")),
    MenuAction("2", "Extensive Pure_Hate Methodology Crack", _late("extensive_crack")),
    MenuAction("3", "Brute Force Attack", _late("brute_force_crack")),
    MenuAction("4", "Top Mask Attack", _late("top_mask_crack")),
    MenuAction("5", "Fingerprint Attack", _late("fingerprint_crack")),
    MenuAction("6", "Combinator Attacks", _late("combinator_submenu")),
    MenuAction("7", "Hybrid Attack", _late("hybrid_crack")),
    MenuAction("8", "Pathwell Top 100 Mask Brute Force Crack", _late("pathwell_crack")),
    MenuAction("9", "PRINCE Attack", _late("prince_attack")),
    MenuAction("10", "Bandrel Methodology", _late("bandrel_method")),
    MenuAction("11", "Loopback Attack", _late("loopback_attack")),
    MenuAction("12", "LLM Attack", _late("ollama_attack")),
    MenuAction("13", "OMEN Attack", _late("omen_attack")),
    MenuAction("14", "Ad-hoc Mask Attack", _late("adhoc_mask_crack")),
    MenuAction("15", "Markov Brute Force Attack", _late("markov_brute_force")),
    MenuAction("16", "N-gram Attack", _late("ngram_attack")),
    MenuAction("17", "Permutation Attack", _late("permute_crack")),
    MenuAction("18", "Random Rules Attack", _late("generate_rules_crack")),
    MenuAction("19", "Combipow Passphrase Attack", _late("combipow_crack")),
    MenuAction("20", "PCFG Attack", _late("pcfg_attack")),
    MenuAction("21", "PRINCE-LING Attack", _late("prince_ling_attack")),
    MenuAction("22", "Spoonman Attack", _late("spoonman_attack")),
    MenuAction("23", "Rosetta Attack", _late("rosetta_attack")),
    MenuAction("24", "Corporate Masks Brute Force", _late("corporate_masks_crack")),
    MenuAction("25", "Smart Mask Attack", _late("smart_mask_crack")),
    MenuAction("80", "Wordlist Tools", _late("wordlist_tools_submenu")),
    MenuAction("81", "Rule File Tools", _late("rule_tools_submenu")),
    MenuAction("82", "Notifications", _late("notifications_submenu")),
    MenuAction("83", "Mask Tools", _late("mask_tools_submenu")),
    MenuAction("85", "Attack Coverage", _late("coverage_submenu")),
    MenuAction("93", "Regenerate .out from POT file", _late("restore_potfile_output")),
    MenuAction(
        "94", "Hashview API", _late("hashview_api"), available=_hashview_configured
    ),
    MenuAction("95", "Analyze hashes with Pipal", _late("pipal")),
    MenuAction("96", "Export Output to Excel Format", _late("export_excel")),
    MenuAction("97", "Display Cracked Hashes", _late("show_results")),
    MenuAction("98", "Display README", _late("show_readme")),
    MenuAction("99", "Quit", _late("quit_hc")),
)


def _bound(fn: Any, module: Any) -> Any:
    return fn.bind(module) if hasattr(fn, "bind") else fn


def menu_items(module: Any) -> list[tuple[str, str]]:
    """Ordered (key, label) pairs; availability is read from ``module`` now."""
    return [(a.key, a.label) for a in MAIN_MENU if _bound(a.available, module)()]


def menu_options(module: Any) -> dict[str, Callable[[], Any]]:
    """Key -> handler; handlers resolve their function on ``module`` per call."""
    return {
        a.key: _bound(a.handler, module)
        for a in MAIN_MENU
        if _bound(a.available, module)()
    }
