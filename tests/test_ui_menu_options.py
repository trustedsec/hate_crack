import importlib.util
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CLI_SPEC = importlib.util.spec_from_file_location(
    "hate_crack_cli", PROJECT_ROOT / "hate_crack.py"
)
CLI_MODULE = importlib.util.module_from_spec(CLI_SPEC)
CLI_SPEC.loader.exec_module(CLI_MODULE)

MENU_OPTION_TEST_CASES = [
    ("1", CLI_MODULE._attacks, "quick_crack", "quick-crack"),
    ("2", CLI_MODULE._attacks, "extensive_crack", "extensive-crack"),
    ("3", CLI_MODULE._attacks, "brute_force_crack", "brute-force"),
    ("4", CLI_MODULE._attacks, "top_mask_crack", "top-mask"),
    ("5", CLI_MODULE._attacks, "fingerprint_crack", "fingerprint"),
    ("6", CLI_MODULE._attacks, "combinator_submenu", "combinator"),
    ("7", CLI_MODULE._attacks, "hybrid_crack", "hybrid"),
    ("8", CLI_MODULE._attacks, "pathwell_crack", "pathwell"),
    ("9", CLI_MODULE._attacks, "prince_attack", "prince"),
    ("10", CLI_MODULE._attacks, "bandrel_method", "bandrel"),
    ("11", CLI_MODULE._attacks, "loopback_attack", "loopback"),
    ("12", CLI_MODULE._attacks, "ollama_attack", "ollama"),
    ("13", CLI_MODULE._attacks, "omen_attack", "omen"),
    ("14", CLI_MODULE._attacks, "adhoc_mask_crack", "adhoc-mask"),
    ("15", CLI_MODULE._attacks, "markov_brute_force", "markov-brute"),
    ("16", CLI_MODULE._attacks, "ngram_attack", "ngram"),
    ("17", CLI_MODULE._attacks, "permute_crack", "permute"),
    ("18", CLI_MODULE._attacks, "generate_rules_crack", "random-rules"),
    ("19", CLI_MODULE._attacks, "combipow_crack", "combipow"),
    ("20", CLI_MODULE._attacks, "pcfg_attack", "pcfg"),
    ("21", CLI_MODULE._attacks, "prince_ling_attack", "prince-ling"),
    ("22", CLI_MODULE._attacks, "spoonman_attack", "spoonman"),
    ("23", CLI_MODULE._attacks, "rosetta_attack", "rosetta"),
    ("24", CLI_MODULE._attacks, "corporate_masks_crack", "corporate-masks"),
    ("25", CLI_MODULE._attacks, "smart_mask_crack", "smart-mask"),
    ("80", CLI_MODULE._attacks, "wordlist_tools_submenu", "wordlist-tools"),
    ("81", CLI_MODULE._attacks, "rule_tools_submenu", "rule-tools"),
    ("82", CLI_MODULE, "notifications_submenu", "notifications-submenu"),
    ("83", CLI_MODULE._attacks, "mask_tools_submenu", "mask-tools"),
    ("93", CLI_MODULE._attacks, "restore_potfile_output", "restore-potfile"),
    ("95", CLI_MODULE, "pipal", "pipal"),
    ("96", CLI_MODULE, "export_excel", "export-excel"),
    ("97", CLI_MODULE, "show_results", "show-results"),
    ("98", CLI_MODULE, "show_readme", "show-readme"),
    ("99", CLI_MODULE, "quit_hc", "quit"),
]


@pytest.mark.parametrize(
    ("option_key", "target_module", "target_attr", "expected_prefix"),
    MENU_OPTION_TEST_CASES,
)
def test_main_menu_option_returns_expected(
    monkeypatch, option_key, target_module, target_attr, expected_prefix
):
    sentinel = f"{expected_prefix}-{option_key}"
    monkeypatch.setattr(
        target_module,
        target_attr,
        lambda *args, **kwargs: sentinel,
    )

    options = CLI_MODULE.get_main_menu_options()
    assert option_key in options, f"Menu option {option_key} must exist"
    handler = options[option_key]
    assert handler() == sentinel


def test_main_menu_option_94_hashview_hidden_without_hashview_api_key(monkeypatch):
    monkeypatch.setattr(CLI_MODULE, "hashview_api_key", "")
    options = CLI_MODULE.get_main_menu_options()
    assert "94" not in options


def test_main_menu_option_94_hashview_visible_with_hashview_api_key(monkeypatch):
    monkeypatch.setattr(CLI_MODULE, "hashview_api_key", "test-key")
    sentinel = "hashview-94"
    monkeypatch.setattr(CLI_MODULE, "hashview_api", lambda *a, **k: sentinel)
    options = CLI_MODULE.get_main_menu_options()
    assert "94" in options
    assert options["94"]() == sentinel


def test_main_menu_option_83_is_mask_tools_84_still_unused():
    """83 was retired alongside 84 when notification toggles moved into the
    Notifications submenu (option 82), then reclaimed for Mask Tools -- it
    now sits alongside Wordlist Tools (80) and Rule File Tools (81). 84
    remains unused."""
    options = CLI_MODULE.get_main_menu_options()
    assert "83" in options
    assert "84" not in options
    assert "82" in options


def test_spoonman_routes_through_both_duplicate_menu_mappings(monkeypatch):
    """hate_crack.py carries a menu mapping separate from main.py's.

    The Spoonman baseword-source work (task 6) added no new menu key and did
    not rename the handler, so neither mapping needed an edit -- but "no edit
    needed" is only true while both still resolve to the same handler, which
    is what this pins.
    """
    sentinel = "spoonman-both-mappings"
    monkeypatch.setattr(
        CLI_MODULE._attacks, "spoonman_attack", lambda *a, **k: sentinel
    )

    cli_options = CLI_MODULE.get_main_menu_options()
    main_options = CLI_MODULE._main.get_main_menu_options()
    assert "22" in cli_options
    assert "22" in main_options
    assert cli_options["22"]() == sentinel
    assert main_options["22"]() == sentinel


def test_mask_tools_routes_through_both_duplicate_menu_mappings():
    """hate_crack.py carries a menu mapping separate from main.py's, and both
    must carry option 83 pointing at the same handler.

    Compared by qualified name, not by object identity: the suite purges
    hate_crack.main from sys.modules between tests, so CLI_MODULE._main can be
    a different module object than the live one and an `is` check passes alone
    while failing in a full run. The failure this guards -- 83 added to one
    mapping only, or pointed at a different handler -- is caught either way.
    """
    cli_options = CLI_MODULE.get_main_menu_options()
    main_options = CLI_MODULE._main.get_main_menu_options()
    assert "83" in cli_options, "hate_crack.py mapping is missing option 83"
    assert "83" in main_options, "main.py mapping is missing option 83"
    assert (
        cli_options["83"].__qualname__
        == main_options["83"].__qualname__
        == "mask_tools_submenu"
    )


def test_main_menu_items_include_notifications_entry():
    items = dict(CLI_MODULE.get_main_menu_items())
    assert "82" in items
    assert "Notifications" in items["82"]
    assert "83" in items
    assert "Mask Tools" in items["83"]
    assert "84" not in items


def test_main_menu_exposes_attack_coverage_at_85():
    """85, not 84: 84 is a retired notification toggle, and reusing it would
    hand an operator's muscle memory a different feature. 83 is legitimately
    in use again, for Mask Tools."""
    items = dict(CLI_MODULE.get_main_menu_items())
    options = CLI_MODULE.get_main_menu_options()
    assert "85" in items
    assert "Attack Coverage" in items["85"]
    assert "85" in options
    assert callable(options["85"])


def test_coverage_menu_routes_through_both_duplicate_menu_mappings():
    """hate_crack.py carries a menu mapping separate from main.py's, and both
    must carry option 85 pointing at the same handler.

    Compared by qualified name, not by object identity: the suite purges
    hate_crack.main from sys.modules between tests, so CLI_MODULE._main can be
    a different module object than the live one and an `is` check passes alone
    while failing in a full run. The failure this guards -- 85 added to one
    mapping only, or pointed at a different handler -- is caught either way.
    """
    cli_options = CLI_MODULE.get_main_menu_options()
    main_options = CLI_MODULE._main.get_main_menu_options()
    assert "85" in cli_options, "hate_crack.py mapping is missing option 85"
    assert "85" in main_options, "main.py mapping is missing option 85"
    assert (
        cli_options["85"].__qualname__
        == main_options["85"].__qualname__
        == "coverage_submenu"
    )


def test_shim_does_not_carry_its_own_menu_mapping(monkeypatch):
    """hate_crack.py used to hand-sync a duplicate of main's menu, whose
    handlers were the raw attacks.* functions (they need a ctx and would raise
    TypeError if dispatched). The menu now lives once, in menu_registry."""
    import ast
    import inspect

    for key_state in ("", "k"):
        monkeypatch.setattr(CLI_MODULE._main, "hashview_api_key", key_state)
        monkeypatch.setattr(CLI_MODULE, "hashview_api_key", key_state)
        shim = CLI_MODULE.get_main_menu_options()
        main_ = CLI_MODULE._main.get_main_menu_options()
        assert list(shim) == list(main_)
        assert {k: v.__qualname__ for k, v in shim.items()} == {
            k: v.__qualname__ for k, v in main_.items()
        }
        assert (
            CLI_MODULE.get_main_menu_items() == CLI_MODULE._main.get_main_menu_items()
        )
        # Dispatch calls handlers with no arguments; the old shim copy did not.
        assert not [k for k, v in shim.items() if inspect.signature(v).parameters]

    tree = ast.parse((PROJECT_ROOT / "hate_crack.py").read_text())
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in (
            "get_main_menu_items",
            "get_main_menu_options",
        ):
            found.add(node.name)
            src = ast.unparse(node)
            assert "_attacks" not in src, f"{node.name} re-grew its own mapping"
            assert not any(isinstance(n, ast.Dict) for n in ast.walk(node))
    assert found == {"get_main_menu_items", "get_main_menu_options"}


def test_menu_registry_resolves_handlers_late(monkeypatch):
    """Replacing a function on main after import must change what the menu
    dispatches to (this is what _sync_callables_to_main relies on)."""
    main = CLI_MODULE._main
    handler = main.get_main_menu_options()["99"]
    monkeypatch.setattr(main, "quit_hc", lambda: "swapped")
    import sys

    if sys.modules["hate_crack.main"] is not main:
        monkeypatch.setattr(
            sys.modules["hate_crack.main"], "quit_hc", lambda: "swapped"
        )
    assert handler() == "swapped"
