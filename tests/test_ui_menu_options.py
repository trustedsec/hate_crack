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
    ("6", CLI_MODULE._attacks, "combinator_crack", "combinator"),
    ("7", CLI_MODULE._attacks, "hybrid_crack", "hybrid"),
    ("8", CLI_MODULE._attacks, "pathwell_crack", "pathwell"),
    ("9", CLI_MODULE._attacks, "prince_attack", "prince"),
    ("10", CLI_MODULE._attacks, "yolo_combination", "yolo"),
    ("11", CLI_MODULE._attacks, "middle_combinator", "middle"),
    ("12", CLI_MODULE._attacks, "thorough_combinator", "thorough"),
    ("13", CLI_MODULE._attacks, "bandrel_method", "bandrel"),
    ("14", CLI_MODULE._attacks, "loopback_attack", "loopback"),
    ("15", CLI_MODULE._attacks, "ollama_attack", "ollama"),
    ("16", CLI_MODULE._attacks, "omen_attack", "omen"),
    ("17", CLI_MODULE._attacks, "passgpt_attack", "passgpt"),
    ("90", CLI_MODULE, "download_hashmob_rules", "hashmob-rules"),
    ("91", CLI_MODULE, "weakpass_wordlist_menu", "weakpass-menu"),
    ("92", CLI_MODULE, "download_hashmob_wordlists", "hashmob-wordlists"),
    ("93", CLI_MODULE, "weakpass_wordlist_menu", "weakpass-menu-secondary"),
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
