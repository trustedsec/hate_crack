import importlib.util
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_cli_module():
    os.environ["HATE_CRACK_SKIP_INIT"] = "1"
    _preserve = {"hate_crack.attacks", "hate_crack.api"}
    for key in list(sys.modules.keys()):
        # Preserve hate_crack.attacks and hate_crack.api - reloading them creates
        # new module objects that break __globals__ references held by functions
        # imported at module level in other test files (test isolation violation).
        # In particular, hate_crack.api must be preserved so that mocks applied via
        # patch("hate_crack.api.*") in later tests (e.g. test_rule_download_parallel)
        # target the same module object that the already-imported functions reference.
        if "hate_crack" in key and key not in _preserve:
            del sys.modules[key]
    spec = importlib.util.spec_from_file_location(
        "hate_crack_cli", PROJECT_ROOT / "hate_crack.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def cli():
    return load_cli_module()


def test_generate_rules_crack_in_main_menu(cli):
    options = cli.get_main_menu_options()
    assert "21" in options


def test_generate_rules_crack_handler_calls_main(cli, tmp_path):
    ctx = MagicMock()
    ctx.hcatHashType = "1000"
    ctx.hcatHashFile = "/tmp/h.txt"
    ctx.hcatWordlists = str(tmp_path)
    ctx.list_wordlist_files.return_value = []
    wl = tmp_path / "words.txt"
    wl.write_text("password\n")
    with patch("builtins.input", side_effect=["100", str(wl)]):
        cli._attacks.generate_rules_crack(ctx)
    ctx.hcatGenerateRules.assert_called_once_with("1000", "/tmp/h.txt", 100, str(wl))
