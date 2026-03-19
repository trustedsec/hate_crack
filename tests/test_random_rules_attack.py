import importlib.util
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_cli_module():
    os.environ["HATE_CRACK_SKIP_INIT"] = "1"
    for key in list(sys.modules.keys()):
        # Preserve hate_crack.attacks - reloading it creates a new module object
        # that breaks __globals__ references held by functions imported at
        # module level in other test files (test isolation violation).
        if "hate_crack" in key and key != "hate_crack.attacks":
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
