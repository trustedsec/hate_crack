import importlib.util
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_cli_module():
    os.environ["HATE_CRACK_SKIP_INIT"] = "1"
    _preserve = {"hate_crack.attacks", "hate_crack.api", "hate_crack.hashview_cache"}
    for key in list(sys.modules.keys()):
        # Preserve hate_crack.attacks and hate_crack.api - reloading them creates
        # new module objects that break __globals__ references held by functions
        # imported at module level in other test files (test isolation violation).
        # In particular, hate_crack.api must be preserved so that mocks applied via
        # patch("hate_crack.api.*") in later tests (e.g. test_rule_download_parallel)
        # target the same module object that the already-imported functions reference.
        #
        # hate_crack.hashview_cache must be preserved for the same reason:
        # hate_crack.api does `from hate_crack.hashview_cache import load_cache,
        # append_to_cache` at module level, binding api's names directly to that
        # module's function objects. If hashview_cache is reloaded here while api
        # is preserved, api's load_cache/append_to_cache keep pointing at the OLD
        # module's functions (whose __globals__ is the old module dict). Any later
        # test's `_isolate_hashview_cache` fixture then patches the NEW module's
        # _cache_path, which api's already-bound functions never see -- silently
        # defeating the cache isolation and risking writes to the real
        # ~/.hate_crack/hashview_uploaded_cache.txt (#264).
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
    assert "18" in options


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


def test_load_cli_module_preserves_hashview_cache_identity(cli):
    """Regression test for #264.

    load_cli_module() purges most `hate_crack.*` modules from sys.modules to
    force a fresh reload, but must preserve `hate_crack.hashview_cache`
    alongside `hate_crack.api`/`hate_crack.attacks`. `hate_crack.api` imports
    `load_cache`/`append_to_cache` by name at module load time
    (`from hate_crack.hashview_cache import ...`), binding those names
    directly to that module's function objects. If hashview_cache were
    reloaded here while api is preserved, api's load_cache/append_to_cache
    would keep pointing at the OLD module's functions -- and a later test's
    `_isolate_hashview_cache` conftest fixture, which patches the *current*
    `hate_crack.hashview_cache` module's `_cache_path`, would silently fail
    to isolate api's calls from the real `~/.hate_crack` cache file.
    """
    import hate_crack.api as api
    import hate_crack.hashview_cache as hashview_cache

    assert api.load_cache is hashview_cache.load_cache
    assert api.append_to_cache is hashview_cache.append_to_cache
