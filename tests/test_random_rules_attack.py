import importlib.util
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_cli_module():
    """Load a fresh copy of the root ``hate_crack.py`` CLI shim.

    This needs ``hate_crack.main`` (and the ``hate_crack`` package init that
    re-exports it) to be re-executed, so a freshly added menu option is
    visible even if an earlier test already imported and cached the old
    module. Earlier revisions did this by deleting *every* ``hate_crack.*``
    module from ``sys.modules`` except a hand-maintained preserve list
    (``hate_crack.attacks``, ``hate_crack.api``, ...). That approach is
    whack-a-mole: any module that does a name-binding import at module load
    time (``from hate_crack.X import y``) ends up with a stale reference the
    moment X is reloaded while the importer isn't -- because ``y`` is bound
    to a specific function/class object whose ``__globals__``/identity is
    fixed to the OLD module, not looked up live through ``sys.modules``. Each
    such binding (``hate_crack.api``'s ``load_cache``/``append_to_cache``
    from ``hate_crack.hashview_cache`` (#264), ``api``'s ``ConfigValueError``
    from ``config_schema``, ``attacks``'s ``_notify`` from ``notify``, ...)
    was a fresh entry that had to be discovered and added to the preserve
    list one at a time, and a conftest fixture patching the reloaded module
    silently stops reaching the code that actually runs.

    The fix is to invert the list: purge only the two modules that actually
    need to be fresh (``hate_crack.main`` and the ``hate_crack`` package
    itself, since ``hate_crack.py`` does ``from hate_crack import main``) and
    leave every other already-imported ``hate_crack.*`` submodule alone. That
    keeps every name-binding import made anywhere else pointed at the same
    module object conftest's isolation fixtures patch, with no per-binding
    accounting required.
    """
    os.environ["HATE_CRACK_SKIP_INIT"] = "1"
    sys.modules.pop("hate_crack.main", None)
    sys.modules.pop("hate_crack", None)
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


def test_load_cli_module_in_main_menu_after_reload(cli):
    """load_cli_module()'s narrow purge still produces a fresh CLI module."""
    options = cli.get_main_menu_options()
    assert "18" in options


def test_load_cli_module_preserves_name_bound_import_identity(cli):
    """Regression test for #264 (and the module-identity-drift class it belongs to).

    load_cli_module() forces a fresh reload of `hate_crack.main` (and the
    `hate_crack` package init) so newly added state is visible, without
    reloading every other already-imported `hate_crack.*` submodule. Several
    modules bind names directly from another module at import time (`from
    hate_crack.X import y`), e.g.:

    - `hate_crack.api` imports `load_cache`/`append_to_cache` from
      `hate_crack.hashview_cache` (#264's original report).
    - `hate_crack.api` imports `ConfigValueError` from `hate_crack.config_schema`
      -- a class-identity drift here would make `except ConfigValueError` in
      `api.py` silently fail to catch an exception raised by a reloaded
      `config_schema`.
    - `hate_crack.attacks` imports `notify` as `_notify` from `hate_crack.notify`
      -- drift here would mean `notify`'s `_settings`/`_run_consent`/
      `_input_func` state (and conftest's `_isolate_notify_state` fixture,
      which resets that module's state) silently stops applying to the
      object `attacks` actually calls into.

    The `cli` fixture only exercises a single `load_cli_module()` call, which
    can't surface this class of bug by itself -- there is no earlier cached
    module state to drift from on a first import. The drift only shows up
    across a *second* call, which is exactly the real-world shape: one test
    file already forced a reload, then a later test file's fixtures
    re-trigger the module-level `from hate_crack.X import y` imports. So this
    calls `load_cli_module()` again here to reproduce that shape within one
    test. (Verified manually that with the old blanket-purge-except-preserve-
    list implementation, all four assertions below fail after this second
    call; under the current narrow-purge implementation they hold.)
    """
    second_cli = load_cli_module()

    import hate_crack.api as api
    import hate_crack.config_schema as config_schema
    import hate_crack.hashview_cache as hashview_cache
    import hate_crack.notify as notify

    assert api.load_cache is hashview_cache.load_cache
    assert api.append_to_cache is hashview_cache.append_to_cache
    assert api.ConfigValueError is config_schema.ConfigValueError
    assert second_cli._attacks._notify is notify
