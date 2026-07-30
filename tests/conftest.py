import importlib.util
import os
import sys
from pathlib import Path

import pytest

# Environment variables that point git at a specific repository, index, or
# object store. Git sets these for its own hooks, so a `git push` running the
# prek pre-push hook exports them into pytest -- and any test that shells out to
# git in a throwaway repo then operates on the OUTER repo's index instead of its
# own. That surfaced as `git commit` failing during setup in
# tests/test_upgrade_real_git.py, but only under the hook, never on a bare
# `pytest` run, which makes it the kind of failure that gets dismissed as flaky.
#
# GIT_AUTHOR_* / GIT_COMMITTER_* are deliberately NOT stripped: they only affect
# identity, and a hook-supplied identity is harmless.
_GIT_REPO_LOCATION_VARS = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_PREFIX",
)


@pytest.fixture(autouse=True, scope="session")
def _isolate_git_environment():
    """Unset inherited git repo-location variables for the whole session.

    Session-scoped and autouse so it also covers tests that shell out to git
    from a fixture's setup, which is where this bit first.
    """
    saved = {k: os.environ[k] for k in _GIT_REPO_LOCATION_VARS if k in os.environ}
    for key in saved:
        del os.environ[key]
    try:
        yield
    finally:
        os.environ.update(saved)


def load_hate_crack_module(monkeypatch):
    monkeypatch.setenv("HATE_CRACK_SKIP_INIT", "1")
    module_path = Path(__file__).resolve().parents[1] / "hate_crack.py"
    module_name = "hate_crack_script"
    if module_name in sys.modules:
        del sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def hc_module(monkeypatch):
    return load_hate_crack_module(monkeypatch)


@pytest.fixture(autouse=True)
def _isolate_notify_state():
    """Reset notify module state between tests.

    ``hate_crack.main`` calls ``notify.init()`` at import time with whatever
    ``config.json`` is resolved from the user's environment (e.g.
    ``~/.hate_crack/config.json``).  If that config has
    ``notify_enabled: true``, the per-attack prompt in ``attacks.py`` fires
    ``input()`` during tests and blows up capture.  Forcing the notify
    package back to its disabled-by-default state before every test keeps
    the suite hermetic regardless of the developer's local config.
    """
    try:
        from hate_crack import notify
    except ImportError:
        yield
        return
    notify.clear_state_for_tests()
    yield
    notify.clear_state_for_tests()


def pytest_configure(config):
    """Spin up + seed a local Hashview docker stack for the live test suite.

    No-op unless ``HASHVIEW_TEST_LOCAL=1``. When enabled, brings up the stack
    from the hashview repo, seeds the DB, and exports the ``HASHVIEW_*`` env
    vars the live tests (and the hate_crack CLI) read so they target the local
    instance instead of whatever ``config.json`` points at.

    This runs in ``pytest_configure`` — *before* collection — on purpose: the
    live subprocess tests gate on ``HASHVIEW_TEST_REAL`` via ``@skipif``, which
    is evaluated at collection time. A session fixture would set the env too
    late and every live test would skip. On failure we deliberately leave
    ``HASHVIEW_TEST_REAL`` unset so the live tests skip with their normal
    reason rather than erroring. See ``tests/_hashview_local.py`` for config.
    """
    from tests import _hashview_local as hv

    if not hv.enabled():
        return
    reason = hv.setup()
    if reason is not None:
        config.issue_config_time_warning(
            pytest.PytestWarning(
                f"HASHVIEW_TEST_LOCAL set but local stack unavailable "
                f"({reason}); live Hashview tests will skip."
            ),
            stacklevel=2,
        )


def pytest_unconfigure(config):
    from tests import _hashview_local as hv

    if hv.enabled():
        hv.teardown()
