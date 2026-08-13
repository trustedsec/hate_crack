import importlib.util
import os
import sys
from pathlib import Path

import pytest

# Set before any test module -- and therefore before anything imports
# hate_crack.main -- rather than per-test. main.py's config bootstrap writes a
# `.env` (from a legacy config.json, or from schema defaults) unless SKIP_INIT
# is set, and whichever test module happens to import main first would
# otherwise create one in the repo root or in ~/.hate_crack as a side effect
# of collection. Individual tests that want the un-skipped path still
# monkeypatch this themselves.
os.environ.setdefault("HATE_CRACK_SKIP_INIT", "1")

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
def _isolate_config_file_discovery(monkeypatch):
    """Keep the suite from finding the developer's real config files.

    ``config_loader.candidate_roots()`` searches the repo root, the package
    directory, and ``~/.hate_crack`` -- so on a machine where hate_crack has
    actually been run, ``api.py``'s helpers would silently load a real
    ``.env``/``config.json`` (complete with real API keys) instead of the
    fixture the test set up. Emptying the search order makes "no config file"
    the hermetic default; a test that wants specific files passes their paths
    explicitly, or re-patches this itself (an autouse fixture is applied
    before the test body, so the test's own monkeypatch wins).
    """
    from hate_crack import config_loader

    monkeypatch.setattr(config_loader, "candidate_roots", list)
    yield


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


@pytest.fixture(autouse=True)
def _isolate_hashview_cache(monkeypatch, tmp_path):
    """Isolate the hashview upload cache per test to avoid cross-test
    contamination.

    The cache module reads from
    ``~/.hate_crack/hashview_uploaded_cache.txt`` by default (see
    ``hate_crack.hashview_cache.CACHE_FILENAME``). Without isolation, tests
    that populate the cache would affect subsequent tests, causing hashes to
    be unexpectedly skipped as already-cached.

    This patches ``hashview_cache._cache_path`` directly rather than
    monkeypatching ``HOME`` for the whole process -- ``HOME`` affects far
    more than this one cache (path expansion elsewhere in the suite), so
    narrowing to the specific function keeps this fixture's blast radius to
    exactly the thing it isolates.
    """
    from hate_crack import hashview_cache

    monkeypatch.setattr(
        hashview_cache,
        "_cache_path",
        lambda: tmp_path / ".hate_crack" / hashview_cache.CACHE_FILENAME,
    )


def pytest_configure(config):
    """Run setup before test collection.

    - Ensure submodules are initialized (issue #266)
    - Spin up + seed a local Hashview docker stack if enabled
    """
    _ensure_submodules_initialized(config)
    _setup_local_hashview_if_enabled(config)


def _ensure_submodules_initialized(config):
    """Ensure submodules are initialized before test collection.

    This runs in pytest_configure — *before* test collection — so that
    hate_crack.main's module-level import always sees a populated HashcatRosetta/
    on the very first run, not just the second. hashcat_rosetta is imported at
    module level in hate_crack/main.py (~line 96-107), so a fresh-worktree
    first run would cache ROSETTA_IMPORT_ERROR if the submodule wasn't populated
    yet. See issue #266.

    No-op if we're not in a git repo, or if git/git submodules are unavailable.
    In a git worktree, the submodule directories might remain empty (submodule
    update exits 0 but doesn't populate worktree dirs), which is expected and
    not an error — just not all tests will be available.
    """
    import subprocess
    import shutil

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))

    # Guard: only attempt init if we're in a git repo with .gitmodules
    has_git_dir = os.path.isdir(os.path.join(repo_root, ".git"))
    has_gitmodules = os.path.isfile(os.path.join(repo_root, ".gitmodules"))
    has_git_cmd = shutil.which("git") is not None

    if not (has_git_dir and has_gitmodules and has_git_cmd):
        return

    # Try to init submodules
    try:
        result = subprocess.run(
            ["git", "submodule", "update", "--init", "--recursive"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=30,
        )
        # Don't fail if the command fails or if dirs remain empty (worktree case).
        # Log a warning if something went wrong, but continue.
        if result.returncode != 0:
            config.issue_config_time_warning(
                pytest.PytestWarning(
                    f"git submodule update failed during pytest_configure "
                    f"(some tests may fail): {result.stderr}"
                ),
                stacklevel=2,
            )
    except Exception as e:
        config.issue_config_time_warning(
            pytest.PytestWarning(
                f"Failed to initialize submodules during pytest_configure: {e}"
            ),
            stacklevel=2,
        )


def _setup_local_hashview_if_enabled(config):
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
