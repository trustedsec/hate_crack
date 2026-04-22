import importlib.util
import sys
from pathlib import Path

import pytest


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
