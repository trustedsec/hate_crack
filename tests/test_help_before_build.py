import importlib.util
import os
import sys
from pathlib import Path


def _load_main_module(monkeypatch, argv, force_missing_binary):
    """Reimport hate_crack.main fresh, without conftest's forced SKIP_INIT.

    conftest.py sets HATE_CRACK_SKIP_INIT=1 for the whole session so the
    asset check never runs during collection. This test needs the real,
    un-skipped startup path, so it explicitly deletes the env var before
    reimporting, and forces the expander binary to look missing via
    os.path.isfile regardless of whether hashcat-utils happens to be built
    on the machine running the test.
    """
    monkeypatch.delenv("HATE_CRACK_SKIP_INIT", raising=False)
    monkeypatch.setattr(sys, "argv", argv)

    if force_missing_binary:
        real_isfile = os.path.isfile

        def fake_isfile(path):
            if str(path).endswith("expander.bin"):
                return False
            return real_isfile(path)

        monkeypatch.setattr(os.path, "isfile", fake_isfile)

    module_path = Path(__file__).resolve().parents[1] / "hate_crack" / "main.py"
    module_name = "hate_crack_main_help_test"
    if module_name in sys.modules:
        del sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_help_does_not_exit_when_hashcat_utils_missing(monkeypatch, capsys):
    """`--help` must not hit the expander.bin asset check at import time."""
    _module = _load_main_module(
        monkeypatch, ["hate_crack", "--help"], force_missing_binary=True
    )
    out = capsys.readouterr().out
    assert "expander not found" not in out


def test_argv_requests_help_or_version_true_for_help():
    import hate_crack.main as hc_main

    assert hc_main._argv_requests_help_or_version(["--help"]) is True
    assert hc_main._argv_requests_help_or_version(["-h"]) is True
    assert hc_main._argv_requests_help_or_version(["--version"]) is True
    assert hc_main._argv_requests_help_or_version(["hashes.txt", "1000"]) is False
    assert hc_main._argv_requests_help_or_version([]) is False
