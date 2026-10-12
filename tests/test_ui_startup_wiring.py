"""Startup wiring for the UI backend: resolution rules and build_ui."""

from __future__ import annotations

import os
import subprocess
import sys

from hate_crack.ui import PlainUI, build_ui, resolve_backend_name
from hate_crack.ui.rich_ui import RichUI


def test_non_interactive_forces_plain_even_with_env_rich():
    name = resolve_backend_name(
        env_value="rich",
        config_value="rich",
        is_tty=True,
        term="xterm",
        non_interactive=True,
    )
    assert name == "plain"


def test_non_tty_forces_plain_even_with_config_rich():
    name = resolve_backend_name(
        env_value=None,
        config_value="rich",
        is_tty=False,
        term="xterm",
        non_interactive=False,
    )
    assert name == "plain"


def test_build_ui_plain():
    assert isinstance(build_ui("plain"), PlainUI)


def test_build_ui_rich():
    assert isinstance(build_ui("rich"), RichUI)


def test_build_ui_unknown_returns_plain_without_raising():
    assert isinstance(build_ui("bogus"), PlainUI)


def test_importing_ui_does_not_import_rich_backend():
    # Subprocess: the shared pytest process already imported RichUI, so an
    # in-process sys.modules check would be order-dependent.
    env = dict(os.environ, HATE_CRACK_SKIP_INIT="1")
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import hate_crack.ui, sys; "
            "assert 'hate_crack.ui.rich_ui' not in sys.modules",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, f"stderr:\n{proc.stderr}"


# ---------------------------------------------------------------------------
# main() wiring: drive the real main() up to the interactive menu.
# ---------------------------------------------------------------------------
class _StopAtMenu(Exception):
    pass


def _drive_main(monkeypatch, tmp_path, *, tty: bool, env_ui: str | None):
    """Run the real main() on an md5 hash file until it reaches the menu.

    Returns the list of objects passed to ``set_ui``.
    """
    import hate_crack.main as hc_main

    hashfile = tmp_path / "hashes.txt"
    hashfile.write_text("5f4dcc3b5aa765d61d8327deb882cf99\n")
    (tmp_path / "hashes.txt.out").write_text("")  # skip the potfile "show" run

    installed: list = []
    monkeypatch.setattr(hc_main._ui, "set_ui", installed.append)
    monkeypatch.setattr(hc_main.sys.stdout, "isatty", lambda: tty, raising=False)
    monkeypatch.setenv("TERM", "xterm")
    if env_ui is None:
        monkeypatch.delenv("HATE_CRACK_UI", raising=False)
    else:
        monkeypatch.setenv("HATE_CRACK_UI", env_ui)

    def _stop(*_a, **_k):
        raise _StopAtMenu

    monkeypatch.setattr(hc_main, "interactive_menu", _stop)
    monkeypatch.setattr(hc_main.sys, "argv", ["hate_crack.py", str(hashfile), "0"])
    try:
        hc_main.main()
    except _StopAtMenu:
        pass
    return installed


def test_main_installs_plain_ui_and_prints_nothing_extra(monkeypatch, tmp_path, capsys):
    installed = _drive_main(monkeypatch, tmp_path, tty=False, env_ui=None)
    assert len(installed) == 1
    assert isinstance(installed[0], PlainUI)
    assert "UI backend" not in capsys.readouterr().out


def test_main_installs_rich_ui_and_announces_it(monkeypatch, tmp_path, capsys):
    installed = _drive_main(monkeypatch, tmp_path, tty=True, env_ui="rich")
    assert len(installed) == 1
    assert isinstance(installed[0], RichUI)
    assert "[*] UI backend: rich" in capsys.readouterr().out
