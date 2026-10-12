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
