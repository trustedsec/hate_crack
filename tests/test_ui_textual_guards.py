"""The guards that keep the Textual display intact.

Textual owns raw-mode stdin and the screen, so readline completion must not be
installed and debug logging must not write to stderr while it runs. Both
decisions are routed through ``UI.supports_readline``; ``cli`` never names a
backend class.
"""

from __future__ import annotations

import logging
import os

import pytest

from hate_crack import cli, ui
from hate_crack.ui import PlainUI, build_ui

BACKENDS = ["plain", "rich", "textual"]


@pytest.fixture
def install_ui():
    previous = ui._ui
    try:
        yield lambda name: ui.set_ui(build_ui(name))
    finally:
        ui._ui = previous


@pytest.fixture
def clean_loggers():
    urllib3 = logging.getLogger("urllib3")
    logger = logging.getLogger("hate_crack_guard_test")
    saved = (list(urllib3.handlers), urllib3.level)
    logger.handlers.clear()
    urllib3.handlers.clear()
    yield logger
    for h in list(logger.handlers):
        h.close()
    logger.handlers.clear()
    urllib3.handlers[:] = saved[0]
    urllib3.setLevel(saved[1])


def _stream_handlers(logger):
    return [
        h
        for h in logger.handlers
        if isinstance(h, logging.StreamHandler)
        and not isinstance(h, logging.FileHandler)
    ]


@pytest.mark.parametrize("name", BACKENDS)
def test_configure_completion_installed_only_off_textual(name, install_ui, monkeypatch):
    calls = []
    monkeypatch.setattr(cli.readline, "set_completer", lambda c: calls.append(c))
    monkeypatch.setattr(cli.readline, "parse_and_bind", lambda *_: None)
    monkeypatch.setattr(cli.readline, "set_completer_delims", lambda *_: None)
    install_ui(name)

    def completer(text, state):
        return None

    cli.configure_completion(completer)
    assert calls == ([] if name == "textual" else [completer])


@pytest.mark.parametrize("name", BACKENDS)
def test_setup_logging_stderr_handler_only_off_textual(
    name, install_ui, clean_loggers, tmp_path, monkeypatch
):
    monkeypatch.setenv("HOME", str(tmp_path))
    install_ui(name)
    logger = clean_loggers

    result = cli.setup_logging(logger, str(tmp_path), debug_mode=True)

    urllib3 = logging.getLogger("urllib3")
    on_stderr = _stream_handlers(logger) + _stream_handlers(urllib3)
    if name == "textual":
        assert on_stderr == []
        expected = os.path.join(str(tmp_path), ".hate_crack", "debug.log")
        assert result == expected
        assert os.path.exists(expected)
    else:
        assert result is None
        assert on_stderr != []


def test_textual_declares_no_readline_and_others_do():
    assert PlainUI().supports_readline is True
    assert build_ui("rich").supports_readline is True
    assert build_ui("textual").supports_readline is False


def test_unbound_textual_ui_degrades_to_plain(monkeypatch, capsys):
    """Before the app is bound (startup), every call behaves like PlainUI."""
    tui = build_ui("textual")
    plain_ui = PlainUI()
    items = [("1", "one"), ("2", "two")]

    def drive(u, answers):
        feed = iter(answers)
        monkeypatch.setattr("builtins.input", lambda *_: next(feed))
        u.say("s")
        u.warn("w")
        u.error("e")
        u.success("ok")
        out = [
            u.ask("p: ", default="d"),
            u.ask("p: ", default="d"),
            u.confirm("c? ", default=False),
            u.select(items, title="T"),
        ]
        u.columns("Cols", ["a", "b", "c"])
        return out, capsys.readouterr().out

    answers = ["x", "", "y", "2"]
    assert drive(tui, answers) == drive(plain_ui, answers)
