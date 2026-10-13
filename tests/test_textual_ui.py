"""TextualUI behaviour: prompts, cancel, columns order, unbound degradation."""

import asyncio
import threading

from textual.widgets import Input, RichLog

from hate_crack.ui import build_ui, resolve_backend_name
from hate_crack.ui.app import HateCrackApp
from hate_crack.ui.textual_ui import TextualUI


def _drive(worker, script):
    """``script(pilot, app)`` plays the operator while ``worker(ui)`` blocks."""
    out = {}

    async def body():
        app = HateCrackApp()
        ui = TextualUI()
        ui.bind(app)
        async with app.run_test() as pilot:
            t = threading.Thread(target=lambda: out.update(v=worker(ui)))
            t.start()
            await pilot.pause(0.2)
            await script(pilot, app)
            while t.is_alive():
                await pilot.pause(0.05)
            t.join()
            out["log"] = "\n".join(
                line.text for line in app.query_one("#content", RichLog).lines
            )

    asyncio.run(body())
    return out


def _type(text):
    async def script(pilot, app):
        await pilot.click(Input)
        for ch in text:
            await pilot.press(ch)
        await pilot.press("enter")
        await pilot.pause(0.1)

    return script


async def _escape(pilot, app):
    await pilot.press("escape")
    await pilot.pause(0.1)


def test_ask_returns_typed_value():
    assert _drive(lambda ui: ui.ask("name? "), _type("abc"))["v"] == "abc"


def test_ask_cancel_returns_empty():
    assert _drive(lambda ui: ui.ask("x ", default="d"), _escape)["v"] == ""


def test_ask_int_cancel_and_value():
    assert _drive(lambda ui: ui.ask_int("n "), _escape)["v"] is None
    assert _drive(lambda ui: ui.ask_int("n "), _type("7"))["v"] == 7


def test_confirm_cancel_returns_default():
    assert _drive(lambda ui: ui.confirm("ok? ", default=False), _escape)["v"] is False
    assert _drive(lambda ui: ui.confirm("ok? ", default=True), _escape)["v"] is True


def test_select_cancel_and_choice():
    items = [("1", "one"), ("2", "two")]
    assert _drive(lambda ui: ui.select(items), _escape)["v"] is None
    assert _drive(lambda ui: ui.select(items), _type("2"))["v"] == "2"


def test_columns_are_column_major(monkeypatch):
    from hate_crack import formatting

    monkeypatch.setattr(formatting, "_terminal_width", lambda: 40)

    async def noop(pilot, app):
        pass

    out = _drive(
        lambda ui: ui.columns(None, ["a", "b", "c", "d"], min_col_width=20), noop
    )
    rows = [ln.split() for ln in out["log"].splitlines() if ln.strip()]
    assert rows == [["a", "c"], ["b", "d"]]


def test_unbound_degrades_to_plain(capsys):
    ui = TextualUI()
    ui.say("hello")
    ui.warn("careful")
    assert "hello" in capsys.readouterr().out
    assert ui.run_terminal(lambda: 5) == 5


def test_build_and_resolution():
    assert isinstance(build_ui("textual"), TextualUI)
    kw = {"is_tty": True, "term": "xterm"}
    assert resolve_backend_name(config_value="textual", **kw) == "textual"
    assert resolve_backend_name(config_value="textual", is_tty=False) == "plain"
    assert (
        resolve_backend_name(config_value="textual", is_tty=True, term="dumb")
        == "plain"
    )
    assert (
        resolve_backend_name(config_value="textual", non_interactive=True, **kw)
        == "plain"
    )
