"""run_textual must outlive its worker, not the other way round.

The worker runs on a daemon thread; if run_textual returned the moment the app
exited, the interpreter would kill the worker mid-statement and truncate
whatever file it was writing. These tests drive the real app headlessly.
"""

import contextlib
import threading
import time

import pytest

from hate_crack import ui as ui_mod
from hate_crack.ui import TerminalUnavailable, build_ui
from hate_crack.ui.app import HateCrackApp


@pytest.fixture(autouse=True)
def _headless(monkeypatch):
    original = HateCrackApp.run
    monkeypatch.setattr(HateCrackApp, "run", lambda self: original(self, headless=True))
    previous = ui_mod._ui
    ui_mod.set_ui(build_ui("textual"))
    yield
    ui_mod._ui = previous
    ui_mod._shutdown.clear()


def _quit_app():
    app = ui_mod.get_ui()._app
    app.call_from_thread(app.exit)


def test_worker_finishes_a_write_that_outlasts_the_app(tmp_path):
    target = tmp_path / "rules.txt"
    seen = {}

    def loop():
        _quit_app()  # the operator presses ctrl+q; the app is gone in ms
        deadline = time.monotonic() + 5
        while not ui_mod.shutdown_requested() and time.monotonic() < deadline:
            time.sleep(0.01)
        seen["shutdown"] = ui_mod.shutdown_requested()
        with target.open("w") as fh:
            fh.write("first line\n")
            time.sleep(0.6)  # measurably longer than the app's teardown
            fh.write("last line\n")
        seen["done"] = True

    ui_mod.run_textual(loop)

    assert seen == {"shutdown": True, "done": True}
    assert target.read_text() == "first line\nlast line\n"


def test_exception_raised_after_the_app_exits_is_not_swallowed():
    def loop():
        _quit_app()
        time.sleep(0.4)
        raise ValueError("late failure")

    with pytest.raises(ValueError, match="late failure"):
        ui_mod.run_textual(loop)


def test_worker_output_after_app_exit_does_not_hang(capsys):
    def loop():
        _quit_app()
        time.sleep(0.4)
        ui_mod.get_ui().say("late line")
        assert ui_mod.get_ui().ask("late? ") == ""

    ui_mod.run_textual(loop)
    assert "late line" in capsys.readouterr().out


def test_a_worker_that_will_not_finish_is_reported(monkeypatch, capsys):
    monkeypatch.setattr(ui_mod, "WORKER_JOIN_TIMEOUT", 0.6)
    monkeypatch.setattr(ui_mod, "_WORKER_JOIN_QUIET", 0.2)
    release = threading.Event()

    def loop():
        _quit_app()
        release.wait(10)

    try:
        ui_mod.run_textual(loop)
        out = capsys.readouterr()
    finally:
        release.set()
    assert "incomplete" in out.out + out.err


def test_unsupported_suspend_aborts_the_attack_with_a_message():
    import asyncio

    from textual.app import SuspendNotSupported

    ran = []
    messages = []

    @contextlib.contextmanager
    def no_suspend():
        raise SuspendNotSupported("no")
        yield  # pragma: no cover

    async def body():
        app = HateCrackApp()
        ui = build_ui("textual")
        ui.bind(app)
        ui.error = messages.append
        app.suspend = no_suspend
        result = {}
        async with app.run_test() as pilot:

            def run():
                try:
                    ui.run_terminal(lambda: ran.append(1))
                except BaseException as exc:
                    result["exc"] = exc

            t = threading.Thread(target=run)
            t.start()
            while t.is_alive():
                await pilot.pause(0.05)
            t.join()
            result["alive"] = app.is_running
        return result

    result = asyncio.run(body())
    assert isinstance(result["exc"], TerminalUnavailable)
    assert result["alive"] is True  # the app survived
    assert ran == []  # hashcat was not started on the worker
    assert "ui_backend=rich" in messages[0]


def test_menu_loop_survives_terminal_unavailable_and_stops_on_shutdown(monkeypatch):
    from hate_crack import main

    calls = []

    def boom():
        calls.append("handler")
        raise TerminalUnavailable("x")

    monkeypatch.setattr(main, "get_main_menu_options", lambda: {"1": boom})
    monkeypatch.setattr(main, "get_main_menu_items", lambda: [])
    picks = iter(["1"])

    def pick(items, title=None):
        try:
            return next(picks)
        except StopIteration:
            ui_mod._shutdown.set()
            return None

    main._menu_loop(pick)
    assert calls == ["handler"]
