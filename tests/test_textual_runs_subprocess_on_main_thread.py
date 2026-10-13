"""run_terminal must execute its callable on the thread running Textual's loop.

A terminal-owning subprocess awaited on a worker thread lets Ctrl-C kill the
whole app (signals reach only the main thread). This test pins that the
callable runs on the event-loop thread, not on the calling worker. Driven with
asyncio.run so no async pytest plugin is needed.
"""

import asyncio
import contextlib
import threading

import pytest

from hate_crack.ui.app import HateCrackApp
from hate_crack.ui.textual_ui import TextualUI


def _drive(worker):
    """Run ``worker(ui)`` on a thread while the app runs; return its results."""
    results = {}

    async def body():
        app = HateCrackApp()
        ui = TextualUI()
        ui.bind(app)
        # The headless test driver cannot suspend a real terminal.
        app.suspend = contextlib.nullcontext
        async with app.run_test() as pilot:
            results["loop"] = threading.current_thread()

            def run():
                try:
                    results["value"] = worker(ui, results)
                except BaseException as exc:
                    results["exc"] = exc

            t = threading.Thread(target=run)
            t.start()
            while t.is_alive():
                await pilot.pause(0.05)
            t.join()
            results["alive"] = app.is_running

    asyncio.run(body())
    return results


def test_callable_runs_on_event_loop_thread_not_worker():
    def worker(ui, results):
        results["worker"] = threading.current_thread()

        def fn():
            results["fn"] = threading.current_thread()
            return 42

        return ui.run_terminal(fn)

    r = _drive(worker)
    assert "exc" not in r, r.get("exc")
    assert r["value"] == 42
    assert r["fn"] is r["loop"]
    assert r["fn"] is not r["worker"]


@pytest.mark.parametrize("exc", [ValueError("boom"), KeyboardInterrupt()])
def test_exception_reaches_worker_and_app_survives(exc):
    def worker(ui, results):
        def fn():
            raise exc

        return ui.run_terminal(fn)

    r = _drive(worker)
    assert r["exc"] is exc
    assert r["alive"] is True
