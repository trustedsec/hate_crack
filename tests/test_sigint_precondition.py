"""Guard the SIGINT precondition a future Textual UI phase depends on.

Background: a prototype for the planned full-screen UI phase showed that
``asyncio.Runner`` (reached through ``App.run()`` -> ``asyncio.run()``)
installs its own SIGINT handler that cancels the main task. With that handler
active, Ctrl-C during a hashcat run, which the UI hands the terminal to via
``App.suspend()``, would exit the WHOLE application instead of killing hashcat
and returning to the menu, which is today's behaviour and what operators rely
on. ``asyncio.Runner`` declines to install its handler when the current SIGINT
handler is not ``signal.default_int_handler``. ``main()`` installs
``_sigint_handler`` for an unrelated reason (the DoubleInterrupt feature), so
the precondition holds today by accident. These tests make sure it cannot be
removed silently.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import signal
import textwrap
import threading

import pytest

pytestmark = pytest.mark.skipif(
    threading.current_thread() is not threading.main_thread(),
    reason="signal handlers can only be installed from the main thread",
)


@pytest.fixture
def restore_sigint():
    original = signal.getsignal(signal.SIGINT)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, original)


def test_asyncio_run_leaves_custom_sigint_handler_alone(restore_sigint):
    """Pin the CPython behaviour the future Textual phase relies on.

    This looks like a test of the standard library, but it is not: it pins the
    mechanism (asyncio.Runner only takes SIGINT when the handler is
    default_int_handler), not a version number. If it fails, a custom handler
    no longer protects Ctrl-C-kills-hashcat under a Textual App.
    """

    def sentinel(signum, frame):  # pragma: no cover - never delivered
        pass

    async def noop():
        return None

    signal.signal(signal.SIGINT, sentinel)
    asyncio.run(noop())
    assert signal.getsignal(signal.SIGINT) is sentinel

    # Contrast case: with the default handler, the runner DOES take over.
    seen = {}

    async def record():
        seen["handler"] = signal.getsignal(signal.SIGINT)

    signal.signal(signal.SIGINT, signal.default_int_handler)
    asyncio.run(record())
    assert seen["handler"] is not signal.default_int_handler


def test_main_installs_sigint_handler():
    """hate_crack must keep installing its own SIGINT handler in main().

    Guards the future Textual phase: that handler is what stops asyncio.Runner
    from installing one that would make Ctrl-C exit the whole app. Removing
    it, even as apparent dead code, silently breaks that phase.
    """
    from hate_crack import main as hc_main

    assert callable(getattr(hc_main, "_sigint_handler", None))

    tree = ast.parse(textwrap.dedent(inspect.getsource(hc_main.main)))
    found = False
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        f = node.func
        if not (
            f.attr == "signal"
            and isinstance(f.value, ast.Name)
            and f.value.id == "signal"
            and len(node.args) == 2
        ):
            continue
        a0, a1 = node.args
        if (
            isinstance(a0, ast.Attribute)
            and a0.attr == "SIGINT"
            and isinstance(a1, ast.Name)
            and a1.id == "_sigint_handler"
        ):
            found = True
    assert found, "main() no longer calls signal.signal(SIGINT, _sigint_handler)"
