"""UI abstraction seam: a Protocol, the plain backend, and backend resolution."""

from __future__ import annotations

import contextlib
import threading
from contextlib import AbstractContextManager
from collections.abc import Callable
from typing import Any, Protocol, TypeVar

from hate_crack.ui.plain import PlainUI

T = TypeVar("T")

BACKENDS = ("plain", "rich", "textual")


class TerminalUnavailable(RuntimeError):
    """The backend cannot hand the terminal to a subprocess; the attack aborts."""


class UI(Protocol):
    def say(self, text: str = "", *, style: str | None = None) -> None: ...

    def warn(self, text: str) -> None: ...

    def error(self, text: str) -> None: ...

    def success(self, text: str) -> None: ...

    def ask(self, prompt: str = "", *, default: str = "") -> str: ...

    def ask_int(
        self,
        prompt: str,
        *,
        default: int | None = None,
        minimum: int | None = None,
    ) -> int | None: ...

    def confirm(self, prompt: str, *, default: bool = True) -> bool: ...

    def select(
        self,
        items: list[tuple[str, str]],
        *,
        title: str | None = None,
        prompt: str = "\nSelect a task: ",
    ) -> str | None: ...

    def columns(
        self,
        title: str | None,
        entries: list[str],
        *,
        min_col_width: int = 20,
        max_col_width: int | None = None,
        styles: list[str | None] | None = None,
    ) -> None: ...

    def spinner(self, message: str) -> AbstractContextManager[Any]: ...

    def run_terminal(self, fn: Callable[[], T]) -> T:
        """Run ``fn``, which owns the terminal (e.g. awaits a child process).

        A terminal-owning subprocess must be awaited on the main thread so
        that Ctrl-C reaches it; a backend running logic on a worker thread
        marshals ``fn`` there. Plain backends just call it.
        """
        ...


def readline_supported() -> bool:
    """False when the active backend owns raw-mode stdin (Textual).

    ``supports_readline`` is an optional capability attribute on a backend, not
    a ``UI`` protocol member: only the one backend that says False matters, and
    a backend that omits it (a test double) gets readline as before.
    """
    return bool(getattr(get_ui(), "supports_readline", True))


def resolve_backend_name(
    *,
    config_value: str | None = None,
    is_tty: bool = False,
    term: str | None = None,
    non_interactive: bool = False,
) -> str:
    """Pick a backend name. Pure: every input is a parameter.

    There is deliberately no environment parameter: the ``UI_BACKEND``
    environment override arrives through the config loader (CLI flag >
    os.environ > home file > schema default), so ``config_value`` already
    carries it. A second env path here would be a parallel config path.
    """
    name = "plain"
    if config_value and config_value in BACKENDS:
        name = config_value
    if non_interactive or not is_tty or (term or "").lower() == "dumb":
        return "plain"
    return name


def build_ui(name: str) -> UI:
    """Map a backend name to an instance.

    The only place that knows which class backs which name. ``rich_ui`` is
    imported here, not at module scope, so a plain run never imports Rich.
    An unknown name yields a PlainUI: a bad config value must not stop startup.
    """
    if name == "rich":
        from hate_crack.ui.rich_ui import RichUI

        return RichUI()
    if name == "textual":
        from hate_crack.ui.textual_ui import TextualUI

        return TextualUI()
    return PlainUI()


# How long run_textual waits for the worker after the app exits. The worker may
# legitimately be mid-write (a rule file, a .working file, an upload), so it is
# waited out rather than abandoned; 30 s covers those and any loop that polls
# shutdown_requested(), yet bounds a wedged network call so a quit can never
# hold the restored terminal forever. Ctrl+C during the wait abandons it too.
WORKER_JOIN_TIMEOUT = 30.0
_WORKER_JOIN_QUIET = 1.0  # join this long silently before printing a notice

_shutdown = threading.Event()


def shutdown_requested() -> bool:
    """True once the Textual app has exited and the worker should wind down.

    A cooperative worker loop polls this and returns instead of being waited
    out; it is never set under the plain/rich backends.
    """
    return _shutdown.is_set()


def run_textual(menu_loop: Callable[[], None]) -> None:
    """Run ``menu_loop`` on one worker thread under a Textual app.

    Textual owns the main thread; the loop and everything it calls run on the
    worker. When the app exits, ``shutdown_requested()`` flips and the worker
    is joined (up to ``WORKER_JOIN_TIMEOUT``) so a file it is mid-way through
    writing is not cut off; only then is anything the loop raised (including
    SystemExit from ``quit_hc``) re-raised here on the main thread.
    """
    from hate_crack.ui.app import HateCrackApp
    from hate_crack.ui.textual_ui import TextualUI

    ui = get_ui()
    if not isinstance(ui, TextualUI):
        raise RuntimeError("run_textual requires the textual backend to be installed")
    outcome: list[BaseException] = []
    _shutdown.clear()

    def work() -> None:
        try:
            menu_loop()
        except BaseException as exc:
            outcome.append(exc)
        finally:
            with contextlib.suppress(Exception):
                app.call_from_thread(app.exit)

    worker = threading.Thread(target=work, name="hate_crack-menu", daemon=True)
    app = HateCrackApp(on_ready=worker.start)
    ui.bind(app)
    try:
        try:
            app.run()
        finally:
            _shutdown.set()
        if worker.is_alive():
            worker.join(_WORKER_JOIN_QUIET)
        if worker.is_alive():
            ui.warn("[*] Waiting for background work to finish...")
            worker.join(WORKER_JOIN_TIMEOUT - _WORKER_JOIN_QUIET)
        if worker.is_alive():
            ui.error(
                "[!] Background work did not finish within "
                f"{WORKER_JOIN_TIMEOUT:.0f}s; a file it was writing may be "
                "incomplete."
            )
    finally:
        ui._app = None
    if outcome:
        raise outcome[0]


_ui: UI | None = None


def get_ui() -> UI:
    """Return the process-wide UI, lazily constructing a PlainUI."""
    global _ui
    if _ui is None:
        _ui = PlainUI()
    return _ui


def set_ui(ui: UI) -> None:
    global _ui
    _ui = ui


def reset_ui() -> None:
    global _ui
    _ui = None


__all__ = [
    "BACKENDS",
    "PlainUI",
    "TerminalUnavailable",
    "UI",
    "build_ui",
    "get_ui",
    "readline_supported",
    "reset_ui",
    "run_textual",
    "shutdown_requested",
    "resolve_backend_name",
    "set_ui",
]
