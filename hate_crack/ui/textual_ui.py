"""TextualUI: the UI protocol bridged to a running Textual app.

Textual runs on the MAIN thread; hate_crack's logic runs on one worker thread.
Every method here is called from that worker and marshals to the app with
``App.call_from_thread``. Before an app is bound the backend behaves like
PlainUI, so output emitted during startup still appears.
"""

from __future__ import annotations

import contextlib
import threading
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager
from typing import TYPE_CHECKING, Any, TypeVar

from rich.text import Text

from hate_crack import formatting
from hate_crack.ui.plain import PlainUI
from hate_crack.ui.rich_ui import _rich_style

if TYPE_CHECKING:
    from hate_crack.ui.app import HateCrackApp

T = TypeVar("T")


class _Handle:
    def __init__(self) -> None:
        self.detail = ""

    def set_detail(self, detail: str) -> None:
        self.detail = detail


class TextualUI:
    def __init__(self) -> None:
        self._app: HateCrackApp | None = None
        self._plain = PlainUI()

    def bind(self, app: HateCrackApp) -> None:
        self._app = app

    # -- plumbing ----------------------------------------------------------

    def _on_app_thread(self, app: HateCrackApp) -> bool:
        return app.ui_thread == threading.get_ident()

    def _post(self, fn: Callable[[], Any]) -> Any:
        app = self._app
        assert app is not None
        if self._on_app_thread(app):
            return fn()
        return app.call_from_thread(fn)

    def _line(self, text: str, style: str | None) -> None:
        app = self._app
        if app is None:
            self._plain.say(text)
            return
        self._post(lambda: app.append(text, _rich_style(style)))

    def _ask(self, prompt: str) -> str | None:
        """Block the worker until the operator submits; None means cancelled."""
        from hate_crack.ui.app import _Prompt

        app = self._app
        assert app is not None
        pending = _Prompt()
        self._post(lambda: app.begin_prompt(prompt, pending))
        pending.event.wait()
        return pending.value

    def set_status(self, **fields: Any) -> None:
        app = self._app
        if app is not None:
            self._post(lambda: app.set_status(**fields))

    # -- output ------------------------------------------------------------

    def say(self, text: str = "", *, style: str | None = None) -> None:
        self._line(text, style)

    def warn(self, text: str) -> None:
        self._line(text, "yellow")

    def error(self, text: str) -> None:
        self._line(text, "bold red")

    def success(self, text: str) -> None:
        self._line(text, "green")

    # -- input -------------------------------------------------------------

    def ask(self, prompt: str = "", *, default: str = "") -> str:
        if self._app is None:
            return self._plain.ask(prompt, default=default)
        answer = self._ask(prompt)
        if answer is None:
            return ""
        return answer or default

    def ask_int(
        self,
        prompt: str,
        *,
        default: int | None = None,
        minimum: int | None = None,
    ) -> int | None:
        if self._app is None:
            return self._plain.ask_int(prompt, default=default, minimum=minimum)
        while True:
            answer = self._ask(prompt)
            if answer is None:
                return None
            answer = answer.strip()
            if not answer:
                if default is not None:
                    return default
                self.warn("Please enter a number.")
                continue
            try:
                value = int(answer)
            except ValueError:
                self.warn("Please enter a whole number.")
                continue
            if minimum is not None and value < minimum:
                self.warn(f"Value must be at least {minimum}.")
                continue
            return value

    def confirm(self, prompt: str, *, default: bool = True) -> bool:
        if self._app is None:
            return self._plain.confirm(prompt, default=default)
        while True:
            answer = self._ask(prompt)
            if answer is None:
                return default
            answer = answer.strip().lower()
            if not answer:
                return default
            if answer in ("y", "yes"):
                return True
            if answer in ("n", "no"):
                return False

    def select(
        self,
        items: list[tuple[str, str]],
        *,
        title: str | None = None,
        prompt: str = "\nSelect a task: ",
    ) -> str | None:
        if self._app is None:
            return self._plain.select(items, title=title, prompt=prompt)
        if title:
            self.say(title)
        for key, label in items:
            self.say(f"  {key}) {label}")
        keys = {key for key, _ in items}
        while True:
            answer = self._ask(prompt)
            if answer is None:
                return None
            answer = answer.strip()
            if not answer:
                return None
            if answer in keys:
                return answer
            self.warn(f"'{answer}' is not one of the options.")

    # -- layout ------------------------------------------------------------

    def columns(
        self,
        title: str | None,
        entries: list[str],
        *,
        min_col_width: int = 20,
        max_col_width: int | None = None,
        styles: list[str | None] | None = None,
    ) -> None:
        if self._app is None:
            self._plain.columns(
                title,
                entries,
                min_col_width=min_col_width,
                max_col_width=max_col_width,
                styles=styles,
            )
            return
        if not entries:
            if title:
                self.say(f"\n{title}:\n  (none)")
            return
        width = formatting._terminal_width()
        if max_col_width is None:
            max_col_width = max(len(e) for e in entries) + 2
        col_width = max(min_col_width, min(max_col_width, width))
        num_cols = max(1, width // col_width)
        rows = (len(entries) + num_cols - 1) // num_cols
        if title:
            self.say("")
            self.say("=" * width)
            self.say(title)
            self.say("=" * width)
        for row in range(rows):
            line = Text()
            for col in range(num_cols):
                idx = row + col * rows  # column-major: down a column
                if idx < len(entries):
                    style = styles[idx] if styles and idx < len(styles) else None
                    cell = entries[idx][:col_width].ljust(col_width)
                    line.append(cell, style=_rich_style(style) or "")
            app = self._app
            self._post(lambda line=line: app.append(line))
        if title:
            self.say("=" * width)

    @contextlib.contextmanager
    def _spinner(self, message: str) -> Iterator[_Handle]:
        self.say(message)
        yield _Handle()

    def spinner(self, message: str) -> AbstractContextManager[Any]:
        if self._app is None:
            return self._plain.spinner(message)
        return self._spinner(message)

    # -- terminal ----------------------------------------------------------

    def run_terminal(self, fn: Callable[[], T]) -> T:
        """Run ``fn`` on the MAIN thread with the app suspended.

        A terminal-owning subprocess must be awaited on the main thread, or
        Ctrl-C (delivered only there) kills the app. The callable returns a
        marker rather than raising, because an exception escaping
        ``call_from_thread`` reaches the worker AND still kills the app.
        """
        app = self._app
        if app is None:
            return fn()
        kind, payload = app.call_from_thread(app._run_terminal_main, fn)
        if kind == "raise":
            raise payload
        return payload
