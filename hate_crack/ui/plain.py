"""PlainUI: today's terminal behaviour, reached through the UI protocol.

Every delegate is resolved at call time through its module object, never bound
at import time, so ``monkeypatch.setattr(hate_crack.menu, "interactive_menu",
...)`` and similar module-attribute patches keep landing.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Any, TypeVar

from hate_crack import cli, formatting, menu, progress

T = TypeVar("T")


class PlainUI:
    supports_readline = True

    def say(self, text: str = "", *, style: str | None = None) -> None:
        print(text)

    def warn(self, text: str) -> None:
        print(text)

    def error(self, text: str) -> None:
        print(text)

    def success(self, text: str) -> None:
        print(text)

    def ask(
        self,
        prompt: str = "",
        *,
        default: str = "",
        choices: list[tuple[str, str]] | None = None,
    ) -> str:
        return input(prompt) or default

    def ask_int(
        self,
        prompt: str,
        *,
        default: int | None = None,
        minimum: int | None = None,
    ) -> int | None:
        return cli.prompt_int(prompt, default=default, minimum=minimum)

    def confirm(self, prompt: str, *, default: bool = True) -> bool:
        while True:
            try:
                answer = input(prompt).strip().lower()
            except EOFError:
                return default
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
        return menu.interactive_menu(items, title=title, prompt=prompt)

    def columns(
        self,
        title: str | None,
        entries: list[str],
        *,
        min_col_width: int = 20,
        max_col_width: int | None = None,
        styles: list[str | None] | None = None,
    ) -> None:
        formatting.print_multicolumn_list(
            title,
            entries,
            min_col_width=min_col_width,
            max_col_width=max_col_width,
            styles=styles,
        )

    def spinner(self, message: str) -> AbstractContextManager[Any]:
        return progress.spinner(message)

    def run_terminal(self, fn: Callable[[], T]) -> T:
        return fn()
