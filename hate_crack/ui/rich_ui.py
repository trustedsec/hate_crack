"""RichUI: the Rich-backed implementation of the UI protocol.

``cli.prompt_int`` and ``menu.interactive_menu`` are reached through their
module objects at call time (same as PlainUI), and ``highlight=False`` is
passed on every print so Rich never recolours hashes, paths or numbers.
"""

from __future__ import annotations

import contextlib
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager
from typing import Any, TypeVar

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text

from hate_crack import cli, formatting, menu

T = TypeVar("T")


class _RichSpinnerHandle:
    """Same ``set_detail`` surface as ``progress.SpinnerHandle``."""

    def __init__(self) -> None:
        self.detail = ""

    def set_detail(self, detail: str) -> None:
        self.detail = detail


class _Elapsed:
    """Rich renderable: message, optional detail, elapsed seconds."""

    def __init__(self, message: str, handle: _RichSpinnerHandle) -> None:
        self.message = message
        self.handle = handle
        self.start = time.monotonic()

    def __rich__(self) -> Text:
        detail = f"  {self.handle.detail}" if self.handle.detail else ""
        return Text(f"{self.message}{detail}  {int(time.monotonic() - self.start)}s")


class RichUI:
    def __init__(
        self, console: Console | None = None, err_console: Console | None = None
    ) -> None:
        self.console = console if console is not None else Console()
        self.err_console = (
            err_console if err_console is not None else Console(stderr=True)
        )

    def say(self, text: str = "", *, style: str | None = None) -> None:
        self.console.print(
            text, style=style, highlight=False, markup=False, soft_wrap=True
        )

    def warn(self, text: str) -> None:
        self.console.print(
            text, style="yellow", highlight=False, markup=False, soft_wrap=True
        )

    def error(self, text: str) -> None:
        self.err_console.print(
            text, style="bold red", highlight=False, markup=False, soft_wrap=True
        )

    def success(self, text: str) -> None:
        self.console.print(
            text, style="green", highlight=False, markup=False, soft_wrap=True
        )

    def ask(self, prompt: str = "", *, default: str = "") -> str:
        # Not rich.prompt: it strips whitespace, appends its own ": " suffix and
        # interprets markup. Behaviour must match PlainUI exactly, so render the
        # prompt through the console and read with input().
        self.console.print(prompt, end="", markup=False, highlight=False)
        return input() or default

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
            self.console.print(prompt, end="", markup=False, highlight=False)
            try:
                answer = input().strip().lower()
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
        # Same fallback chain as PlainUI (tty, COLUMNS, then 120) so both
        # backends lay out the same columns; Rich's own default is 80.
        width = formatting._terminal_width()
        if not entries:
            if title:
                self.console.print(
                    f"\n{title}:\n  (none)", markup=False, highlight=False
                )
            return
        if max_col_width is None:
            max_col_width = max(len(e) for e in entries) + 2
        col_width = max(min_col_width, min(max_col_width, width))
        num_cols = max(1, width // col_width)
        rows = (len(entries) + num_cols - 1) // num_cols

        # Render the whole block (rules, title, table) at the width the columns
        # were laid out for: print(width=) is capped at the console's own width,
        # which may be Rich's 80 default. Rich has no public way to unset it.
        saved = self.console._width
        self.console.width = width
        try:
            if title:
                self.console.print("")
                self.console.rule(style="none", characters="=")
                self.console.print(title, markup=False, highlight=False)
                self.console.rule(style="none", characters="=")

            table = Table.grid(padding=0)
            for _ in range(num_cols):
                table.add_column(width=col_width, no_wrap=True, overflow="ellipsis")
            for row in range(rows):
                cells: list[Text] = []
                for col in range(num_cols):
                    idx = row + col * rows  # column-major: down a column
                    if idx < len(entries):
                        style = styles[idx] if styles and idx < len(styles) else None
                        cells.append(Text(entries[idx], style=_rich_style(style) or ""))
                    else:
                        cells.append(Text(""))
                table.add_row(*cells)
            self.console.print(table, highlight=False)

            if title:
                self.console.rule(style="none", characters="=")
        finally:
            self.console._width = saved

    def spinner(self, message: str) -> AbstractContextManager[Any]:
        return self._spinner(message)

    @contextlib.contextmanager
    def _spinner(self, message: str) -> Iterator[_RichSpinnerHandle]:
        handle = _RichSpinnerHandle()
        if not sys.stdout.isatty():
            self.console.print(message, markup=False, highlight=False)
            yield handle
            return
        live = Live(
            _Elapsed(message, handle),
            console=self.console,
            transient=True,
            refresh_per_second=8,
        )
        with live:
            yield handle

    def run_terminal(self, fn: Callable[[], T]) -> T:
        return fn()


def _rich_style(style: str | None) -> str | None:
    """Callers pass raw ANSI prefixes (e.g. "\\033[31m"); map the common ones."""
    if not style:
        return None
    if "\033[" not in style:
        return style
    codes = style.replace("\033[", "").rstrip("m").split(";")
    names = {
        "1": "bold", "30": "black", "31": "red", "32": "green", "33": "yellow",
        "34": "blue", "35": "magenta", "36": "cyan", "37": "white",
        "90": "bright_black",
    }  # fmt: skip
    mapped = [names[c] for c in codes if c in names]
    return " ".join(mapped) or None
