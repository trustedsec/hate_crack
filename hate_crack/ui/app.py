"""The Textual app shell: content log, prompt input, status bar, footer.

Textual owns the main thread's event loop. hate_crack's synchronous logic runs
on ONE worker thread (see ``run_textual`` in ``hate_crack.ui``) and reaches this
app only through ``App.call_from_thread``. Everything here that touches a widget
runs on the main thread.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any, TypeVar

from rich.text import Text
from textual.app import App, ComposeResult, SuspendNotSupported
from textual.binding import Binding
from textual.widgets import Footer, Input, RichLog, Static

T = TypeVar("T")


class _Prompt:
    """One outstanding prompt: the worker blocks on ``event`` for ``value``."""

    def __init__(self) -> None:
        self.event = threading.Event()
        self.value: str | None = None  # None means cancelled


class HateCrackApp(App[None]):
    CSS = """
    #content { height: 1fr; }
    #status { height: 1; dock: bottom; background: $boost; padding: 0 1; }
    #answer { dock: bottom; display: none; }
    #answer.active { display: block; }
    """

    BINDINGS = [
        Binding("escape", "cancel_prompt", "Cancel", show=True),
        Binding("ctrl+q", "quit", "Quit", show=True),
        Binding("up", "move_choice(-1)", "Prev", show=False),
        Binding("down", "move_choice(1)", "Next", show=False),
    ]

    def __init__(self, on_ready: Callable[[], None] | None = None) -> None:
        super().__init__()
        self._on_ready = on_ready
        self._prompt: _Prompt | None = None
        self._status: dict[str, Any] = {}
        # (key, label) pairs while a menu prompt is open; Up/Down walk them.
        self._choices: list[tuple[str, str]] = []
        self._choice_index: int | None = None
        self.ui_thread: int | None = None

    def compose(self) -> ComposeResult:
        yield RichLog(id="content", markup=False, highlight=False, wrap=True)
        yield Input(id="answer")
        yield Static("", id="status")
        yield Footer()

    def on_mount(self) -> None:
        self.ui_thread = threading.get_ident()
        self._render_status()
        if self._on_ready is not None:
            self._on_ready()

    # -- content -----------------------------------------------------------

    def append(self, text: str | Text, style: str | None = None) -> None:
        log = self.query_one("#content", RichLog)
        if isinstance(text, str):
            text = Text(text, style=style or "")
        log.write(text)

    # -- status bar --------------------------------------------------------

    def set_status(self, **fields: Any) -> None:
        self._status.update(fields)
        self._render_status()

    def _render_status(self) -> None:
        parts: list[str] = []
        s = self._status
        if s.get("hash_file"):
            parts.append(f"file: {s['hash_file']}")
        if s.get("hash_type"):
            parts.append(f"type: {s['hash_type']}")
        if s.get("cracked") is not None and s.get("total") is not None:
            parts.append(f"cracked: {s['cracked']}/{s['total']}")
        self.query_one("#status", Static).update("  |  ".join(parts) or "hate_crack")

    # -- prompts -----------------------------------------------------------

    def begin_prompt(
        self,
        text: str,
        prompt: _Prompt,
        choices: list[tuple[str, str]] | None = None,
    ) -> None:
        """Main thread: show the input for ``prompt`` and focus it.

        ``choices`` makes it a menu prompt: the operator may type a key or walk
        the list with Up/Down, which fills the input with that key.
        """
        self._release_prompt()
        self._prompt = prompt
        self._choices = list(choices or [])
        self._choice_index = None
        box = self.query_one("#answer", Input)
        box.value = ""
        box.border_subtitle = "Up/Down or type a number, Enter" if choices else ""
        box.placeholder = text.strip()
        box.add_class("active")
        if text.strip():
            self.append(text.rstrip(), style="bold")
        box.focus()

    def _release_prompt(self, value: str | None = None) -> None:
        prompt, self._prompt = self._prompt, None
        box = self.query_one("#answer", Input)
        box.remove_class("active")
        box.value = ""
        box.border_subtitle = ""
        self._choices = []
        self._choice_index = None
        if prompt is not None:
            prompt.value = value
            prompt.event.set()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        if self._prompt is not None:
            self.append(f"> {event.value}", style="dim")
            self._release_prompt(event.value)

    def action_move_choice(self, delta: int) -> None:
        if self._prompt is None or not self._choices:
            return
        n = len(self._choices)
        if self._choice_index is None:
            idx = 0 if delta > 0 else n - 1
        else:
            idx = (self._choice_index + delta) % n
        self._choice_index = idx
        key, label = self._choices[idx]
        box = self.query_one("#answer", Input)
        box.value = key
        box.cursor_position = len(key)
        box.border_subtitle = f"{key}) {label}"

    def action_cancel_prompt(self) -> None:
        if self._prompt is not None:
            self.append("(cancelled)", style="dim")
            self._release_prompt(None)

    # -- terminal handoff --------------------------------------------------

    def _run_terminal_main(self, fn: Callable[[], T]) -> tuple[str, Any]:
        """Run ``fn`` on the main thread with the app suspended.

        An exception must NOT escape this callable: letting it propagate out of
        ``call_from_thread`` reaches the worker and still kills the app. It is
        returned as a marker and re-raised on the worker side instead.
        """
        try:
            with self.suspend():
                return ("ok", fn())
        except SuspendNotSupported as exc:
            # Raised on entering suspend(), so ``fn`` never ran.
            return ("unsupported", exc)
        except BaseException as exc:
            return ("raise", exc)

    async def action_quit(self) -> None:
        # Never leave the worker blocked on a prompt nobody can answer.
        self._release_prompt(None)
        self.exit()

    def on_unmount(self) -> None:
        if self._prompt is not None:
            self._prompt.value = None
            self._prompt.event.set()
