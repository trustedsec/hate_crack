"""UI abstraction seam: a Protocol, the plain backend, and backend resolution."""

from __future__ import annotations

from contextlib import AbstractContextManager
from typing import Any, Protocol

from hate_crack.ui.plain import PlainUI

BACKENDS = ("plain", "rich")  # "textual" joins this in Phase 3


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

    def suspend(self) -> AbstractContextManager[None]: ...


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
    return PlainUI()


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
    "UI",
    "build_ui",
    "get_ui",
    "reset_ui",
    "resolve_backend_name",
    "set_ui",
]
