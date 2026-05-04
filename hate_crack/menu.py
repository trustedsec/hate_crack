"""Reusable interactive menu with optional arrow-key navigation.

Default: classic numbered ``print()`` + ``input()`` selection (full number
entry for all keys).

Set ``HATE_CRACK_ARROW_MENU=1`` to enable arrow-key navigation via
``simple-term-menu`` (single-digit shortcut keys only; 10+ require arrows).
"""

from __future__ import annotations

import os
import sys

try:
    from simple_term_menu import TerminalMenu

    _HAS_TERM_MENU = True
except ImportError:
    _HAS_TERM_MENU = False


def _use_arrow_menu() -> bool:
    if os.environ.get("HATE_CRACK_ARROW_MENU", "") != "1":
        return False
    if not _HAS_TERM_MENU:
        return False
    if not sys.stdout.isatty():
        return False
    return True


def _arrow_menu(
    items: list[tuple[str, str]],
    title: str | None,
) -> str | None:
    w = max(len(key) for key, _ in items)
    menu_entries = [f"[{key:>{w}}] {label}" for key, label in items]
    shortcuts = [key for key, _ in items]

    menu = TerminalMenu(menu_entries, title=title)
    idx = menu.show()
    if idx is None:
        return None
    return shortcuts[idx]


def _numbered_menu(
    items: list[tuple[str, str]],
    prompt: str,
) -> str | None:
    w = max(len(key) for key, _ in items)
    for key, label in items:
        print(f"\t[{key:>{w}}] {label}")
    choice = input(prompt).strip()
    if not choice:
        return None
    return choice


def interactive_menu(
    items: list[tuple[str, str]],
    title: str | None = None,
    prompt: str = "\nSelect a task: ",
) -> str | None:
    """Display *items* as a menu and return the selected key string.

    Parameters
    ----------
    items:
        Ordered ``(key, label)`` pairs.  *key* is the string returned on
        selection (e.g. ``"1"``, ``"99"``).
    title:
        Optional heading printed above the menu (arrow-key mode) or
        ignored (numbered mode, where callers print their own headers).
    prompt:
        Input prompt shown in numbered-menu mode.

    Returns
    -------
    str | None
        The *key* of the selected item, or ``None`` on Escape / cancel.
    """
    if _use_arrow_menu():
        return _arrow_menu(items, title)
    return _numbered_menu(items, prompt)
