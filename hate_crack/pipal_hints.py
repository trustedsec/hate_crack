"""Hint words for the PCFG Hints attack, derived from Pipal's baseword report.

``ctx`` is the main module (or a stand-in): ``ctx.pipal()`` returns the top
basewords from the passwords cracked so far, or ``None``/``[]`` when Pipal is
not configured or nothing has cracked.
"""

from typing import Any

from hate_crack.ui import get_ui

__all__ = ["hints_path", "pipal_hint_words"]


def hints_path(hash_file: str) -> str:
    return hash_file + ".hints"


def pipal_hint_words(ctx: Any) -> list[str]:
    """Top Pipal basewords, de-duplicated, saved beside the hash file.

    The ``<hashfile>.hints`` copy is a convenience so the words can be edited
    and fed back in with ``--hintfile``; failing to write it never loses the
    words. Returns ``[]`` when Pipal yields nothing.
    """
    words = list(dict.fromkeys(w for w in (ctx.pipal() or []) if w))
    if not words:
        return []
    path = hints_path(ctx.hcatHashFile)
    try:
        with open(path, "w") as fh:
            fh.write("\n".join(words) + "\n")
    except OSError as exc:
        get_ui().warn(f"[!] Could not save the Pipal hints to {path}: {exc}")
    else:
        get_ui().say(f"[*] Pipal hints saved to {path}")
    return words
