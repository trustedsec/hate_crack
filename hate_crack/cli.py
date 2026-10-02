import logging
import os
import readline
import sys
from typing import Optional

# Space, tab and semicolon split one path token from the next.
#
# Deliberately NOT including "\n": libedit on macOS mistracks the cursor when
# newline is a completer delimiter and the prompt contains an embedded newline
# (26+ input locations here do), which breaks backspace during completion.
# See https://github.com/python/cpython/issues/117447
COMPLETER_DELIMS = " \t;"


def using_libedit() -> bool:
    """True when Python's readline is backed by libedit rather than GNU readline.

    macOS ships libedit, which needs a different key-binding syntax. ``backend``
    exists on 3.13+; the docstring sniff is the historical fallback.
    """
    backend = getattr(readline, "backend", None)
    if backend is not None:
        return backend == "editline"
    return "libedit" in (readline.__doc__ or "")


def configure_completion(completer, display_matches_hook=None) -> None:
    """Install *completer* and bind Tab to it.

    The two backends need different bind syntax and the wrong one is silently
    ignored, so pick by backend rather than firing both and hoping: an
    unbound Tab inserts a literal tab instead of completing, which looks like
    "tab completion is broken" with nothing logged.
    """
    readline.set_completer_delims(COMPLETER_DELIMS)
    libedit = using_libedit()
    if libedit:
        bind = "bind ^I rl_complete"
    else:
        bind = "tab: complete"
        # GNU readline only -- libedit has no "set" command, and asking it
        # anyway is how the old code ended up swallowing every bind error.
        # Suppresses "Display all 312 possibilities?" -- callers print their
        # own listings.
        readline.parse_and_bind("set completion-query-items -1")
    if display_matches_hook is not None and hasattr(
        readline, "set_completion_display_matches_hook"
    ):
        readline.set_completion_display_matches_hook(display_matches_hook)
    readline.parse_and_bind(bind)
    readline.set_completer(completer)


def orig_cwd() -> str:
    """Return the caller's original working directory.

    When invoked via the bash shim (``uv run --directory``), the process CWD
    is the install directory, not where the user ran the command.
    ``HATE_CRACK_ORIG_CWD`` preserves the real CWD so that output files
    (e.g. ``.out``, ``.nt``) are created next to the hashfile the user specified.
    """
    return os.environ.get("HATE_CRACK_ORIG_CWD") or os.getcwd()


def resolve_path(value: Optional[str]) -> Optional[str]:
    """Expand user and return an absolute path, or None.

    When invoked via the bash shim (``uv run --directory``), the working
    directory is changed to the repo root before Python starts.
    ``HATE_CRACK_ORIG_CWD`` preserves the caller's real working directory
    so that relative paths on the command line resolve correctly.
    """
    if not value:
        return None
    value = os.path.expanduser(value)
    if os.path.isabs(value):
        return value
    orig_cwd = os.environ.get("HATE_CRACK_ORIG_CWD")
    if orig_cwd:
        return os.path.normpath(os.path.join(orig_cwd, value))
    return os.path.abspath(value)


def add_common_args(parser) -> None:
    pass  # All config items are now set via config file only


def setup_logging(logger: logging.Logger, hate_path: str, debug_mode: bool) -> None:
    if not debug_mode:
        return
    logger.setLevel(logging.DEBUG)
    # Debug logs go to stderr by default (no log file side effects).
    has_stream = any(
        isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)
        for h in logger.handlers
    )
    if not has_stream:
        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        )
        logger.addHandler(stream_handler)
    # Show HTTP requests made by the requests/urllib3 library.
    debug_handler = logging.StreamHandler(sys.stderr)
    debug_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    urllib3_logger = logging.getLogger("urllib3")
    urllib3_logger.setLevel(logging.DEBUG)
    urllib3_logger.addHandler(debug_handler)
