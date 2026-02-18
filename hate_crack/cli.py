import logging
import os
import sys
from typing import Optional


def resolve_path(value: Optional[str]) -> Optional[str]:
    """Expand user and return an absolute path, or None."""
    if not value:
        return None
    return os.path.abspath(os.path.expanduser(value))


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
    debug_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    urllib3_logger = logging.getLogger("urllib3")
    urllib3_logger.setLevel(logging.DEBUG)
    urllib3_logger.addHandler(debug_handler)
