import logging
import os
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
    if not any(isinstance(h, logging.FileHandler) for h in logger.handlers):
        log_path = os.path.join(hate_path, "hate_crack.log")
        file_handler = logging.FileHandler(log_path)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        )
        logger.addHandler(file_handler)
