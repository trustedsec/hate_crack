#!/usr/bin/env python3
import sys

from .main import main as _main


def main() -> int:
    return _main() or 0


if __name__ == "__main__":
    sys.exit(main())
