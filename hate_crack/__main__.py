#!/usr/bin/env python3
import sys

from .hate_crack import cli_main


def main() -> int:
    return cli_main() or 0


if __name__ == "__main__":
    sys.exit(main())
