"""Permite `python -m sast_sentinel` além do console script `sast-sentinel`."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
