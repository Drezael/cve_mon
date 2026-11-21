"""Explicit authentication operator entry point; no secret arguments."""

import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.security.manage import main

if __name__ == "__main__":
    sys.argv.insert(1, "status")
    raise SystemExit(main())
