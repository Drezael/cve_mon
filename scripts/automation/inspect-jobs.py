"""Bounded administrative metadata inspection; no arbitrary SQL or payload output."""

import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.automation.manage import main

if __name__ == "__main__":
    sys.argv.insert(1, "jobs")
    raise SystemExit(main())
