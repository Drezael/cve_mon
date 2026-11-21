#!/usr/bin/env python3
"""Kompatibler CLI-Einstieg in die gemeinsame Egress-Policyprüfung."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.infrastructure.envoy import main

if __name__ == "__main__":
    sys.argv.insert(1, "policy-check")
    raise SystemExit(main())
