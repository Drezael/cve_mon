"""Verify the current migration head and the dedicated status probe interface."""

import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.database import manage as db
from scripts.infrastructure.manage import load_config

if __name__ == "__main__":
    config = load_config()
    print(db.verify(config))
    with db.connect(config, "status_probe") as connection:
        assert connection.execute("SELECT automation.runtime_metrics()").fetchone()
