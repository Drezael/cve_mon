"""Reuse the existing locked builders; never starts or changes an application deployment."""

import os
import subprocess

from scripts.hardening import supply_chain
from scripts.hardening.runtime_images import build
from scripts.infrastructure.manage import load_config


def run() -> None:
    from scripts.automation import manage as automation
    from scripts.cve_enricher import manage as enricher
    from scripts.cve_findings import manage as findings
    from scripts.cve_importer import manage as importer
    from scripts.cve_matcher import manage as matcher
    from scripts.dashboard.manage import npm
    from scripts.inventory_processor import manage as inventory
    from scripts.notifications import manage as notification

    config = load_config()
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch is None:
        result = subprocess.run(
            ["git", "show", "-s", "--format=%ct", "HEAD"],
            cwd=config.root,
            check=False,
            text=True,
            capture_output=True,
        )
        epoch = result.stdout.strip() if result.returncode == 0 else "315532800"
    if not epoch.isdigit():
        raise ValueError("Numeric SOURCE_DATE_EPOCH required")
    previous = os.environ.get("SOURCE_DATE_EPOCH")
    os.environ["SOURCE_DATE_EPOCH"] = epoch
    try:
        for runtime in [
            "python",
            "postgres",
            "nginx",
            "mail",
            "n8n",
        ]:
            build(config, runtime)
        for module in [automation, inventory, importer, enricher, matcher, findings, notification]:
            module.build(config)
        npm(config.root, "ci", "--ignore-scripts", "--no-audit", "--no-fund")
        npm(config.root, "run", "build")
        supply_chain.dependencies()
        supply_chain.images()
    finally:
        if previous is None:
            os.environ.pop("SOURCE_DATE_EPOCH", None)
        else:
            os.environ["SOURCE_DATE_EPOCH"] = previous
