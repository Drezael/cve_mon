"""Outbound-only Ansible bridge. n8n owns due times; the controller executes fixed local plans."""

import argparse
import contextlib
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any
from uuid import UUID


def request(config: dict[str, Any], action: str, value: dict[str, Any]) -> Any:
    from scripts.ansible.submit import request as internal_request

    return internal_request(
        config, "/api/v1/inventories/collection/" + action, json.dumps(value).encode()
    )["result"]


def execute(config: dict[str, Any], alias: str) -> str:
    """Use only this repository's fixed collector and internal upload implementation."""
    from cve_automation.inventory_adapter import encode

    from scripts.ansible.manage import collect
    from scripts.ansible.submit import submit

    plan = config["targets"].get(alias)
    if not plan:
        raise ValueError("Unregistered local collection alias")
    document = collect(Path(plan["connection_file"]))
    result = submit(config, encode(document))
    return str(UUID(result["submission_id"]))


def poll(config: dict[str, Any]) -> bool:
    job = request(config, "claim", {})
    if not job:
        return False
    submission = None
    with contextlib.suppress(ValueError, OSError, subprocess.SubprocessError):
        submission = execute(config, job["alias"])
    request(
        config,
        "finish",
        {
            "request_id": job["request_id"],
            "lease_token": job["lease_token"],
            "submission_id": submission,
        },
    )
    return True


def load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
        raise ValueError("Owner-only collector configuration required")
    config: dict[str, Any] = json.loads(path.read_text())
    if not config.get("targets") or any(
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", a) for a in config["targets"]
    ):
        raise ValueError("Explicit local target aliases required")
    return config


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--register", action="store_true")
    parser.add_argument("--request-now", action="store_true")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    config = load(args.config)
    if args.register:
        for alias, plan in config["targets"].items():
            request(
                config,
                "targets",
                {
                    "alias": alias,
                    "interval_seconds": plan.get("interval_seconds", 21600),
                    "enabled": plan.get("enabled", True),
                    "request_now": args.request_now,
                },
            )
    while True:
        try:
            poll(config)
        except (ValueError, OSError):
            print("collector_bridge_unavailable", flush=True)
        if args.once:
            return
        time.sleep(30)


if __name__ == "__main__":
    main()
