"""Compare the seven running development services to the scanned immutable artifacts."""

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from scripts.hardening import supply_chain
from scripts.infrastructure.manage import compose, docker_command, load_config, resolved, run


def verify() -> dict[str, Any]:
    cfg = load_config()
    inventory_path = supply_chain.REPORTS / "image-inventory.json"
    inventory = json.loads(inventory_path.read_text())
    model = resolved(cfg)["services"]
    if len(inventory) != 7 or {v["service"] for v in inventory} != set(model):
        raise ValueError("Complete seven-service scan inventory required")
    services = []
    for item in inventory:
        name = item["service"]
        if model[name]["image"] != item["reference"]:
            raise ValueError("Compose reference changed since scan: " + name)
        container = compose(cfg, ["ps", "-q", name]).stdout.strip()
        if not container or "\n" in container:
            raise ValueError("Exactly one running container required: " + name)
        # Select only identities and health; never inspect credential environments.
        fields = json.loads(
            run(
                [
                    *docker_command(),
                    "inspect",
                    "--format",
                    "[{{json .Image}},{{json .State.Health.Status}}]",
                    container,
                ]
            ).stdout
        )
        identity = run(
            [*docker_command(), "image", "inspect", "--format", "{{.Id}}", item["reference"]]
        ).stdout.strip()
        if (
            fields[0] not in [item["image_id"], *item["config_digests"]]
            or fields[1] != "healthy"
            or identity != item["image_id"]
        ):
            raise ValueError("Running image differs from healthy scanned artifact: " + name)
        services.append({"service": name, "image_digest": fields[0], "healthy": True})
    result = {
        "checked_at": datetime.now(UTC).isoformat(),
        "inventory_sha256": hashlib.sha256(inventory_path.read_bytes()).hexdigest(),
        "input_hashes": supply_chain.input_hashes(),
        "verified_services": services,
        "all_scanned_artifacts_running": True,
    }
    target = cfg.root / ".runtime/test-reports/phase-23-artifact-verification.json"
    target.write_text(json.dumps(result, indent=2))
    target.chmod(0o600)
    return result


if __name__ == "__main__":
    print(json.dumps(verify()))
