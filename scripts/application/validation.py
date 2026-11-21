"""Independent constraints for application image, identities, endpoints and private mounts."""

import json
from pathlib import Path
from typing import Any

from cve_common.deployment import APPLICATION_IMAGE, PORTS

ROLE_SETTINGS = {
    "cve-event-dispatcher": ("CVE_DISPATCHER_", "event_dispatcher"),
    "cve-inventory": ("CVE_INVENTORY_", "inventory_processor"),
    "cve-matcher": ("CVE_MATCHER_", "matcher"),
    "cve-findings": ("CVE_FINDINGS_", "findings_writer"),
    "cve-notification": ("CVE_NOTIFICATION_", "notification"),
    "cve-importer": ("CVE_IMPORTER_", "importer"),
    "cve-enricher": ("CVE_ENRICHER_", "enricher"),
    "cve-automation": ("CVE_ANSIBLE_", "ansible_worker"),
}


def validate(
    model: dict[str, Any],
    root: Path,
    *,
    mount_base: Path | None = None,
    secrets_base: Path | None = None,
) -> list[str]:
    mount_base = mount_base or root / ".runtime"
    secrets_base = secrets_base or root / ".runtime"
    contract = json.loads((root / "infrastructure/application/profiles.json").read_text())
    errors = []
    for name in ["cve-processing", "cve-sources"]:
        item = model["services"][name]
        spec = contract[name]
        networks = {
            "cve_data",
            "cve_internal" if name == "cve-processing" else "cve_ssh",
        }
        if name == "cve-processing":
            networks.add("cve_outbound")
        if (
            set(item.get("networks", {})) != networks
            or item.get("ports")
            or item.get("privileged")
            or item.get("network_mode")
            or item.get("container_name")
            or item.get("cap_add")
            or not item.get("read_only")
            or item.get("cap_drop") != ["ALL"]
            or item.get("user", "0").split(":")[0] in {"0", "root"}
            or item.get("image") != APPLICATION_IMAGE
            or item.get("entrypoint")
            or item.get("build")
            or not all(
                item.get(k) for k in ["healthcheck", "mem_limit", "cpus", "pids_limit", "ulimits"]
            )
        ):
            errors.append(
                name + ": bounded unprivileged application group and exact network zones required"
            )
        env = item.get("environment", {})
        if set(env) != set(spec["environment_keys"]) or env.get(
            "CVE_APPLICATION_PROFILE"
        ) != name.removeprefix("cve-"):
            errors.append(name + ": explicit profile environment required")
        for role in spec["roles"]:
            prefix, database = ROLE_SETTINGS[role]
            if (
                env.get(prefix + "DATABASE__HOST") != "cve-postgres"
                or env.get(prefix + "DATABASE__USERNAME") != database
                or env.get(prefix + "HTTP_PORT") != str(PORTS[role])
            ):
                errors.append(role + ": dedicated database identity and unique HTTP port required")
        if name == "cve-processing":
            try:
                processes = int(env.get("CVE_ENRICHER_PROCESSES", "0"))
                concurrency = int(env.get("CVE_ENRICHER_CONCURRENCY", "0"))
                pool = int(env.get("CVE_ENRICHER_DATABASE__POOL_SIZE", "0"))
                if not (
                    1 <= processes <= 2
                    and 1 <= concurrency <= 4
                    and concurrency + 2 <= pool <= 8
                    and processes * pool <= 16
                ):
                    raise ValueError("Unbounded process/pool budget")
            except (TypeError, ValueError):
                errors.append(name + ": bounded enrichment processes and heartbeat pool required")
        if name == "cve-processing":
            try:
                processes = int(env.get("CVE_MATCHER_PROCESSES", "0"))
                concurrency = int(env.get("CVE_MATCHER_CONCURRENCY", "0"))
                pool = int(env.get("CVE_MATCHER_DATABASE__POOL_SIZE", "0"))
                if not (
                    1 <= processes <= 2
                    and 1 <= concurrency <= 4
                    and concurrency < pool <= 5
                    and processes * pool <= 10
                ):
                    raise ValueError("Unbounded matcher process/pool budget")
            except (TypeError, ValueError):
                errors.append(name + ": bounded matcher processes and heartbeat pool required")
        if any("PASSWORD" in k and not k.endswith("_FILE") for k in env):
            errors.append(name + ": inline credentials forbidden")
        expected = {}
        for mount in spec["mounts"]:
            if not isinstance(mount, dict):
                raise ValueError("Explicit private bind mount contract required")
            source = mount["source"].replace(
                "${COMPOSE_PROJECT_NAME:-cve-monitoring}", str(model["name"])
            )
            source = source.replace("${MOUNT_BASE:-./.runtime}", str(mount_base))
            source = source.replace("${SECRETS_BASE:-./.runtime}", str(secrets_base))
            expected[mount["target"]] = (str((root / source).resolve()), mount["read_only"])
        actual = {
            m.get("target"): (m.get("source"), bool(m.get("read_only")))
            for m in item.get("volumes", [])
        }
        if actual != expected or any(
            m.get("type") != "bind" or m.get("bind", {}).get("create_host_path")
            for m in item.get("volumes", [])
        ):
            errors.append(
                name
                + ": only declared private configurations, gate and separate scratch mounts allowed"
            )
        if item.get("healthcheck", {}).get("test") != [
            "CMD",
            "python",
            "-m",
            "cve_common.application",
            "health",
        ]:
            errors.append(name + ": aggregate child and readiness healthcheck required")
    return errors
