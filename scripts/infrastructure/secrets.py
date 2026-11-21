"""Relocate installation-specific credentials and certificate snapshots without replacing keys."""

import fcntl
import json
from pathlib import Path

from scripts.infrastructure.manage import SECRET_DIRECTORIES, Config, docker_command, run
from scripts.infrastructure.mounts import checked, ensure_directory


def prepare(config: Config) -> None:
    from scripts.deployment.contracts import atomic
    from scripts.infrastructure.storage import helper

    base = config.secrets_base
    checked(base)
    state = config.root / ".runtime/mount-locations"
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (state / (config.project + "-secrets.lock")).open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        marker = state / (config.project + "-secrets.json")
        previous = config.root / ".runtime"
        if marker.exists():
            previous = Path(json.loads(marker.read_text())["secrets_base"])
        if previous == base:
            return
        if run(
            [
                *docker_command(),
                "ps",
                "-q",
                "--filter",
                "label=com.docker.compose.project=" + config.project,
            ]
        ).stdout.strip():
            raise ValueError("Vor Änderung von SECRETS_BASE den bisherigen Stack stoppen")
        ensure_directory(config, base)
        pairs = []
        for name in SECRET_DIRECTORIES:
            pairs.append((previous / name / config.project, config.runtime_directory(name), name))
        pairs += [
            (
                previous / "notifications" / (config.project + "-signing"),
                base / "notifications" / (config.project + "-signing"),
                "notifications",
            ),
            (
                previous / "storage" / config.project / "postgres-tls",
                base / "storage" / config.project / "postgres-tls",
                "postgres-tls",
            ),
            (previous / "development/pki", base / "development/pki", "ingress-pki"),
            (previous / "tls" / config.project, base / "tls" / config.project, "managed-tls"),
            (
                previous / "tls-input" / config.project,
                base / "tls-input" / config.project,
                "tls-input",
            ),
        ]
        for source, target, kind in pairs:
            checked(source)
            checked(target)
            if source == target or not source.exists() or target.exists():
                continue
            # Bootstrap one ancestor at a time, including a root-owned /mnt parent.
            parents = [p for p in reversed(target.parents) if p != base and p.is_relative_to(base)]
            for parent in parents:
                ensure_directory(config, parent)
            staging = target.with_name(".moving-" + target.name)
            checked(staging)
            staging.mkdir(mode=0o700, exist_ok=True)
            exclusions = " --exclude=control.sock --exclude=agent.pid"
            if kind in {"cve-importer", "cve-enricher"}:
                exclusions += " --exclude=./scratch"
            if kind == "n8n":
                exclusions += " --exclude=./data"
            print("Secrets/Zertifikate übernehmen: " + kind, flush=True)
            helper(
                config,
                [
                    "type=bind,source=" + str(source) + ",target=/source,readonly",
                    "type=bind,source=" + str(staging) + ",target=/target",
                ],
                "set -o pipefail; tar"
                + exclusions
                + " -cpf - -C /source . | tar -xpf - -C /target",
            )
            staging.rename(target)
            if kind == "ingress-pki":
                for path in target.rglob("*.cnf"):
                    path.write_text(path.read_text().replace(str(previous), str(base)))
        atomic(marker, {"secrets_base": str(base)})
