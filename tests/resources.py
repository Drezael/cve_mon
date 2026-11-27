"""Label-checked cleanup callbacks, including fixture failures before yield."""

import json
import subprocess

from scripts.infrastructure.manage import docker_command


def remove(kind: str, name: str, label: str, project: str) -> None:
    command = [*docker_command(), *(["network"] if kind == "network" else [])]
    inspected = subprocess.run(
        [*command, "inspect", name], capture_output=True, text=True, check=False
    )
    if inspected.returncode:
        return
    item = json.loads(inspected.stdout)[0]
    labels = item["Labels"] if kind == "network" else item["Config"]["Labels"]
    if labels.get(label) != project:
        raise ValueError("Refusing cleanup of a foreign resource: " + name)
    subprocess.run(
        [*command, "rm", *([] if kind == "network" else ["-f"]), name],
        check=True,
        capture_output=True,
        text=True,
    )
