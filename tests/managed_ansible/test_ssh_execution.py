"""Real SSH/Ansible: key, encrypted key, password and host-key verification."""

import json
import secrets
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from cve_automation.execute import run
from cve_automation.inventory_adapter import normalize

from scripts.infrastructure.manage import docker_command
from scripts.services.manage import PYTHON_IMAGE

pytestmark = pytest.mark.automation


@pytest.fixture(scope="module")
def ssh_target(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Any]]:
    root = tmp_path_factory.mktemp("managed-ssh")
    password = secrets.token_urlsafe(24)
    name = "cve-ssh-fixture-" + uuid4().hex[:12]
    docker = docker_command()
    command = (
        "apk add --no-cache openssh-server >/dev/null && "
        "adduser -D collector && mkdir -p /run/sshd && ssh-keygen -A >/dev/null && "
        "exec /usr/sbin/sshd -D -e "
        "-o PasswordAuthentication=yes -o PerSourcePenalties=no"
    )
    subprocess.run(
        [*docker, "run", "-d", "--name", name, PYTHON_IMAGE, "sh", "-c", command],
        check=True,
        capture_output=True,
    )
    try:
        for _ in range(120):
            result = subprocess.run(
                [*docker, "exec", name, "test", "-f", "/etc/ssh/ssh_host_ed25519_key"],
                capture_output=True,
            )
            if result.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise AssertionError("Disposable SSH fixture did not start")
        subprocess.run(
            [*docker, "exec", "-i", name, "chpasswd"],
            input=f"collector:{password}\n",
            text=True,
            check=True,
            capture_output=True,
        )
        inspected = json.loads(
            subprocess.run(
                [*docker, "inspect", name], check=True, capture_output=True, text=True
            ).stdout
        )[0]
        address = inspected["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]
        keys = []
        for index, passphrase in enumerate(("", "fixture-encrypted-key")):
            key = root / f"identity-{index}"
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", passphrase, "-f", str(key)],
                check=True,
                capture_output=True,
            )
            keys.append((key.read_text(), passphrase))
        public = "\n".join(p.read_text() for p in root.glob("*.pub"))
        subprocess.run(
            [
                *docker,
                "exec",
                "-i",
                name,
                "sh",
                "-c",
                (
                    "mkdir -p /home/collector/.ssh && cat > /home/collector/.ssh/autho"
                    "rized_keys && chown -R collector:collector /home/collector/.ssh &"
                    "& chmod 700 /home/collector/.ssh && chmod 600 /home/collector/.ss"
                    "h/authorized_keys"
                ),
            ],
            input=public,
            text=True,
            check=True,
            capture_output=True,
        )
        yield {"address": address, "password": password, "keys": keys, "name": name}
    finally:
        subprocess.run([*docker, "rm", "-f", name], check=False, capture_output=True)


@pytest.mark.parametrize("method", ["password", "key", "encrypted-key"])
def test_real_login_and_collection(ssh_target: dict[str, Any], tmp_path: Path, method: str) -> None:
    plan = {
        "address": ssh_target["address"],
        "port": 22,
        "username": "collector",
        "use_sudo": False,
        "auth_method": "password" if method == "password" else "key",
        "action": "probe",
        "credentials": {},
        "mount_paths": [],
    }
    probe = run(plan, tmp_path)
    assert probe["success"]
    plan["host_key"] = probe["host_key"]
    plan["credentials"] = {}
    if method == "password":
        plan["credentials"]["password"] = ssh_target["password"]
    else:
        private, passphrase = ssh_target["keys"][method == "encrypted-key"]
        plan["credentials"].update(private_key=private, passphrase=passphrase)
    plan["action"] = "test"
    assert run(plan, tmp_path)["success"]
    plan["action"] = "collect"
    result = run(plan, tmp_path)
    assert result["success"]
    inventory = normalize(json.loads((tmp_path / "inventory-input.json").read_text()))
    first_identity = inventory["host"]["monitoring_id"]
    assert run(plan, tmp_path)["success"]
    again = normalize(json.loads((tmp_path / "inventory-input.json").read_text()))
    assert again["host"]["monitoring_id"] == first_identity
    # Collection must not provision persistent identities, binaries or caches on the target.
    subprocess.run(
        [
            *docker_command(),
            "exec",
            ssh_target["name"],
            "sh",
            "-c",
            "test ! -e /home/collector/.local && test ! -e /home/collector/.cache",
        ],
        check=True,
        capture_output=True,
    )
    assert inventory["os"]["data"]["distribution"] == "Alpine"
    assert inventory["docker"]["status"] == "not_installed"
    if method == "password":
        import os
        import sys

        # Use the local venv without another checkout or PATH activation.
        credential = tmp_path / "ssh.password"
        credential.write_text(ssh_target["password"])
        credential.chmod(0o600)
        connection = tmp_path / "connection.json"
        connection.write_text(
            json.dumps(
                {
                    "host": ssh_target["address"],
                    "username": "collector",
                    "auth_method": "password",
                    "password_file": str(credential),
                    "host_key": probe["host_key"],
                }
            )
        )
        connection.chmod(0o600)
        output = tmp_path / "local-inventory.json"
        subprocess.run(
            [
                sys.executable,
                "-m",
                "scripts.ansible.manage",
                "collect",
                "--config",
                str(connection),
                "--output",
                str(output),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=90,
            env={**os.environ, "PATH": "/usr/bin:/bin"},
        )
        local = json.loads(output.read_text())
        assert local["host"]["monitoring_id"] == first_identity
        assert output.stat().st_mode & 0o777 == 0o600
    # A pinned different public key must never permit authentication or collection.
    plan["host_key"] = "ssh-ed25519 " + __import__("base64").b64encode(b"wrong-host-key").decode()
    plan["action"] = "test"
    assert not run(plan, tmp_path)["success"]


def test_own_runtime_image_collects_without_root_or_extra_capabilities(
    ssh_target: dict[str, Any], tmp_path: Path
) -> None:
    import os

    from cve_common.deployment import APPLICATION_IMAGE

    from scripts.application.build import build
    from scripts.infrastructure.manage import load_config

    build(load_config())
    plan = {
        "address": ssh_target["address"],
        "port": 22,
        "username": "collector",
        "auth_method": "password",
        "use_sudo": False,
        "action": "probe",
        "credentials": {
            "password": ssh_target["password"],
        },
        "mount_paths": [],
    }
    probe = run(plan, tmp_path)
    assert probe["success"]
    plan.update(action="collect", host_key=probe["host_key"])
    (tmp_path / "plan.json").write_text(json.dumps(plan))
    (tmp_path / "plan.json").chmod(0o600)
    subprocess.run(
        [
            *docker_command(),
            "run",
            "--rm",
            "--read-only",
            "--cap-drop=ALL",
            "--user",
            str(os.getuid()),
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=32m",
            "--volume",
            str(tmp_path) + ":/work",
            "--entrypoint",
            "python",
            APPLICATION_IMAGE,
            "-m",
            "cve_automation.execute",
            "/work/plan.json",
        ],
        check=True,
        capture_output=True,
        timeout=120,
    )
    result = json.loads((tmp_path / "result.json").read_text())
    assert result["success"], result
    assert normalize(json.loads((tmp_path / "inventory-input.json").read_text()))["host"][
        "monitoring_id"
    ]
