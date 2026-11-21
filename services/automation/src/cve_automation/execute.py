"""A disposable Ansible Runner process. Only fixed playbooks and bounded local files."""

import base64
import json
import os
import subprocess
import sys
from importlib.resources import files
from pathlib import Path
from typing import Any

import ansible_runner  # type: ignore[import-untyped]


def run(plan: dict[str, Any], root: Path) -> dict[str, Any]:
    host, port = plan["address"], plan["port"]
    if plan["action"] == "probe":
        p = subprocess.run(
            ["ssh-keyscan", "-T", "10", "-p", str(port), "-t", "ed25519,rsa", host],
            capture_output=True,
            text=True,
            timeout=35,
        )
        keys = [line for line in p.stdout.splitlines() if line and not line.startswith("#")]
        if not keys:
            return {"success": False, "error_code": "ssh_unreachable"}
        chosen = next((k for k in keys if "ssh-ed25519" in k), keys[0]).split()
        return {"success": True, "host_key": " ".join(chosen[-2:])}
    if plan.get("use_sudo") or plan["username"] == "root":
        return {"success": False, "error_code": "unprivileged_account_required"}
    cfg = plan["credentials"]
    inventory = {
        "all": {
            "hosts": {
                "target": {
                    "ansible_host": host,
                    "ansible_port": port,
                    "ansible_user": plan["username"],
                    "ansible_become": False,
                    "ansible_ssh_pipelining": True,
                    "ansible_ssh_args": (
                        "-C -o ControlMaster=no -o ControlPersist=no -o ControlPath=none"
                    ),
                    "ansible_ssh_common_args": (
                        "-o StrictHostKeyChecking=yes "
                        f"-o UserKnownHostsFile={root / 'known_hosts'} "
                        "-o GlobalKnownHostsFile=/dev/null -o ConnectTimeout=15"
                    ),
                    "ansible_ssh_password_mechanism": "sshpass",  # pragma: allowlist secret
                    **(
                        {"ansible_ssh_extra_args": "-o PubkeyAuthentication=no"}
                        if plan["auth_method"] == "password"
                        else {}
                    ),
                    **(
                        {"ansible_password": cfg["password"]}
                        if plan["auth_method"] == "password"
                        else {}
                    ),
                }
            }
        }
    }
    (root / "known_hosts").write_text(
        f"[{host}]:{port} {plan['host_key']}\n{host} {plan['host_key']}\n"
    )
    data = files("cve_automation").joinpath("data")

    def encoded(source: str) -> str:
        return (
            "import base64;exec(base64.b64decode("
            + repr(base64.b64encode(source.encode()).decode())
            + "))"
        )

    docker_source = (
        "COLLECTOR_SOURCE="
        + repr(data.joinpath("docker_software.py.txt").read_text())
        + "\n"
        + data.joinpath("docker_metadata.py.txt").read_text()
    )
    extra = {
        "identity_code": encoded(data.joinpath("host_identity.py.txt").read_text()),
        "docker_code": encoded(docker_source),
        "mount_paths": plan["mount_paths"],
        "output_file": str(root / "inventory-input.json"),
    }
    import yaml

    name = "connection-test.yml" if plan["action"] == "test" else "collect.yml"
    playbook = yaml.safe_load(files("cve_automation").joinpath("playbooks/" + name).read_text())
    (root / "project").mkdir(exist_ok=True)
    (root / "project" / "collect.yml").write_text(__import__("yaml").safe_dump(playbook))
    passwords = {r"ssh_key_data.*:\s*$": cfg["passphrase"]} if cfg.get("passphrase") else {}
    (root / "ansible.cfg").write_text("[defaults]\n")
    result = ansible_runner.run(
        private_data_dir=str(root),
        playbook="collect.yml",
        inventory=inventory,
        extravars=extra,
        ssh_key=cfg.get("private_key") if plan["auth_method"] == "key" else None,
        passwords=passwords,
        quiet=True,
        event_handler=lambda event: False,
        envvars={
            "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", ""),
            "HOME": str(root),
            "USER": "cve",
            "LOGNAME": "cve",
            "ANSIBLE_CONFIG": str(root / "ansible.cfg"),
            "ANSIBLE_HOME": str(root / "ansible-home"),
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_LOG_PATH": "/dev/null",
            "ANSIBLE_HOST_KEY_CHECKING": "True",
            "ANSIBLE_LOCAL_TEMP": str(root / "local-tmp"),
            "ANSIBLE_SSH_CONTROL_PATH_DIR": str(root / "ssh-control"),
        },
        settings={
            "job_timeout": 2100,
            "idle_timeout": 300,
            "suppress_ansible_output": True,
            "suppress_output_file": True,
        },
    )
    return {"success": result.rc == 0, "error_code": None if result.rc == 0 else "ansible_failed"}


def main() -> None:
    os.umask(0o077)
    p = Path(sys.argv[1])
    plan = json.loads(p.read_text())
    try:
        result = run(plan, p.parent)
    except Exception as error:
        result = {
            "success": False,
            "error_code": "execution_failed",
            "error_class": type(error).__name__,
        }
    (p.parent / "result.json").write_text(json.dumps(result))


if __name__ == "__main__":
    main()
