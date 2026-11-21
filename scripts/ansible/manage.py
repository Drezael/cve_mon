"""Run the packaged, read-only Ansible playbooks without an external Ansible checkout."""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from cve_automation.execute import run
from cve_automation.inventory_adapter import encode, normalize, validate
from cve_automation.service import destination

ROOT = Path(__file__).resolve().parents[2]
PLAYBOOKS = ROOT / "services/automation/src/cve_automation/playbooks"


def private_json(path: Path) -> dict[str, Any]:
    """Accept only operator-owned private configuration, never executable commands."""
    if path.is_symlink() or path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
        raise ValueError("Owner-only configuration required")
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError("Configuration must be a JSON object")
    return value


def secret(path: str) -> str:
    target = Path(path)
    if target.is_symlink() or target.stat().st_uid != os.getuid() or target.stat().st_mode & 0o077:
        raise ValueError("Owner-only credential file required")
    return target.read_text().rstrip("\r\n")


def collect(path: Path, *, action: str = "collect") -> dict[str, Any]:
    config = private_json(path)
    if action not in {"collect", "probe", "test"}:
        raise ValueError("Unsupported fixed Ansible action")
    if config.get("use_sudo") or config["username"] == "root":
        raise ValueError("An unprivileged account without sudo is required")
    credentials = {}
    method = config.get("auth_method", "key")
    if action != "probe":
        if method not in {"key", "password"} or not config.get("host_key"):
            raise ValueError("Authentication method and confirmed SSH host key required")
        for name in ("private_key", "password", "passphrase"):
            if config.get(name + "_file"):
                credentials[name] = secret(config[name + "_file"])
                if name == "private_key":
                    credentials[name] += "\n"
        if method == "password" and not credentials.get("password"):
            raise ValueError("Password file required")
        if method == "key" and not credentials.get("private_key"):
            raise ValueError("Private key file required")
    plan = {
        "address": destination(config["host"], config.get("port", 22)),
        "port": config.get("port", 22),
        "username": config["username"],
        "auth_method": method,
        "use_sudo": False,
        "action": action,
        "credentials": credentials,
        "host_key": config.get("host_key"),
        "mount_paths": config.get("mount_paths", []),
    }
    with tempfile.TemporaryDirectory(prefix="cve-local-inventory-") as temporary:
        root = Path(temporary)
        result = run(plan, root)
        if not result["success"]:
            raise ValueError("Ansible action failed: " + str(result.get("error_code")))
        if action != "collect":
            return result
        document = normalize(json.loads((root / "inventory-input.json").read_text()))
        validate(document)
        return document


def save(path: Path, document: dict[str, Any]) -> None:
    if path.is_symlink():
        raise ValueError("Symlink inventory output forbidden")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(encode(document))
            stream.flush()
            temporary.chmod(0o600)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def syntax() -> None:
    executable = Path(sys.executable).parent / "ansible-playbook"
    if not executable.is_file():
        raise ValueError("Install the repository's local Python/Ansible environment first")
    with tempfile.TemporaryDirectory(prefix="cve-ansible-syntax-") as temporary:
        settings = Path(temporary) / "ansible.cfg"
        settings.write_text("[defaults]\nretry_files_enabled=False\n")
        for playbook in sorted(PLAYBOOKS.glob("*.yml")):
            subprocess.run(
                [str(executable), "--syntax-check", "-i", "target,", str(playbook)],
                check=True,
                cwd=ROOT,
                env={**os.environ, "ANSIBLE_HOME": temporary, "ANSIBLE_CONFIG": str(settings)},
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["collect", "probe", "test", "syntax"])
    parser.add_argument("--config", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.action == "syntax":
        syntax()
        return
    if not args.config or args.action == "collect" and not args.output:
        parser.error("--config and, for collect, --output are required")
    try:
        result = collect(args.config, action=args.action)
        if args.action == "collect":
            save(args.output, result)
        else:
            print(json.dumps(result))
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SystemExit(
            "Ansible action failed; check private connection settings and target access"
        ) from None


if __name__ == "__main__":
    main()
