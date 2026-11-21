"""Scoped Postfix operator: locked build, file secrets, native queue and gated Envoy integration."""

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from scripts.infrastructure import network as net
from scripts.infrastructure.images import REFERENCES
from scripts.infrastructure.manage import (
    Config,
    compose,
    docker_command,
    load_config,
    run,
    service_image,
)

ROOT = Path(__file__).resolve().parents[2]
IMAGE = REFERENCES["mail"]
CAPABILITIES = {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID", "KILL"}
SETTING_RANGES = {
    "message_size_limit": (1024, 10485760),
    "smtpd_recipient_limit": (1, 100),
    "queue_minfree": (0, 2**60),
    "minimal_backoff_time": (1, 3600),
    "maximal_backoff_time": (1, 86400),
    "queue_run_delay": (1, 3600),
    "maximal_queue_lifetime": (1, 432000),
    "bounce_queue_lifetime": (1, 86400),
}


def directory(config: Config) -> Path:
    return config.secrets_base / "mail" / config.project


def validate(value: dict[str, Any]) -> dict[str, Any]:
    if (
        set(value) != {"enabled", "smarthost", "port", "clients", "recipients", "settings"}
        or type(value["enabled"]) is not bool
    ):
        raise ValueError("Unknown/missing mail policy fields")
    if (
        not isinstance(value["smarthost"], str)
        or type(value["port"]) is not int
        or not isinstance(value["clients"], list)
        or not isinstance(value["recipients"], list)
        or not isinstance(value["settings"], dict)
    ):
        raise ValueError("Invalid mail policy types")
    if (
        not re.fullmatch(
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", value["smarthost"]
        )
        or not 1 <= value["port"] <= 65535
    ):
        raise ValueError("Explicit FQDN and port required")
    email = re.compile(
        r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}@[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\.[a-z]{2,63}"
    )
    seen = set()
    for client in value["clients"]:
        if (
            not isinstance(client, dict)
            or set(client) != {"name", "fingerprint", "senders", "enabled", "purpose"}
            or type(client["enabled"]) is not bool
        ):
            raise ValueError("Invalid client policy")
        if (
            not isinstance(client["name"], str)
            or not isinstance(client["fingerprint"], str)
            or not isinstance(client["senders"], list)
            or not isinstance(client["purpose"], str)
            or not 1 <= len(client["purpose"]) <= 200
            or not re.fullmatch(r"[a-z][a-z0-9_-]{0,47}", client["name"])
        ):
            raise ValueError("Client holder and purpose required")
        fp = client["fingerprint"].upper()
        if not re.fullmatch(r"(?:[A-F0-9]{2}:){31}[A-F0-9]{2}", fp) or fp in seen:
            raise ValueError("Unique SHA-256 fingerprint required")
        seen.add(fp)
        if not client["senders"] or any(
            not isinstance(a, str) or not email.fullmatch(a) for a in client["senders"]
        ):
            raise ValueError("Explicit senders required")
    if any(not isinstance(a, str) or not email.fullmatch(a) for a in value["recipients"]) or len(
        value["recipients"]
    ) != len(set(value["recipients"])):
        raise ValueError("Explicit unique recipients required")
    for key, number in value["settings"].items():
        if (
            key not in SETTING_RANGES
            or type(number) is not int
            or not SETTING_RANGES[key][0] <= number <= SETTING_RANGES[key][1]
        ):
            raise ValueError("Unsupported Postfix setting")
    if not value["enabled"] and (value["clients"] or value["recipients"]):
        raise ValueError("Disabled policy must have no relay grants")
    return value


def build(config: Config) -> None:
    from scripts.hardening.runtime_images import build as build_runtime

    build_runtime(config, "mail")


def certificate(
    base: Path, name: str, ca: str, hostname: str, client: bool = False, expired: bool = False
) -> None:
    private = base / "private"
    private.mkdir(parents=True, exist_ok=True, mode=0o700)
    run(
        [
            "openssl",
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(private / (name + ".key")),
            "-out",
            str(private / (name + ".csr")),
            "-subj",
            "/CN=" + hostname,
        ]
    )
    extensions = private / (name + ".ext")
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage="
        + ("clientAuth" if client else "serverAuth")
        + "\nsubjectAltName=DNS:"
        + hostname
        + "\n"
    )
    run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(private / (name + ".csr")),
            "-CA",
            str(base / (ca + ".crt")),
            "-CAkey",
            str(private / (ca + ".key")),
            "-CAcreateserial",
            "-out",
            str(base / (name + ".crt")),
            "-days",
            "-1" if expired else "365",
            "-sha256",
            "-extfile",
            str(extensions),
        ]
    )
    (private / (name + ".key")).chmod(0o600)


def prepare(config: Config) -> None:
    base = directory(config)
    state = base / "state"
    secrets = base / "secrets"
    if state.exists():
        validate(json.loads((state / "policy.json").read_text()))
        check_secrets(config)
        return
    if not config.manages_credentials:
        raise ValueError("Production requires externally provisioned keys/credentials")
    base.mkdir(parents=True, exist_ok=True, mode=0o755)
    pki = base / "pki"
    pki.mkdir(mode=0o755)
    (pki / "private").mkdir(mode=0o700)
    for ca in ("client-ca", "upstream-ca", "foreign-ca"):
        run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "365",
                "-keyout",
                str(pki / "private" / (ca + ".key")),
                "-out",
                str(pki / (ca + ".crt")),
                "-subj",
                "/CN=CVE "
                + ("Development" if config.values["APP_ENV"] == "development" else "Internal")
                + " "
                + ca,
                "-addext",
                "basicConstraints=critical,CA:TRUE",
            ]
        )
        (pki / "private" / (ca + ".key")).chmod(0o600)
    certificate(pki, "server", "client-ca", "cve-mail-relay")
    certificate(pki, "notification", "client-ca", "notification", True)
    state.mkdir(mode=0o755)
    secrets.mkdir(mode=0o700)
    for name in ("client-ca.crt", "upstream-ca.crt", "server.crt"):
        shutil.copyfile(pki / name, state / name)
    shutil.copyfile(pki / "private/server.key", secrets / "server.key")
    (secrets / "server.key").chmod(0o600)
    import secrets as random_secrets

    for name in ("smtp_username", "smtp_password"):
        path = secrets / name
        path.write_text(random_secrets.token_urlsafe(36) + "\n")
        path.chmod(0o600)
    value = {
        "enabled": False,
        "smarthost": "smtp.example.invalid",
        "port": 587,
        "clients": [],
        "recipients": [],
        "settings": {},
    }
    (state / "policy.json").write_text(json.dumps(value, indent=2))
    if config.values["APP_ENV"] == "development":
        (base / "development-only").touch()


def check_secrets(config: Config) -> None:
    base = directory(config)
    for name in ("smtp_username", "smtp_password", "server.key"):
        path = base / "secrets" / name
        if (
            path.is_symlink()
            or not path.is_file()
            or stat.S_IMODE(path.stat().st_mode) not in (0o400, 0o600)
        ):
            raise ValueError("Missing/insecure secret file")
        if name != "server.key":
            value = path.read_text().removesuffix("\n")
            if (
                not value
                or any(c.isspace() or c == "\0" for c in value)
                or (name == "smtp_username" and ":" in value)
            ):
                raise ValueError("Invalid credential format")
    if config.values["APP_ENV"] == "production" and (base / "development-only").exists():
        raise ValueError("Development PKI is not production PKI")


def container(config: Config) -> dict[str, Any]:
    name = compose(config, ["ps", "-aq", "cve-mail-relay"]).stdout.strip()
    if not name:
        raise ValueError("Postfix container missing")
    value = net.inspect_container(name)
    if value["Config"]["Labels"].get("org.cve-monitoring.project") != config.project:
        raise ValueError("Foreign mail container")
    return value


def exec_mail(config: Config, args: list[str]) -> str:
    return run([*docker_command(), "exec", container(config)["Id"], *args]).stdout


def release(config: Config) -> None:
    value = container(config)
    pid = int(value["State"]["Pid"])
    if pid <= 1:
        raise ValueError("Invalid mail namespace")
    ns = net.namespace_command(pid, ["readlink", "/proc/self/ns/net"]).stdout.strip()
    if ns == os.readlink("/proc/self/ns/net"):
        raise ValueError("Host namespace forbidden")
    internal = value["NetworkSettings"]["Networks"][config.project + "_cve_internal"]["IPAddress"]
    interfaces = json.loads(
        net.namespace_command(pid, ["ip", "-j", "-4", "address", "show"]).stdout
    )
    device = next(
        i["ifname"]
        for i in interfaces
        if any(a.get("local") == internal for a in i.get("addr_info", []))
    )
    rules = (
        "table inet cve_mail_input { chain input { type filter hook input priority 0; "
        'policy drop; iifname "lo" accept; ct state established,related accept; iifname "'
        + device
        + '" ip daddr '
        + internal
        + " tcp dport 2525 accept;\n }\n}\n"
    )
    if "table inet cve_mail_input" in net.namespace_command(pid, ["nft", "list", "tables"]).stdout:
        rules = "delete table inet cve_mail_input\n" + rules
    net.namespace_command(pid, ["nft", "-c", "-f", "-"], input=rules)
    net.namespace_command(pid, ["nft", "-f", "-"], input=rules)
    state = directory(config) / "state"
    (state / "listen-address").write_text(internal + "\n")
    boot = exec_mail(config, ["cat", "/run/postfix/boot"]).strip()
    digest = hashlib.sha256((state / "policy.json").read_bytes()).hexdigest()
    ready = state / "network.pending"
    ready.write_text(ns + " " + boot + " " + digest + "\n")
    ready.replace(state / "network.ready")


def start(config: Config) -> None:
    check_secrets(config)
    validate(json.loads((directory(config) / "state/policy.json").read_text()))
    compose(config, ["up", "-d", "--no-deps", "cve-mail-relay"])
    for _ in range(40):
        result = subprocess.run(
            [*docker_command(), "exec", container(config)["Id"], "test", "-f", "/run/postfix/boot"],
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            break
        time.sleep(0.2)
    else:
        raise ValueError("Postfix bootstrap failed")
    release(config)
    compose(config, ["up", "-d", "--wait", "--wait-timeout", "40", "cve-mail-relay"])


def queue(config: Config) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in exec_mail(config, ["postqueue", "-j"]).splitlines()
        if line.strip()
    ]


def queue_bind(config: Config, info: dict[str, Any]) -> str:
    from scripts.infrastructure.storage import checked, path

    checked(config)
    mounts = [m for m in info["Mounts"] if m["Destination"] == "/var/spool/postfix"]
    expected = path(config, "cve_postfix_queue")
    if (
        len(mounts) != 1
        or mounts[0].get("Type") != "bind"
        or mounts[0].get("Source") != str(expected)
        or expected.is_symlink()
    ):
        raise ValueError("Foreign queue bind mount")
    return str(expected)


def backup(config: Config, target: Path) -> None:
    """Quiesced queue backup only; no live-file copy claiming consistency."""
    from scripts.infrastructure.storage import image_tmpfs

    target.mkdir(parents=True, exist_ok=False, mode=0o700)
    info = container(config)
    compose(config, ["stop", "cve-mail-relay"])
    image = net.inspect_container(info["Id"])
    volume = queue_bind(config, image)
    archive = target / "queue.tar"
    with archive.open("xb") as output:
        archive.chmod(0o600)
        subprocess.run(
            [
                *docker_command(),
                "run",
                "--rm",
                "--network",
                "none",
                "--read-only",
                *image_tmpfs(service_image(config, "cve-mail-relay", IMAGE)),
                "--cap-drop",
                "ALL",
                "--cap-add",
                "DAC_OVERRIDE",
                "-v",
                volume + ":/queue:ro",
                "--entrypoint",
                "tar",
                service_image(config, "cve-mail-relay", IMAGE),
                "-C",
                "/queue",
                "--numeric-owner",
                # Vendor-generated chroot configuration is recreated at startup.
                "--exclude=./etc",
                "--exclude=./lib",
                "--exclude=./lib64",
                "--exclude=./usr",
                "--exclude=./dev",
                "-cpf",
                "-",
                ".",
            ],
            check=True,
            stdout=output,
            stderr=subprocess.PIPE,
        )
    (target / "manifest.json").write_text(
        json.dumps(
            {
                "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "image": info["Config"]["Image"],
                "consistency": "stopped Postfix",
                "external_secrets": ["TLS key/CA", "SMTP credentials", "operator mail policy"],
            }
        )
    )
    (target / "manifest.json").chmod(0o600)


def restore(config: Config, source: Path) -> None:
    """Restore only a stopped own, empty queue; never overwrite accepted messages."""
    import tarfile

    from scripts.infrastructure.storage import image_tmpfs

    archive = source / "queue.tar"
    if archive.is_symlink() or (source / "manifest.json").is_symlink():
        raise ValueError("Regular backup files required")
    manifest = json.loads((source / "manifest.json").read_text())
    if (
        manifest["image"] != service_image(config, "cve-mail-relay", IMAGE)
        or hashlib.sha256(archive.read_bytes()).hexdigest() != manifest["sha256"]
    ):
        raise ValueError("Backup version/checksum mismatch")
    if stat.S_IMODE(archive.stat().st_mode) & 0o077:
        raise ValueError("Private archive mode required")
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            if (
                member.name.startswith("/")
                or ".." in Path(member.name).parts
                or member.issym()
                or member.islnk()
            ):
                raise ValueError("Unsafe archive member")
    info = container(config)
    if info["State"]["Running"]:
        raise ValueError("Stop own Postfix before restore")
    volume = queue_bind(config, info)
    command = [
        *docker_command(),
        "run",
        "-i",
        "--rm",
        "--network",
        "none",
        "--read-only",
        *image_tmpfs(service_image(config, "cve-mail-relay", IMAGE)),
        "--cap-drop",
        "ALL",
        "--cap-add",
        "DAC_OVERRIDE",
        "--cap-add",
        "CHOWN",
        "--cap-add",
        "FOWNER",
        "-v",
        volume + ":/queue",
        "--entrypoint",
        "sh",
        service_image(config, "cve-mail-relay", IMAGE),
    ]
    # Empty native scaffold is fine, but no regular message/control files may be replaced.
    run(
        command + ["-c", 'test -z "$(find /queue -path /queue/etc -prune -o -type f -print -quit)"']
    )
    with archive.open("rb") as incoming:
        subprocess.run(
            command + ["-c", "cd /queue && tar --numeric-owner -xpf -"],
            stdin=incoming,
            capture_output=True,
            check=True,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=["build", "secrets", "check", "up", "down", "queue", "flush", "backup", "restore"],
    )
    parser.add_argument("--backup-dir", type=Path)
    args = parser.parse_args()
    try:
        config = load_config()
        if args.action == "build":
            build(config)
        elif args.action == "secrets":
            prepare(config)
        elif args.action == "up":
            start(config)
        elif args.action == "down":
            compose(config, ["stop", "cve-mail-relay"])
        elif args.action == "check":
            check_secrets(config)
            validate(json.loads((directory(config) / "state/policy.json").read_text()))
            exec_mail(config, ["postfix", "check"])
            exec_mail(config, ["/opt/cve-mail/healthcheck.sh"])
        elif args.action == "queue":
            print(json.dumps(queue(config)))
        elif args.action == "flush":
            exec_mail(config, ["postqueue", "-f"])
        elif args.action in {"backup", "restore"}:
            if not args.backup_dir:
                raise ValueError("--backup-dir required")
            (backup if args.action == "backup" else restore)(config, args.backup_dir.resolve())
        print(json.dumps({"action": args.action, "project": config.project, "result": "ok"}))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(
            json.dumps({"action": args.action, "result": "error", "code": type(error).__name__}),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
