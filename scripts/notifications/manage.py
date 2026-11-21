"""Own-project n8n/notification provisioning, immutable builds and namespace isolation."""

import argparse
import hashlib
import ipaddress
import json
import os
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cve_common.deployment import APPLICATION_IMAGE
from cve_notification.control import STAGES

from scripts.database import manage as db
from scripts.infrastructure import mail
from scripts.infrastructure import network as net
from scripts.infrastructure.manage import Config, compose, docker_command, load_config, run
from scripts.security.manage import origin

IMAGE = APPLICATION_IMAGE


def directory(config: Config) -> Path:
    return config.secrets_base / "notifications" / config.project


def n8n_directory(config: Config) -> Path:
    return config.secrets_base / "n8n" / config.project


def write(path: Path, value: bytes) -> None:
    if path.is_symlink():
        raise ValueError("Symlink configuration forbidden")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(value)
    path.chmod(0o600)


def certificates(base: Path) -> None:
    if (base / "ca.crt").exists():
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Local notification service CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    write(base / "ca.crt", ca.public_bytes(serialization.Encoding.PEM))
    # Keep CA signing key outside both runtime mounts.
    private = base.parent / (base.name + "-signing")
    private.mkdir(mode=0o700, exist_ok=True)
    write(
        private / "ca.key",
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    for name, host in [("notification", "cve-notification"), ("n8n", "cve-n8n")]:
        leaf = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(subject)
            .public_key(leaf.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=14))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(host), x509.DNSName("localhost")]),
                critical=False,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256())
        )
        write(base / (name + ".crt"), cert.public_bytes(serialization.Encoding.PEM))
        write(
            base / (name + ".key"),
            leaf.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )


def prepare(config: Config) -> None:
    base = directory(config)
    n8n = n8n_directory(config)
    nc = n8n / "config"
    if base.is_symlink() or n8n.is_symlink():
        raise ValueError("Unsafe runtime directory")
    if not config.manages_credentials and not base.exists():
        raise ValueError("External production credentials and certificates required")
    data = config.mount_base / "n8n" / config.project / "data"
    for path in [base, n8n, nc, data]:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if config.manages_credentials:
        certificates(base)
        mail.prepare(config)
        copies = [
            (base / "notification.password", db.secret_file(config, "notification")),
            (base / "workflow_control.password", db.secret_file(config, "workflow_control")),
            (base / "db-ca.crt", db.workdir(config) / "tls/ca.crt"),
            (nc / "n8n_app.password", db.secret_file(config, "n8n_app")),
            (nc / "db-ca.crt", db.workdir(config) / "tls/ca.crt"),
            (base / "smtp-ca.crt", mail.directory(config) / "pki/client-ca.crt"),
            (base / "smtp-client.crt", mail.directory(config) / "pki/notification.crt"),
            (base / "smtp-client.key", mail.directory(config) / "pki/private/notification.key"),
        ]
        for target, source in copies:
            if not target.exists():
                write(target, source.read_bytes())
        for name in ["ca.crt", "n8n.crt", "n8n.key"]:
            if not (nc / name).exists():
                write(nc / name, (base / name).read_bytes())
        for path in [
            base / "service-key.current",
            base / "webhook-key",
            base / "workflow-webhook.key",
            nc / "encryption.key",
        ]:
            if not path.exists():
                write(path, secrets.token_urlsafe(48).encode())
        for stage in STAGES:
            stage_key = base / ("workflow-key." + stage)
            if not stage_key.exists():
                write(stage_key, secrets.token_urlsafe(48).encode())
        if not (base / "runtime.json").exists():
            write(
                base / "runtime.json",
                json.dumps(
                    {
                        "sender": "security@cve.example.test",
                        "dashboard": origin(config),
                        "relay_instance": config.project + ":cve-mail-relay",
                    }
                ).encode(),
            )
    # Keys for the other service are not mounted in this namespace.
    for name in ["n8n.key", "n8n.crt"]:
        if (base / name).exists():
            (base / name).unlink()
    write(
        nc / "trust-bundle.crt",
        (nc / "ca.crt").read_bytes() + b"\n" + (nc / "db-ca.crt").read_bytes(),
    )
    prepare_credentials(config)
    db.read_secret(base / "notification.password")
    db.read_secret(nc / "n8n_app.password")


def build(config: Config) -> None:
    from scripts.application.build import build as shared_build

    shared_build(config)


def peer(config: Config, service: str, network: str) -> str:
    identity = compose(config, ["ps", "-q", service]).stdout.strip()
    if not identity:
        raise ValueError("Required own service is not running")
    value = net.inspect_container(identity)
    networks = value["NetworkSettings"]["Networks"]
    entry = next(v for k, v in networks.items() if k.endswith("_" + network))
    return str(ipaddress.IPv4Address(entry["IPAddress"]))


def guard(config: Config) -> None:
    from scripts.application.manage import processing_guard, release

    processing_guard(config)
    release(config, "cve-processing")
    for service, table in [("cve-n8n", "cve_n8n")]:
        identity = compose(config, ["ps", "-q", service]).stdout.strip()
        value = net.inspect_container(identity)
        if (
            value["Config"]["Labels"].get("com.docker.compose.project") != config.project
            or value["Config"]["Labels"].get("com.docker.compose.service") != service
        ):
            raise ValueError("Only own labelled namespaces")
        pid = int(value["State"]["Pid"])
        namespace = net.namespace_command(pid, ["readlink", "/proc/self/ns/net"]).stdout.strip()
        if pid <= 1 or namespace == os.readlink("/proc/self/ns/net"):
            raise ValueError("Host namespace forbidden")
        target = "cve-n8n" if service == "cve-notification" else "cve-notification"
        port = 5678 if service == "cve-notification" else 8000
        allowed = [
            (peer(config, target, network), port)
            for network in ["cve_internal", "cve_data", "cve_outbound"]
        ]
        allowed.append((db.address(config), 5432))
        if service == "cve-notification":
            allowed.append((peer(config, "cve-mail-relay", "cve_internal"), 2525))
        rules = (
            "table inet "
            + table
            + (
                " {\n chain forward { type filter hook forward priority 0; policy d"
                "rop; }\n chain output { type filter hook output priority -110; pol"
                "icy drop;\n ct direction reply accept\n ip daddr 127.0.0.11 udp dpo"
                "rt 53 accept\n ip daddr 127.0.0.11 tcp dport 53 accept\n ip daddr 1"
                "27.0.0.1 accept\n"
            )
        )
        rules += (
            "".join(
                f" ip daddr {ipaddress.IPv4Address(host)} tcp dport {p} accept\n"
                for host, p in allowed
            )
            + " ip daddr { 0.0.0.0/8,10.0.0.0/8,100.64.0.0/10,"
            "127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.168.0.0/16,"
            "224.0.0.0/4,240.0.0.0/4 } reject\n meta nfproto ipv4 tcp dport 443 accept\n"
            " counter reject\n }\n"
        )
        local = 8000 if service == "cve-notification" else 5678
        rules += " chain input { type filter hook input priority -110; policy drop; "
        rules += 'ct state established,related accept\n iifname "lo" accept\n'
        for network in ["cve_internal", "cve_data", "cve_outbound"]:
            remote = peer(config, target, network)
            rules += f"ip saddr {remote} tcp dport {local} accept\n"
        rules += " }\n}\n"
        if "table inet " + table in net.namespace_command(pid, ["nft", "list", "tables"]).stdout:
            rules = "delete table inet " + table + "\n" + rules
        net.namespace_command(pid, ["nft", "-c", "-f", "-"], input=rules)
        net.namespace_command(pid, ["nft", "-f", "-"], input=rules)
        if service == "cve-notification":
            write(directory(config) / "guard.ready", (namespace + "\n").encode())
        write(
            (directory(config) if service == "cve-notification" else n8n_directory(config))
            / (table + ".nft"),
            rules.encode(),
        )


def prepare_credentials(config: Config) -> None:
    base = directory(config)
    nc = n8n_directory(config) / "config"
    credentials: list[dict[str, Any]] = [
        {
            "id": "cve-notification-service-v1",
            "name": "CVE Notification Service",
            "type": "httpHeaderAuth",
            "data": {
                "name": "X-CVE-Service",
                "value": (base / "service-key.current").read_text().strip(),
            },
        },
        {
            "id": "cve-notification-webhook-v1",
            "name": "CVE Notification Webhook",
            "type": "httpHeaderAuth",
            "data": {"name": "X-CVE-Webhook", "value": (base / "webhook-key").read_text().strip()},
        },
    ]
    credentials.extend(
        {
            "id": "cve-control-" + stage + "-v1",
            "name": "CVE Control " + stage,
            "type": "httpHeaderAuth",
            "data": {
                "name": "X-CVE-Orchestrator",
                "value": (base / ("workflow-key." + stage)).read_text().strip(),
            },
        }
        for stage in STAGES
    )
    credentials.append(
        {
            "id": "cve-control-webhook-v1",
            "name": "CVE Control Webhook",
            "type": "httpHeaderAuth",
            "data": {
                "name": "Authorization",
                "value": "Bearer " + (base / "workflow-webhook.key").read_text().strip(),
            },
        }
    )
    credentials.append(
        {
            "id": "cve-control-watchdog-db-v1",
            "name": "CVE Control Watchdog Database",
            "type": "postgres",
            "data": {
                "host": "cve-postgres",
                "database": "cve_monitoring",
                "user": "workflow_control",
                "password": db.read_secret(db.secret_file(config, "workflow_control")),
                "port": 5432,
                "ssl": "require",
                "allowUnauthorizedCerts": False,
                "maxConnections": 2,
            },
        }
    )
    write(nc / "credentials.json", json.dumps(credentials).encode())


def install_workflows(config: Config) -> None:
    """Restart the container; its bootstrap owns import and publication."""
    prepare(config)
    compose(config, ["up", "-d", "--no-deps", "--force-recreate", "cve-n8n"])
    guard(config)
    compose(
        config,
        ["up", "-d", "--no-deps", "--no-recreate", "--wait", "--wait-timeout", "120", "cve-n8n"],
    )


def start(config: Config) -> None:
    from scripts.application.manage import start as start_group

    prepare(config)
    compose(config, ["up", "-d", "cve-n8n"])
    start_group(config, "cve-processing")
    guard(config)
    compose(config, ["up", "-d", "--wait", "--wait-timeout", "90", "cve-processing", "cve-n8n"])


def rotate(config: Config) -> None:
    base = directory(config)
    write(base / "service-key.previous", (base / "service-key.current").read_bytes())
    write(base / "service-key.current", secrets.token_urlsafe(48).encode())
    install_workflows(config)


def reconcile_postfix(config: Config) -> dict[str, int]:
    """Read only own Postfix logs/queue; message IDs and instance/queue bind observations."""
    import re

    info = mail.container(config)
    fixed = json.loads((directory(config) / "runtime.json").read_text())
    logs = run([*docker_command(), "logs", "--tail", "5000", info["Id"]])
    lines = (logs.stdout + "\n" + logs.stderr).splitlines()
    queue_rows = mail.queue(config)
    queues: dict[str, UUID] = {}
    observations: list[tuple[str, str, str]] = []
    for item in queue_rows[:100]:
        identity = item.get("queue_id", "")
        if not re.fullmatch(r"[A-Za-z0-9]{5,64}", identity):
            continue
        headers = mail.exec_mail(config, ["postcat", "-h", "-q", identity])
        match = re.search(r"Message-ID: <([0-9a-f-]{36})@cve-monitoring\.invalid>", headers, re.I)
        if match:
            queues[identity] = UUID(match[1])
            observations.append((identity, "relay_accepted", str(queues[identity])))
    depth = len(queue_rows)
    count = 0
    with db.connect(config, "notification") as c:
        c.execute(
            (
                "INSERT INTO automation.notification_transport_samp"
                "les(relay_instance,queue_depth) VALUES(%s,%s)"
            ),
            (fixed["relay_instance"], depth),
        )
        for line in lines:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if (
                not isinstance(event, dict)
                or event.get("event") not in {"sent", "bounced"}
                or not re.fullmatch(r"[A-Za-z0-9]{5,64}", str(event.get("queue_id", "")))
            ):
                continue
            queue = event["queue_id"]
            candidates = c.execute(
                (
                    "SELECT a.notification_id FROM automation.notificat"
                    "ion_delivery_results r JOIN automation.notificatio"
                    "n_delivery_attempts a ON a.id=r.attempt_id WHERE r"
                    ".queue_id=%s AND r.relay_instance=%s AND a.started"
                    "_at<=%s::timestamptz AND a.started_at>%s::timestam"
                    "ptz-interval '6 days'"
                ),
                (queue, fixed["relay_instance"], event["time"], event["time"]),
            ).fetchall()
            if len(candidates) != 1:
                continue
            queues[queue] = candidates[0]["notification_id"]
            observations.append(
                (
                    queue,
                    "upstream_accepted" if event["event"] == "sent" else "bounced",
                    event["time"],
                )
            )
        for queue, status, stamp in observations:
            evidence = hashlib.sha256(
                (
                    fixed["relay_instance"]
                    + ":"
                    + queue
                    + ":"
                    + str(queues[queue])
                    + ":"
                    + status
                    + ":"
                    + stamp
                ).encode()
            ).hexdigest()
            row = c.execute(
                "SELECT automation.notification_observe(%s,%s,%s,%s,%s) AS changed",
                (queues[queue], evidence, fixed["relay_instance"], queue, status),
            ).fetchone()
            assert row
            count += int(row["changed"])
    return {"queue_depth": depth, "observations": count}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=[
            "prepare",
            "build",
            "up",
            "guard",
            "rotate",
            "down",
            "metrics",
            "reconcile-postfix",
        ],
    )
    args = parser.parse_args()
    config = load_config()
    if args.action == "down":
        compose(config, ["stop", "cve-notification", "cve-n8n"])
    elif args.action == "reconcile-postfix":
        print(json.dumps(reconcile_postfix(config)))
    elif args.action == "metrics":
        with db.connect(config, "notification") as c:
            print(
                json.dumps(
                    c.execute("SELECT automation.notification_metrics() AS metrics").fetchone(),
                    default=str,
                )
            )
    else:
        {"prepare": prepare, "build": build, "up": start, "guard": guard, "rotate": rotate}[
            args.action
        ](config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
