"""Apply committed SMTP settings using direct native Postfix reloads; never restart containers."""

import json
import logging
import os
import secrets
import ssl
from pathlib import Path
from typing import Any

from cve_common.smtp_settings import SMTPConfig, SMTPKeyring

from scripts.database import manage as db
from scripts.infrastructure import mail
from scripts.infrastructure.manage import Config, docker_command, run
from scripts.notifications.manage import directory as notification_directory


def replace(path: Path, value: bytes, mode: int = 0o600) -> None:
    if path.is_symlink():
        raise ValueError("unsafe_configuration_path")
    temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".smtp-pending")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(value)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def reload_postfix(config: Config) -> None:
    # Original upstream image, supported mounted configuration hook and native reload.
    code = (
        "import sys;sys.path.insert(0,'/opt/cve-mail');import runtime;"
        "runtime.configure();runtime.native(['postconf','-e','inet_interfaces = '+"
        "(runtime.SOURCE/'listen-address').read_text().strip()]);"
        "runtime.native(['postfix','reload'])"
    )
    run(
        [
            *docker_command(),
            "exec",
            "--user",
            "0",
            mail.container(config)["Id"],
            "python3",
            "-c",
            code,
        ]
    )


def apply(
    config: Config,
    settings: SMTPConfig,
    credentials: dict[str, Any],
    *,
    profiles: list[dict[str, Any]] | None = None,
    recipients: list[str] | None = None,
) -> None:
    """Apply direct native Postfix transport maps atomically; retain the durable queue."""
    base = mail.directory(config)
    identifier = mail.container(config)["Id"]
    profiles = (
        profiles
        if profiles is not None
        else (
            [
                {
                    "owner": "system",
                    "sender": settings.sender,
                    "envelope_sender": settings.sender,
                    "host": settings.host,
                    "port": settings.port,
                    "credentials": credentials,
                }
            ]
            if settings.enabled
            else []
        )
    )
    previous = json.loads((base / "state/policy.json").read_text())
    enabled = bool(profiles)
    desired = {
        **previous,
        "enabled": enabled,
        "smarthost": settings.host or "smtp.example.invalid",
        "port": settings.port,
        "clients": [],
        "recipients": sorted(set(recipients if recipients is not None else settings.recipients))
        if enabled
        else [],
    }
    if enabled:
        certificate = notification_directory(config) / "smtp-client.crt"
        output = run(
            ["openssl", "x509", "-in", str(certificate), "-fingerprint", "-sha256", "-noout"]
        ).stdout
        desired["clients"] = [
            {
                "name": "notification",
                "purpose": "Configured CVE notifications",
                "enabled": True,
                "fingerprint": output.strip().split("=", 1)[1],
                "senders": sorted(
                    {p["envelope_sender"] for p in profiles} | {p["sender"] for p in profiles}
                ),
            }
        ]
    mail.validate(desired)
    runtime_path = notification_directory(config) / "runtime.json"
    files = [
        base / name
        for name in [
            "state/policy.json",
            "secrets/smtp_username",
            "secrets/smtp_password",
            "state/upstream-ca.crt",
            "state/smtp-profiles.json",
            "secrets/smtp-profiles.json",
        ]
    ]
    delivery_path = notification_directory(config) / "smtp-delivery.json"
    files += [runtime_path, delivery_path]
    snapshot = {
        p: (p.read_bytes(), p.stat().st_mode & 0o777) if p.exists() else None for p in files
    }
    try:
        replace(base / "state/policy.json", json.dumps(desired).encode())
        for field in ["username", "password"]:
            replace(
                base / "secrets" / ("smtp_" + field),
                ((credentials.get(field) or "not-configured") + "\n").encode(),
            )
        trust = ssl.get_default_verify_paths().cafile
        if not trust:
            raise ValueError("system_trust_unavailable")
        replace(base / "state/upstream-ca.crt", Path(trust).read_bytes(), 0o644)
        public_profiles = [
            {k: v for k, v in p.items() if k not in {"credentials", "listen_port"}}
            for p in profiles
        ]
        replace(base / "state/smtp-profiles.json", json.dumps(public_profiles).encode())
        replace(
            base / "secrets/smtp-profiles.json",
            json.dumps({p["envelope_sender"]: p["credentials"] for p in profiles}).encode(),
        )
        runtime = json.loads(runtime_path.read_text())
        if settings.sender:
            runtime["sender"] = settings.sender
        replace(runtime_path, json.dumps(runtime).encode())
        mail.check_secrets(config)
        reload_postfix(config)
        if mail.container(config)["Id"] != identifier:
            raise ValueError("mail_identity_changed")
        replace(
            delivery_path,
            json.dumps(
                {
                    p["owner"]: {"sender": p["sender"], "envelope_sender": p["envelope_sender"]}
                    for p in profiles
                }
            ).encode(),
        )
    except Exception:
        for path, saved in snapshot.items():
            if saved is None:
                path.unlink(missing_ok=True)
            else:
                replace(path, saved[0], saved[1])
        reload_postfix(config)
        raise


def process(config: Config) -> None:
    from scripts.automation_executor.agent import exclusive

    with exclusive(config):
        from scripts.smtp.certificates import maintain

        # Queued settings survive startup; claim only once the native relay can reload them.
        relay = mail.container(config)
        if (
            not relay["State"]["Running"]
            or relay["State"].get("Health", {}).get("Status") != "healthy"
        ):
            return
        maintain(config)
        with db.connect(config, "dashboard_admin") as s:
            row = s.execute("SELECT automation.claim_smtp() AS id").fetchone()
            if not row or row["id"] is None:
                return
            saved = s.execute(
                "SELECT * FROM automation.smtp_configs WHERE id=%s", (row["id"],)
            ).fetchone()
            assert saved
        error = None
        try:
            ring = SMTPKeyring(config.secrets_base / "services" / config.project / "smtp-keys.json")
            settings, credentials, profiles, recipients = projection(config, saved, ring)
            apply(config, settings, credentials, profiles=profiles, recipients=recipients)
        except Exception as failure:
            logging.getLogger("cve.smtp").warning(
                "smtp_configuration_failed", extra={"error_type": type(failure).__name__}
            )
            error = "SMTP_CONFIGURATION_FAILED"
        with db.connect(config, "dashboard_admin") as s:
            s.execute(
                "SELECT automation.finish_smtp(%s,%s,%s)",
                (saved["id"], saved["lease_token"], error),
            )


def projection(
    config: Config, candidate: dict[str, Any], ring: SMTPKeyring
) -> tuple[SMTPConfig, dict[str, Any], list[dict[str, Any]], list[str]]:
    """Build one coherent projection of applied settings plus the n8n-authorized change."""
    with db.connect(config, "dashboard_admin") as s:
        rows = s.execute(
            "SELECT DISTINCT ON (owner_id) c.* FROM automation.smtp_configs c LEFT "
            "JOIN security.users u ON u.id=c.owner_id WHERE c.state='applied' AND "
            "(c.owner_id IS NULL OR u.status='active') ORDER BY owner_id,version "
            "DESC"
        ).fetchall()
        users = s.execute("SELECT id,email FROM security.users WHERE status='active'").fetchall()
    by_owner = {str(r["owner_id"]) if r["owner_id"] else "system": r for r in rows}
    by_owner[str(candidate["owner_id"]) if candidate["owner_id"] else "system"] = candidate
    system = by_owner.get("system")
    settings = (
        SMTPConfig.model_validate({k: v for k, v in system["configuration"].items() if k != "mode"})
        if system
        else SMTPConfig()
    )
    credentials = (
        ring.decrypt(system["id"], system["key_id"], bytes(system["credentials"])) if system else {}
    )
    recipients = set(settings.recipients)
    profiles = []
    if settings.enabled:
        profiles.append(
            {
                "owner": "system",
                "sender": settings.sender,
                "envelope_sender": "system@cve-routing.invalid",
                "host": settings.host,
                "port": settings.port,
                "credentials": credentials,
            }
        )
    for user in users:
        owner = str(user["id"])
        personal = by_owner.get(owner)
        if personal:
            value = personal["configuration"]
            recipients.update(value["recipients"])
            if value["mode"] == "custom":
                secret = ring.decrypt(
                    personal["id"], personal["key_id"], bytes(personal["credentials"])
                )
                profiles.append(
                    {
                        "owner": owner,
                        "sender": value["sender"],
                        "envelope_sender": "user" + user["id"].hex + "@cve-routing.invalid",
                        "host": value["host"],
                        "port": value["port"],
                        "credentials": secret,
                    }
                )
        elif user["email"]:
            recipients.add(user["email"])
    return settings, credentials, profiles, sorted(recipients)
