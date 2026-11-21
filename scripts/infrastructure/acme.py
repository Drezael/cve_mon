"""Optional Cloudflare DNS-01 lifecycle using the unchanged Certbot plugin image."""

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography import x509

from scripts.infrastructure.manage import Config


def enabled(config: Config) -> bool:
    return config.values.get("LETSENCRYPT_ENABLED") == "true"


def directory(config: Config) -> Path:
    return config.mount_base / "acme" / config.project


def prepare(config: Config) -> None:
    from scripts.infrastructure.mounts import checked, ensure_directory

    base = directory(config)
    credentials = config.secrets_base / "acme-credentials" / config.project
    for path in (
        config.mount_base,
        base.parent,
        base,
        *(base / p for p in ("config", "work", "logs")),
        config.secrets_base,
        credentials.parent,
        credentials,
    ):
        ensure_directory(config, path)
    target = credentials / "cloudflare.ini"
    checked(target)
    temporary = target.with_suffix(".new")
    checked(temporary)
    # Token never appears in the container environment or process arguments.
    with open(
        temporary, "w", opener=lambda path, flags: os.open(path, flags | os.O_NOFOLLOW, 0o600)
    ) as f:
        f.write("dns_cloudflare_api_token = " + config.values["CLOUDFLARE_API_TOKEN"] + "\n")
    temporary.chmod(0o600)
    temporary.replace(target)


def bootstrap(config: Config) -> None:
    """Obtain or recover a certificate before strict production TLS validation."""
    if not enabled(config):
        return
    from scripts.hardening.runtime_images import ensure
    from scripts.infrastructure.images import REFERENCES
    from scripts.infrastructure.manage import compose

    prepare(config)
    ensure(REFERENCES["certbot"])
    folder = Path(config.values["TLS_DIR"])
    certificate = folder / "fullchain.pem"
    key = folder / "privkey.pem"
    if certificate.is_file() and key.is_file():
        try:
            leaf = x509.load_pem_x509_certificate(certificate.read_bytes())
            names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            now = datetime.now(UTC)
            if (
                leaf.not_valid_before_utc <= now
                and leaf.not_valid_after_utc > now + timedelta(days=1)
                and config.values["DASHBOARD_DOMAIN"]
                in names.value.get_values_for_type(x509.DNSName)
            ):
                return
        except (OSError, ValueError, x509.ExtensionNotFound):
            pass
    # Avoid a Certbot state lock collision if recovering an expired lineage.
    compose(config, ["stop", "--timeout", "30", "cve-certbot"])
    print("Let's Encrypt: Zertifikat über Cloudflare DNS-01 ausstellen …", flush=True)
    compose(
        config,
        [
            "run",
            "--rm",
            "--no-deps",
            "--entrypoint",
            "certbot",
            "cve-certbot",
            "certonly",
            "--dns-cloudflare",
            "--dns-cloudflare-credentials",
            "/run/cve-acme/cloudflare.ini",
            "--dns-cloudflare-propagation-seconds",
            "60",
            "--non-interactive",
            "--agree-tos",
            "--email",
            config.values["LETSENCRYPT_EMAIL"],
            "--cert-name",
            "dashboard",
            "-d",
            config.values["DASHBOARD_DOMAIN"],
            "--server",
            "https://acme-v02.api.letsencrypt.org/directory",
            "--preferred-challenges",
            "dns-01",
            "--renew-with-new-domains",
        ],
        timeout=600,
    )


def start(config: Config) -> None:
    if not enabled(config):
        return
    from scripts.infrastructure.manage import compose

    prepare(config)
    compose(
        config,
        ["up", "-d", "--no-deps", "--wait", "--wait-timeout", "120", "cve-certbot"],
        managed=False,
    )


def validate(model: dict[str, Any], mount_base: Path, secrets_base: Path, root: Path) -> list[str]:
    """Reject public ports, socket access, extra networks, and foreign state/credentials."""
    service = model.get("services", {}).get("cve-certbot")
    if service is None:
        return []
    from scripts.infrastructure.images import REFERENCES

    base = mount_base / "acme" / str(model.get("name"))
    expected = {
        "/etc/letsencrypt": str(base / "config"),
        "/var/lib/letsencrypt": str(base / "work"),
        "/var/log/letsencrypt": str(base / "logs"),
        "/opt/cve-acme/renew.py": str(root / "infrastructure/acme/renew.py"),
        "/run/cve-acme": str(secrets_base / "acme-credentials" / str(model.get("name"))),
    }
    mounts = service.get("volumes", [])
    actual = {m["target"]: m.get("source") for m in mounts}
    if (
        service.get("image") != REFERENCES["certbot"]
        or service.get("build")
        or service.get("ports")
        or service.get("privileged")
        or service.get("network_mode")
        or service.get("container_name")
        or not service.get("read_only")
        or service.get("cap_drop") != ["ALL"]
        or service.get("cap_add")
        or service.get("user", "0").split(":")[0] == "0"
        or service.get("entrypoint") != ["python", "/opt/cve-acme/renew.py"]
        or set(service.get("networks", {})) != {"cve_outbound"}
        or not service.get("healthcheck")
        or actual != expected
        or any(
            bool(m.get("read_only")) != (m["target"] in {"/opt/cve-acme/renew.py", "/run/cve-acme"})
            for m in mounts
        )
        or not all(service.get(k) for k in ("mem_limit", "cpus", "pids_limit"))
        or service.get("environment")
        != {
            "ACME_DOMAIN": model["services"]["cve-api"]["environment"][
                "CVE_API_STATUS__DASHBOARD_HOST"
            ],
            "ACME_EMAIL": service.get("environment", {}).get("ACME_EMAIL"),
        }
    ):
        return ["Certbot benötigt das feste abgeschottete DNS-01-Modell ohne Hostports/Socket"]
    return []


def main() -> int:
    import argparse

    from scripts.infrastructure.manage import compose, load_config

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["dry-run"])
    parser.parse_args()
    config = load_config()
    if not enabled(config):
        parser.error("LETSENCRYPT_ENABLED=true erforderlich")
    result = compose(
        config,
        ["exec", "-T", "cve-certbot", "python", "/opt/cve-acme/renew.py", "dry-run"],
        timeout=600,
    )
    print(result.stdout, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
