"""Kleine, projektbezogene Compose-/Nginx-Werkzeuge ohne fremde Ressourcenverwaltung."""

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from scripts.infrastructure.images import REFERENCES
from scripts.infrastructure.policy import CONTAINER_POLICY, EXTERNAL_KEYS, INTERNAL_DEFAULTS

ROOT = Path(__file__).resolve().parents[2]
DOMAINS = ("DASHBOARD_DOMAIN",)
CERT_FILES = (
    "TLS_CERT_FILE",
    "TLS_KEY_FILE",
    "TLS_TRUST_FILE",
    "CLIENT_CA_FILE",
    "CLIENT_CRL_FILE",
)
SECRET_DIRECTORIES = (
    "automation-executor",
    "services",
    "nginx",
    "automation",
    "ansible",
    "inventory-processor",
    "cve-importer",
    "cve-enricher",
    "cve-matcher",
    "cve-findings",
    "notifications",
    "n8n",
    "mail",
    "envoy",
    "database",
    "security",
    "authentication",
    "acme-credentials",
)


@dataclass(frozen=True)
class Config:
    """Geprüfte Konfiguration; keine Auswertung als Shellcode."""

    root: Path
    values: dict[str, str]
    compose_overrides: tuple[Path, ...] = ()
    initialize_secrets: bool = False

    @property
    def manages_credentials(self) -> bool:
        return self.values["APP_ENV"] == "development" or self.initialize_secrets

    @property
    def project(self) -> str:
        return self.values["COMPOSE_PROJECT_NAME"]

    @property
    def external_values(self) -> dict[str, str]:
        return {key: self.values[key] for key in EXTERNAL_KEYS if key in self.values}

    @property
    def mount_base(self) -> Path:
        return (self.root / self.values.get("MOUNT_BASE", "./.runtime")).absolute()

    @property
    def secrets_base(self) -> Path:
        return (self.root / self.values.get("SECRETS_BASE", "./.runtime")).absolute()

    @property
    def directory(self) -> Path:
        return self.secrets_base / "nginx" / self.project

    def runtime_directory(self, name: str) -> Path:
        if name == "database":
            return Path(self.values["PG_WORK_DIR"]) / self.project
        base = self.secrets_base if name in SECRET_DIRECTORIES else self.root / ".runtime"
        return base / name / self.project


def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    """Führe Argumentlisten mit begrenzter Wartezeit aus und unterdrücke keine Fehler."""
    kwargs.setdefault("timeout", 120)
    try:
        return subprocess.run(command, check=True, text=True, capture_output=True, **kwargs)
    except subprocess.CalledProcessError as exc:
        exc.add_note((exc.stderr or "Werkzeug meldet Fehlerstatus ohne weitere Diagnose.")[:4000])
        raise


def load_config(
    env_file: Path | None = None,
    overrides: dict[str, str] | None = None,
    root: Path = ROOT,
) -> Config:
    """Lade einfache KEY=value-Dateien; unbekannte oder gefährliche Werte ablehnen."""
    env_file = env_file or (
        Path(os.environ["CVE_ENV_FILE"]) if os.environ.get("CVE_ENV_FILE") else None
    )
    path = env_file or (root / ".env" if (root / ".env").exists() else root / ".env.example")
    values: dict[str, str] = {}
    allowed = EXTERNAL_KEYS
    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if key in INTERNAL_DEFAULTS or key in {"PG_WORK_DIR", "NGINX_UID", "NGINX_GID"}:
            raise ValueError(f"Interne Architekturvariable ist in .env nicht erlaubt: {key}")
        if not separator or key not in allowed or key in values:
            raise ValueError(f"Ungültige/mehrfache Variable in {path.name}: {key}")
        values[key] = value
    for key in allowed:
        if key in os.environ:
            values[key] = os.environ[key]
    if overrides and (unknown := set(overrides) - allowed):
        raise ValueError(
            "Nur externe Konfiguration darf überschrieben werden: " + ", ".join(sorted(unknown))
        )
    values.update(overrides or {})
    for key, default in {
        "LETSENCRYPT_ENABLED": "false",
        "LETSENCRYPT_EMAIL": "",
        "CLOUDFLARE_API_TOKEN": "",
        "LETSENCRYPT_AGREE_TOS": "false",
    }.items():
        values.setdefault(key, default)
    for key in ("LETSENCRYPT_ENABLED", "LETSENCRYPT_AGREE_TOS"):
        if values[key] not in {"true", "false"}:
            raise ValueError(key + " muss true oder false sein")
    if values["LETSENCRYPT_ENABLED"] == "true":
        if values["APP_ENV"] != "production":
            raise ValueError("Automatisches Let's Encrypt ist nur in production erlaubt")
        if values["LETSENCRYPT_AGREE_TOS"] != "true":
            raise ValueError("Let's Encrypt benötigt LETSENCRYPT_AGREE_TOS=true")
        if not re.fullmatch(
            r"[a-zA-Z0-9_.+%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}", values["LETSENCRYPT_EMAIL"]
        ):
            raise ValueError("LETSENCRYPT_EMAIL benötigt eine gültige Kontaktadresse")
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{20,512}", values["CLOUDFLARE_API_TOKEN"]):
            raise ValueError("CLOUDFLARE_API_TOKEN benötigt einen gültigen eingeschränkten Token")
        values["TLS_DIR"] = str(
            (root / values.get("MOUNT_BASE", "./.runtime")).absolute()
            / "acme"
            / values["COMPOSE_PROJECT_NAME"]
            / "config/live/dashboard"
        )
    values.update(INTERNAL_DEFAULTS)
    # Host identities are derived from the operator, never read from configuration or the shell.
    values["NGINX_UID"] = str(os.getuid())
    values["NGINX_GID"] = str(os.getgid())
    values.setdefault("MOUNT_BASE", "./.runtime")
    values.setdefault("SECRETS_BASE", "./.runtime")
    mount_base = Path(values["MOUNT_BASE"])
    if (
        not re.fullmatch(r"[a-zA-Z0-9_./-]+", values["MOUNT_BASE"])
        or ".." in mount_base.parts
        or (root / mount_base).absolute() == Path("/")
    ):
        raise ValueError("MOUNT_BASE muss ein eigenes Verzeichnis ohne Pfadtraversierung sein")
    secrets_base = Path(values["SECRETS_BASE"])
    if (
        not re.fullmatch(r"[a-zA-Z0-9_./-]+", values["SECRETS_BASE"])
        or ".." in secrets_base.parts
        or (root / secrets_base).absolute() == Path("/")
    ):
        raise ValueError("SECRETS_BASE muss ein eigenes Verzeichnis ohne Pfadtraversierung sein")
    if values.get("PG_WORK_DIR", "./.runtime/database") == "./.runtime/database":
        values["PG_WORK_DIR"] = str(secrets_base / "database")
    values.setdefault("TLS_DIR", "./.runtime/development/pki")
    if (
        not re.fullmatch(r"[a-zA-Z0-9_./-]+", values["TLS_DIR"])
        or ".." in Path(values["TLS_DIR"]).parts
    ):
        raise ValueError("TLS_DIR muss ein Zertifikatsverzeichnis ohne Pfadtraversierung sein")
    directory = Path(values["TLS_DIR"])
    if values["TLS_DIR"].startswith("./.runtime/"):
        directory = secrets_base / values["TLS_DIR"].removeprefix("./.runtime/")
    directory = (root / directory).absolute()
    if directory == Path("/"):
        raise ValueError("TLS_DIR muss ein eigenes Zertifikatsverzeichnis sein")
    values["TLS_DIR"] = str(directory)
    import ssl

    try:
        custom_trust = (directory / "ca.crt").is_file()
    except OSError:
        custom_trust = False
    internal_ca = (
        directory
        if values["APP_ENV"] == "development"
        else (root / secrets_base / "tls" / values["COMPOSE_PROJECT_NAME"])
    )
    values.update(
        {
            "TLS_CERT_FILE": str(directory / "fullchain.pem"),
            "TLS_KEY_FILE": str(directory / "privkey.pem"),
            "TLS_TRUST_FILE": str(directory / "ca.crt")
            if custom_trust
            else str(
                Path(
                    ssl.get_default_verify_paths().cafile or "/etc/ssl/certs/ca-certificates.crt"
                ).resolve()
            ),
            "CLIENT_CA_FILE": str(internal_ca / "client-ca.crt"),
            "CLIENT_CRL_FILE": str(internal_ca / "client-ca.crl"),
        }
    )
    values["DEFAULT_LANGUAGE"] = values.get("DEFAULT_LANGUAGE") or "en"
    smtp_defaults = {
        "SMTP_HOST": "",
        "SMTP_PORT": "587",
        "SMTP_SENDER": "",
        "SMTP_USERNAME": "",
        "SMTP_PASSWORD": "",
    }
    for name, default in smtp_defaults.items():
        values.setdefault(name, default)
    public_port = values.get("INGRESS_HTTPS_PORT", "443")
    values["DASHBOARD_ORIGIN"] = (
        "https://"
        + values.get("DASHBOARD_DOMAIN", "")
        + ("" if public_port == "443" else ":" + public_port)
    )
    effective_keys = (
        allowed
        | set(INTERNAL_DEFAULTS)
        | {"PG_WORK_DIR", "NGINX_UID", "NGINX_GID", "DASHBOARD_ORIGIN", *CERT_FILES}
    )
    if set(values) != effective_keys or any(
        not value
        for name, value in values.items()
        if name not in {*smtp_defaults, "LETSENCRYPT_EMAIL", "CLOUDFLARE_API_TOKEN"}
    ):
        raise ValueError(
            "Pflichtvariablen fehlen oder sind leer: " + ", ".join(sorted(allowed - set(values)))
        )
    if values["APP_ENV"] not in {"development", "production"}:
        raise ValueError("APP_ENV muss development oder production sein")
    if values["LOG_LEVEL"] not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
        raise ValueError("LOG_LEVEL ist ungültig")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,60}", values["COMPOSE_PROJECT_NAME"]):
        raise ValueError("COMPOSE_PROJECT_NAME ist ungültig")
    for key in DOMAINS:
        if not re.fullmatch(
            r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", values[key]
        ):
            raise ValueError(f"Ungültiger Domainname: {key}")
    address = ipaddress.ip_address(values["INGRESS_BIND_IP"])
    if address.version != 4:
        raise ValueError("IPv6-Publishing erst nach gleichwertigem Firewall-Nachweis freigeben")
    if values["APP_ENV"] == "development" and not address.is_loopback:
        raise ValueError("Entwicklungsports müssen an Loopback gebunden sein")
    for key in (
        "INGRESS_HTTP_PORT",
        "INGRESS_HTTPS_PORT",
        "MAILHOG_HTTP_PORT",
        "NGINX_UID",
        "NGINX_GID",
        "RATE_BURST",
    ):
        if not values[key].isdigit() or not 1 <= int(values[key]) <= 65535:
            raise ValueError(f"Ungültiger positiver Zahlenwert: {key}")
    if (
        len(
            {values["INGRESS_HTTP_PORT"], values["INGRESS_HTTPS_PORT"], values["MAILHOG_HTTP_PORT"]}
        )
        != 3
    ):
        raise ValueError("HTTP, HTTPS und MailHog benötigen unterschiedliche Ports")
    for key in ("WEB_RATE", "UPLOAD_RATE"):
        if not re.fullmatch(r"[1-9][0-9]{0,3}r/[sm]", values[key]):
            raise ValueError(f"Ungültiges Rate-Limit: {key}")
    for key in ("MAX_BODY_SIZE", "DASHBOARD_MAX_BODY_SIZE"):
        if not re.fullmatch(r"[1-9][0-9]{0,2}m", values[key]):
            raise ValueError(f"Ungültige Größenbegrenzung: {key}")
    if not re.fullmatch(r"[1-9][0-9]?s", values["CLIENT_TIMEOUT"]):
        raise ValueError("CLIENT_TIMEOUT muss 1–99 Sekunden betragen")
    for key in CERT_FILES:
        if values[key].startswith("./.runtime/development/pki/"):
            values[key] = str(secrets_base / values[key].removeprefix("./.runtime/"))
        if not re.fullmatch(r"[a-zA-Z0-9_./-]+", values[key]):
            raise ValueError(f"Ungültiger Zertifikatspfad: {key}")
        values[key] = str((root / values[key]).absolute())
    if not re.fullmatch(r"[a-zA-Z0-9_./-]+", values["PG_WORK_DIR"]):
        raise ValueError("PG_WORK_DIR ist ungültig")
    values["PG_WORK_DIR"] = str((root / values["PG_WORK_DIR"]).resolve())
    if (
        not values["PG_CONNECT_TIMEOUT"].isdigit()
        or not 1 <= int(values["PG_CONNECT_TIMEOUT"]) <= 30
    ):
        raise ValueError("PG_CONNECT_TIMEOUT muss 1–30 sein")
    return Config(root, values)


def docker_command(daemon: bool = True) -> list[str]:
    """sudo nur bei explizitem CVE_DOCKER_SUDO=1; keine Gruppen-/Hoständerung."""
    if daemon and os.environ.get("CVE_DOCKER_SUDO") == "1":
        return ["sudo", "-n", "docker"]
    return ["docker"]


def compose(
    config: Config,
    arguments: list[str],
    daemon: bool = True,
    *,
    managed: bool = True,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    """Wähle ausschließlich die festen Compose-Dateien und das geprüfte Projekt."""
    from scripts.infrastructure.topology import GROUPS
    from scripts.infrastructure.topology import arguments as selectors

    arguments = selectors(arguments)
    if daemon and arguments and arguments[0] == "up":
        from scripts.infrastructure.mounts import prepare as prepare_mounts
        from scripts.infrastructure.secrets import prepare as prepare_secrets

        prepare_secrets(config)
        prepare_mounts(config)
        from scripts.infrastructure.storage import STORES, prepare

        services = list({item[1] for item in STORES.values()})
        selected_services = [s for s in services if s in arguments]
        if not any(a.startswith("cve-") for a in arguments):
            selected_services = services
        prepare(config, selected_services)
    if daemon and managed and arguments and arguments[0] == "up":
        from scripts.application.manage import start as start_group

        selected = [
            g
            for g in GROUPS
            if g != "cve-api"
            and (g in arguments or not any(a.startswith("cve-") for a in arguments))
        ]
        for group in selected:
            start_group(config, group, force="--force-recreate" in arguments)
        if selected:
            arguments = [a for a in arguments if a != "--force-recreate"]
    if daemon and arguments and arguments[0] == "up" and not config.compose_overrides:
        from scripts.hardening.runtime_images import build

        for service, runtime in {
            "cve-nginx": "nginx",
            "cve-postgres": "postgres",
            "cve-mail-relay": "mail",
            "cve-n8n": "n8n",
            "cve-mailhog": "mailhog",
        }.items():
            if service in arguments:
                build(config, runtime)
    if (
        daemon
        and arguments
        and arguments[0] == "up"
        and ("cve-postgres" in arguments or not any(a.startswith("cve-") for a in arguments))
    ):
        from scripts.database.tls import prepare_bind

        prepare_bind(config)
    prefix = docker_command(daemon)
    if prefix[0] == "sudo":
        # sudo entfernt standardmäßig Compose-Interpolationswerte. Ausschließlich
        # diese bereits geprüften Nicht-Secret-Werte explizit erhalten.
        prefix = ["sudo", "-n", "--preserve-env=" + ",".join(sorted(config.values)), "docker"]
    command = [
        *prefix,
        "compose",
        *(
            ["--profile", "mail-test"]
            if config.root / "infrastructure/compose/mail-test.yml" in config.compose_overrides
            else []
        ),
        "--project-name",
        config.project,
        "-f",
        str(config.root / "compose.yml"),
    ]
    if config.values["APP_ENV"] == "development":
        command += ["-f", str(config.root / "infrastructure/compose/development.yml")]
    if config.values.get("LETSENCRYPT_ENABLED") == "true":
        command += ["-f", str(config.root / "infrastructure/compose/letsencrypt.yml")]
    for override in config.compose_overrides:
        command += ["-f", str(override)]
    return run(
        command + arguments, cwd=config.root, env={**os.environ, **config.values}, timeout=timeout
    )


def service_image(config: Config, service: str, default: str) -> str:
    """A release overlay selects immutable images without relaxing namespace checks."""
    if config.compose_overrides:
        return str(resolved(config)["services"][service]["image"])
    return default


def resolved(config: Config) -> dict[str, Any]:
    """Compose-Auflösung benötigt keinen Daemon und keine Schlüsseldateien."""
    value = json.loads(compose(config, ["config", "--format", "json"], daemon=False).stdout)
    if not isinstance(value, dict):
        raise ValueError("Compose liefert keine Objektkonfiguration")
    return value


def network_definitions(config: Config) -> dict[str, Any]:
    """Compose entfernt ungenutzte Netze; ein config-only Override hält sie zur Prüfung."""
    result = compose(
        config,
        [
            "-f",
            str(config.root / "tests/infrastructure/fixtures/compose.network-audit.yml"),
            "config",
            "--format",
            "json",
        ],
        daemon=False,
    )
    value = json.loads(result.stdout)["networks"]
    if not isinstance(value, dict):
        raise ValueError("Compose-Netzwerke müssen ein Objekt sein")
    return value


def validate_networks(
    networks: dict[str, Any],
    complete: bool = True,
    project: str | None = None,
) -> list[str]:
    """Prüfe kanonische Netze einschließlich der noch ungenutzten zukünftigen Zonen."""
    expected = {
        "cve_ingress": False,
        "cve_internal": True,
        "cve_data": True,
        "cve_outbound": False,
        "cve_ssh": False,
    }
    errors: list[str] = []
    if complete and set(networks) != set(expected):
        errors.append("Fünf definierte Netzwerke erforderlich")
    for name, item in networks.items():
        if project and item.get("name") != f"{project}_{name}":
            errors.append(f"Globaler oder fremder Netzwerkname: {name}")
        if (
            name not in expected
            or item.get("driver") != "bridge"
            or bool(item.get("internal", False)) != expected.get(name)
        ):
            errors.append(f"Falsche Netzwerkzone: {name}")
        if item.get("external") or item.get("ipam") or item.get("enable_ipv6"):
            errors.append(f"Unzulässige globale/externe/IPv6-Netzdefinition: {name}")
    return errors


def validate_model(
    model: dict[str, Any],
    development: bool,
    root: Path = ROOT,
    *,
    mount_base: Path | None = None,
    secrets_base: Path | None = None,
) -> list[str]:
    """Prüfe aufgelöste Konfiguration statt YAML-Zeichenfolgen."""
    errors: list[str] = []
    for name, expected in CONTAINER_POLICY.items():
        environment = model.get("services", {}).get(name, {}).get("environment", {})
        for key, value in expected.items():
            if environment.get(key) != value:
                errors.append(name + ": feste interne Architekturvariable geändert: " + key)
    mount_base = mount_base or load_config(root=root).mount_base
    secrets_base = secrets_base or load_config(root=root).secrets_base
    infrastructure = root / "infrastructure"
    if model.get("volumes") or any(
        mount.get("type") != "bind"
        for service in model.get("services", {}).values()
        for mount in service.get("volumes", [])
    ):
        errors.append("All persistent service mounts must be explicit bind mounts")
    for service in model.get("services", {}).values():
        for mount in service.get("volumes", []):
            if (
                mount.get("type") == "bind"
                and not mount.get("read_only")
                and not Path(mount.get("source", "")).is_relative_to(mount_base)
            ):
                errors.append("Beschreibbarer Bind-Mount liegt außerhalb von MOUNT_BASE")
    for secret in model.get("secrets", {}).values():
        if "file" in secret and not Path(secret["file"]).is_relative_to(secrets_base):
            errors.append("Read-only Secret-Mount liegt außerhalb von SECRETS_BASE")
    errors.extend(
        validate_networks(model.get("networks", {}), complete=False, project=model.get("name"))
    )
    from cve_common.deployment import APPLICATION_IMAGE, SERVICES

    if set(model.get("services", {})) - {"cve-mailhog", "cve-certbot"} != set(SERVICES):
        return ["Seven physical services (three application groups) required"]
    vendors = {
        "cve-nginx": "nginx",
        "cve-postgres": "postgres",
        "cve-mail-relay": "mail",
        "cve-n8n": "n8n",
        "cve-mailhog": "mailhog",
    }
    for service, vendor in vendors.items():
        if service not in model["services"]:
            continue
        definition = model["services"][service]
        if (
            definition.get("image") != REFERENCES[vendor]
            or definition.get("build")
            or (definition.get("entrypoint") and service != "cve-n8n")
        ):
            errors.append(
                service + ": unverändertes Originalimage mit Hersteller-Entrypoint erforderlich"
            )
    for name, candidate in model["services"].items():
        # Uniform guard also covers bootstrap services with narrowly approved capabilities.
        if candidate.get("security_opt") != ["no-new-privileges:true"]:
            errors.append(f"{name}: ausschließlich No New Privileges und Docker-Seccomp-Default")
        if any(candidate.get(k) for k in ("devices", "device_cgroup_rules", "gpus")):
            errors.append(f"{name}: keine Hostgeräte oder Gerätegrants")
        if any(candidate.get(k) == "host" for k in ("pid", "ipc", "uts", "cgroup")):
            errors.append(f"{name}: keine Host-Prozess-/IPC-/UTS-/Cgroup-Namespaces")
    if "cve-mailhog" in model["services"]:
        if model["services"]["cve-mailhog"].get("profiles") != ["mail-test"]:
            errors.append("MailHog darf ausschließlich im optionalen mail-test-Profil laufen")
        capture = model["services"]["cve-mailhog"]
        if (
            set(capture.get("networks", {})) != {"cve_outbound"}
            or capture.get("privileged")
            or capture.get("network_mode")
            or capture.get("container_name")
            or not capture.get("read_only")
            or capture.get("cap_drop") != ["ALL"]
            or capture.get("cap_add")
            or capture.get("user") != "1000:1000"
            or not capture.get("healthcheck")
        ):
            errors.append("MailHog requires a confined original image on the outbound bridge")
        capture_ports = capture.get("ports", [])
        if len(capture_ports) != 1 or any(
            p.get("target") != 8025 or p.get("host_ip") != "127.0.0.1" for p in capture_ports
        ):
            errors.append("MailHog UI must be published only on IPv4 loopback")
        if capture.get("environment") != {
            "MH_STORAGE": "maildir",
            "MH_MAILDIR_PATH": "/home/mailhog/maildir",
        }:
            errors.append("MailHog must retain captured messages in its own bind mount")
        capture_mounts = capture.get("volumes", [])
        if (
            len(capture_mounts) != 1
            or capture_mounts[0].get("type") != "bind"
            or capture_mounts[0].get("source")
            != str(mount_base / "storage" / str(model.get("name")) / "mailhog")
            or capture_mounts[0].get("read_only")
            or capture_mounts[0].get("target") != "/home/mailhog"
        ):
            errors.append("MailHog requires only its dedicated persistent mail bind mount")
    from scripts.infrastructure.acme import validate as validate_acme

    errors.extend(validate_acme(model, mount_base, secrets_base, root))
    service = model["services"]["cve-nginx"]
    if set(service.get("networks", {})) != {"cve_ingress", "cve_internal"}:
        errors.append("Nginx ist falschen Netzwerken zugeordnet")
    if service.get("privileged") or service.get("network_mode") or service.get("container_name"):
        errors.append("Privilegierter/Host-/global benannter Container verboten")
    if service.get("cap_add") or service.get("cap_drop") != ["ALL"] or not service.get("read_only"):
        errors.append("Read-only und cap_drop ALL erforderlich")
    if service.get("security_opt") != ["no-new-privileges:true"]:
        errors.append("no-new-privileges erforderlich")
    if service.get("user", "0").split(":")[0] == "0":
        errors.append("Nginx muss ohne Root laufen")
    ports = service.get("ports", [])
    if len(ports) != 2 or {port["target"] for port in ports} != {8080, 8443}:
        errors.append("Nur HTTP/HTTPS dürfen veröffentlicht sein")
    for port in ports:
        if development and not ipaddress.ip_address(port.get("host_ip", "0.0.0.0")).is_loopback:
            errors.append("Entwicklungsport ist öffentlich")
    for volume in service.get("volumes", []):
        if (
            not volume.get("read_only")
            or "docker.sock" in str(volume)
            or volume.get("target") in {"/", "/var/run"}
        ):
            errors.append("Unzulässiger beschreibbarer/Host-/Socket-Mount")
    expected_mounts = {
        "/etc/nginx/nginx.conf": str(infrastructure / "nginx/nginx.conf"),
        "/etc/nginx/cve": str(secrets_base / "nginx" / str(model.get("name"))),
    }
    mounts = {volume["target"]: volume.get("source") for volume in service.get("volumes", [])}
    if mounts != expected_mounts:
        errors.append("Nur explizite Projekt-Konfigurations- und ACME-Mounts sind erlaubt")
    if not service.get("mem_limit") or not service.get("cpus") or not service.get("pids_limit"):
        errors.append("Speicher-, CPU- und Prozesslimits erforderlich")
    if service.get("image") != REFERENCES["nginx"]:
        errors.append("Image muss unveränderlich gepinnt sein")
    pg = model["services"]["cve-postgres"]
    if set(pg.get("networks", {})) != {"cve_data"} or pg.get("ports"):
        errors.append("PostgreSQL darf nur ins Datenbanknetz und keinen Hostport veröffentlichen")
    if pg.get("privileged") or pg.get("network_mode") or not pg.get("read_only"):
        errors.append("Unsicherer PostgreSQL-Betriebsmodus")
    if set(pg.get("cap_add", [])) != {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID"}:
        errors.append("PostgreSQL-Bootstrap-Capabilities weichen ab")
    volumes = pg.get("volumes", [])
    data = [v for v in volumes if v["target"] == "/var/lib/postgresql"]
    storage = mount_base / "storage" / str(model.get("name"))
    if (
        len(data) != 1
        or data[0].get("type") != "bind"
        or data[0].get("source") != str(storage / "postgres-data")
        or data[0].get("read_only")
    ):
        errors.append("PostgreSQL 18 benötigt den privaten Daten-Bind-Mount am Elternpfad")
    tls = [v for v in volumes if v["target"] == "/var/run/postgresql/tls"]
    if (
        len(tls) != 1
        or tls[0].get("source")
        != str(secrets_base / "storage" / str(model.get("name")) / "postgres-tls")
        or not tls[0].get("read_only")
    ):
        errors.append("PostgreSQL benötigt den privaten read-only TLS-Bind-Mount")
    if any(
        v.get("type") == "bind"
        and not v.get("read_only")
        and v.get("target") != "/var/lib/postgresql"
        for v in volumes
    ):
        errors.append("PostgreSQL-Konfiguration/Secrets müssen read-only sein")
    if "docker.sock" in str(volumes) or "POSTGRES_PASSWORD" in pg.get("environment", {}):
        errors.append("Socket/Klartextkennwort im Datenbankmodell verboten")
    mail = model["services"]["cve-mail-relay"]
    if set(mail.get("networks", {})) != {"cve_internal", "cve_outbound"}:
        errors.append("Postfix benötigt internes SMTP und direktes Ausgangsnetz")
    if (
        mail.get("ports")
        or mail.get("privileged")
        or mail.get("network_mode")
        or mail.get("container_name")
    ):
        errors.append("Postfix darf keine Hostports oder privilegierten/Hostbetrieb besitzen")
    if (
        mail.get("user") != "0:0"
        or not mail.get("read_only")
        or set(mail.get("cap_drop", [])) != {"ALL"}
        or set(mail.get("cap_add", []))
        != {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID", "KILL"}
        or mail.get("security_opt") != ["no-new-privileges:true"]
    ):
        errors.append("Postfix-Master benötigt exakt die begrenzten nativen Prozessrechte")
    if mail.get("environment") != {
        "LOG_FORMAT": "json",
        "ANONYMIZE_EMAILS": "0",
        "ALLOWED_SENDER_DOMAINS": "example.invalid",
        "HOSTNAME": "cve-mail-relay",
    } or mail.get("secrets"):
        errors.append("Postfix-Secrets ausschließlich über private Dateien")
    expected_mail = {
        "/etc/rsyslog.conf": str(infrastructure / "mail/rsyslog.conf"),
        "/opt/cve-mail": str(infrastructure / "mail"),
        "/docker-init.d/90-cve-configuration.sh": str(infrastructure / "mail/init.sh"),
        "/var/spool/postfix": str(storage / "postfix-queue"),
        "/opt/cve-status/postfix.py": str(infrastructure / "status/postfix.py"),
        "/opt/cve-status/postfix.sh": str(infrastructure / "status/postfix.sh"),
        "/run/cve-status/postfix": str(mount_base / "status" / str(model.get("name")) / "postfix"),
        "/mail-state": str(secrets_base / "mail" / str(model.get("name")) / "state"),
        "/mail-secrets": str(secrets_base / "mail" / str(model.get("name")) / "secrets"),
    }
    if {v.get("target"): v.get("source") for v in mail.get("volumes", [])} != expected_mail:
        errors.append("Postfix besitzt unerlaubte Mounts")
    for v in mail.get("volumes", []):
        if (
            v.get("type") == "bind"
            and not v.get("read_only")
            and v.get("target") not in {"/run/cve-status/postfix", "/var/spool/postfix"}
        ):
            errors.append("Postfix-Konfiguration/Secrets müssen read-only sein")
    if mail.get("image") != REFERENCES["mail"]:
        errors.append("Postfix-Version muss dem geprüften Paket-Lock entsprechen")
    if not all(mail.get(k) for k in ("mem_limit", "pids_limit", "cpus", "ulimits", "healthcheck")):
        errors.append("Postfix-Limits/Healthcheck fehlen")
    api = model["services"]["cve-api"]
    if set(api.get("networks", {})) != {"cve_internal", "cve_data"}:
        errors.append("API darf ausschließlich in interne und Datenbankzone")
    if (
        api.get("ports")
        or api.get("privileged")
        or api.get("network_mode")
        or api.get("container_name")
    ):
        errors.append("API ohne Hostports oder privilegierten/Hostbetrieb")
    if (
        not api.get("read_only")
        or api.get("cap_add")
        or api.get("cap_drop") != ["ALL"]
        or api.get("security_opt") != ["no-new-privileges:true"]
        or api.get("user", "0").split(":")[0] == "0"
    ):
        errors.append("API benötigt Nicht-Root, read-only, keine Capabilities")
    api_mounts = api.get("volumes", [])
    expected_api_mounts = {
        "/run/cve-api": (str(secrets_base / "services" / str(model.get("name"))), True),
        "/run/cve-status": (str(root / ".runtime/status" / str(model.get("name"))), True),
        "/run/cve-status/postfix": (
            str(mount_base / "status" / str(model.get("name")) / "postfix"),
            True,
        ),
    }
    if {
        m.get("target"): (m.get("source"), bool(m.get("read_only"))) for m in api_mounts
    } != expected_api_mounts:
        errors.append("API requires only own credentials and read-only aggregate observations")
    if (
        api.get("environment", {}).get("CVE_APPLICATION_PROFILE") != "api"
        or api.get("environment", {}).get("CVE_API_HTTP_PORT") != "8000"
        or api.get("entrypoint")
        or api.get("command")
    ):
        errors.append("API requires its isolated application profile and fixed endpoint")
    expected_environment = {
        "CVE_DEFAULT_LANGUAGE",
        "CVE_SMTP_HOST",
        "CVE_SMTP_PORT",
        "CVE_SMTP_SENDER",
        "CVE_SMTP_USERNAME",
        "CVE_SMTP_PASSWORD",
        "CVE_APPLICATION_PROFILE",
        "CVE_API_HTTP_PORT",
        "CVE_API_STATUS__PAUSED",
        "CVE_API_STATUS__APP_ENV",
        "CVE_API_STATUS__DATABASE__HOST",
        "CVE_API_STATUS__DATABASE__USERNAME",
        "CVE_API_STATUS__DATABASE__PASSWORD_FILE",
        "CVE_API_STATUS__DATABASE__CA_FILE",
        "CVE_API_STATUS__REPORTS_DIR",
        "CVE_API_STATUS__DASHBOARD_CA",
        "CVE_API_STATUS__NOTIFICATION_CA",
        "CVE_API_STATUS__DASHBOARD_HOST",
        "CVE_API_STATUS__PROBE_KEY_FILE",
        "CVE_API_APP_ENV",
        "CVE_API_LOG_LEVEL",
        "CVE_API_DATABASE__HOST",
        "CVE_API_DATABASE__USERNAME",
        "CVE_API_DATABASE__PASSWORD_FILE",
        "CVE_API_DATABASE__CA_FILE",
        "CVE_API_ALLOWED_HOSTS",
        "CVE_API_AUTH__DATABASE__HOST",
        "CVE_API_AUTH__DATABASE__USERNAME",
        "CVE_API_AUTH__DATABASE__PASSWORD_FILE",
        "CVE_API_AUTH__DATABASE__CA_FILE",
        "CVE_API_AUTH__ADMINISTRATION_DATABASE__HOST",
        "CVE_API_AUTH__ADMINISTRATION_DATABASE__USERNAME",
        "CVE_API_AUTH__ADMINISTRATION_DATABASE__PASSWORD_FILE",
        "CVE_API_AUTH__ADMINISTRATION_DATABASE__CA_FILE",
        "CVE_API_INVENTORY__DATABASE__HOST",
        "CVE_API_INVENTORY__DATABASE__USERNAME",
        "CVE_API_INVENTORY__DATABASE__PASSWORD_FILE",
        "CVE_API_INVENTORY__DATABASE__CA_FILE",
        "CVE_API_INVENTORY__DATABASE__POOL_SIZE",
        "CVE_API_INVENTORY__DATABASE__STATEMENT_TIMEOUT_MS",
        "CVE_API_INVENTORY__ORIGIN",
        "CVE_API_INVENTORY__GATEWAY_FILE",
        "CVE_API_INVENTORY__TOKEN_KEY_FILE",
        "CVE_API_INVENTORY__CLIENT_CA_FILE",
        "CVE_API_INVENTORY__CLIENT_CRL_FILE",
        "CVE_API_INVENTORY__MAX_BYTES",
        "CVE_API_AUTH__ORIGIN",
        "CVE_API_AUTH__KEYRING_FILE",
        "CVE_API_AUTH__GATEWAY_FILE",
        "CVE_API_AUTH__ARGON_MEMORY",
        "CVE_API_AUTH__ARGON_CONCURRENCY",
        "CVE_API_AUTH__LOGIN_LIMIT",
        "CVE_API_AUTH__IP_LIMIT",
    }
    if (
        set(api.get("environment", {})) != expected_environment
        or api["environment"].get("CVE_API_STATUS__DATABASE__USERNAME") != "status_probe"
        or api["environment"].get("CVE_API_DATABASE__USERNAME") != "api_reader"
        or api["environment"].get("CVE_API_AUTH__DATABASE__USERNAME") != "api_security"
        or api["environment"].get("CVE_API_AUTH__ADMINISTRATION_DATABASE__USERNAME")
        != "dashboard_admin"
        or api["environment"].get("CVE_API_INVENTORY__DATABASE__USERNAME") != "api_ingest"
    ):
        errors.append(
            "API benötigt getrennte Reader-/Security-/Administrationskontexte ohne Klartext-Secrets"
        )
    if api.get("image") != APPLICATION_IMAGE or not all(
        api.get(k) for k in ("healthcheck", "mem_limit", "cpus", "pids_limit", "ulimits")
    ):
        errors.append("API-Version und Ressourcenlimits erforderlich")
    from scripts.application.validation import validate as validate_groups

    errors.extend(validate_groups(model, root, mount_base=mount_base, secrets_base=secrets_base))
    n8n = model["services"]["cve-n8n"]
    if (
        set(n8n.get("networks", {})) != {"cve_internal", "cve_data", "cve_outbound"}
        or n8n.get("ports")
        or n8n.get("privileged")
        or n8n.get("network_mode")
        or n8n.get("cap_add")
        or not n8n.get("read_only")
        or n8n.get("cap_drop") != ["ALL"]
        or n8n.get("user", "0").split(":")[0] in {"0", "root"}
    ):
        errors.append("n8n requires its bounded private unprivileged container")
    expected_n8n = {
        "/opt/cve-n8n": (str(root / "infrastructure/n8n"), True),
        "/opt/cve-workflows": (str(root / "workflows/n8n"), True),
        "/run/cve-n8n": (str(secrets_base / "n8n" / str(model["name"]) / "config"), True),
        "/home/node/.n8n": (str(mount_base / "n8n" / str(model["name"]) / "data"), False),
    }
    if {
        m.get("target"): (m.get("source"), bool(m.get("read_only"))) for m in n8n.get("volumes", [])
    } != expected_n8n:
        errors.append(
            "n8n requires read-only repository bootstrap/workflows and private data mounts"
        )
    if n8n.get("entrypoint") != ["/bin/sh", "/opt/cve-n8n/start.sh"] or n8n.get("command"):
        errors.append("n8n requires its fixed workflow bootstrap before the vendor entrypoint")
    n8n = model["services"]["cve-n8n"]
    env = n8n.get("environment", {})
    if (
        env.get("EXECUTIONS_MODE") != "regular"
        or env.get("DB_TYPE") != "postgresdb"
        or env.get("DB_POSTGRESDB_DATABASE") != "n8n"
        or env.get("DB_POSTGRESDB_USER") != "n8n_app"
        or env.get("EXECUTIONS_DATA_PRUNE") != "true"
        or env.get("N8N_BLOCK_ENV_ACCESS_IN_NODE") != "true"
        or n8n.get("image") != REFERENCES["n8n"]
        or any("REDIS" in k for k in env)
        or any(k in env for k in ["DB_POSTGRESDB_PASSWORD", "N8N_ENCRYPTION_KEY"])
    ):
        errors.append("n8n requires pinned regular PostgreSQL mode and bounded private execution")
    return errors


def validate_compose_files(root: Path = ROOT) -> list[str]:
    """Prüfe Entwicklungs- und Produktivmodell ohne Docker-Daemon oder Secrets."""
    errors: list[str] = []
    for environment in ("development", "production"):
        config = load_config(
            root / ".env.example",
            overrides={
                "APP_ENV": environment,
                "COMPOSE_PROJECT_NAME": "cve-check-" + environment,
                "INGRESS_BIND_IP": "127.0.0.1" if environment == "development" else "0.0.0.0",
            },
            root=root,
        )
        errors.extend(
            validate_model(
                resolved(config),
                environment == "development",
                root,
                mount_base=config.mount_base,
                secrets_base=config.secrets_base,
            )
        )
        errors.extend(validate_networks(network_definitions(config), project=config.project))
    return errors


def certificate_preflight(config: Config) -> None:
    """Prüfe Kette, Namen, Ablauf, Schlüsselpaar und private Dateirechte."""
    from cve_api.inventories.errors import UploadError
    from cve_api.technical_auth.certificates import crl

    from scripts.infrastructure.tls import prepare as prepare_tls
    from scripts.inventory.configuration import development_crl

    prepare_tls(config)
    try:
        development_crl(config)
        crl(Path(config.values["CLIENT_CRL_FILE"]), Path(config.values["CLIENT_CA_FILE"]))
    except UploadError:
        raise ValueError("Valid client CA and CRL required") from None
    v = config.values
    for key in CERT_FILES:
        if not Path(v[key]).is_file():
            raise ValueError(f"Zertifikatsdatei fehlt: {key}; Entwicklungszertifikate erzeugen")
    if Path(v["TLS_KEY_FILE"]).stat().st_mode & 0o077:
        raise ValueError("TLS-Schlüssel darf nur für seinen Eigentümer lesbar sein")
    if int(v["NGINX_UID"]) != os.getuid():
        raise ValueError("NGINX_UID muss zum Benutzer der gerenderten Dateien passen")
    for key in ("TLS_CERT_FILE", "CLIENT_CA_FILE", "TLS_TRUST_FILE"):
        run(["openssl", "x509", "-in", v[key], "-checkend", "86400", "-noout"])
    if v["APP_ENV"] == "production":
        info = run(
            ["openssl", "x509", "-in", v["TLS_CERT_FILE"], "-issuer", "-subject", "-noout"]
        ).stdout
        if "CVE Development" in info:
            raise ValueError("Entwicklungszertifikate sind für production verboten")
    for domain in (v[key] for key in DOMAINS):
        run(
            [
                "openssl",
                "verify",
                "-purpose",
                "sslserver",
                "-CAfile",
                v["TLS_TRUST_FILE"],
                "-untrusted",
                v["TLS_CERT_FILE"],
                "-verify_hostname",
                domain,
                v["TLS_CERT_FILE"],
            ]
        )
    public = run(["openssl", "x509", "-in", v["TLS_CERT_FILE"], "-pubkey", "-noout"]).stdout
    private_public = run(["openssl", "pkey", "-in", v["TLS_KEY_FILE"], "-pubout"]).stdout
    if public != private_public:
        raise ValueError("TLS-Zertifikat und Schlüssel passen nicht zusammen")


def render_template(text: str, variables: dict[str, str]) -> str:
    """Ersetze nur explizite ${GROSSBUCHSTABEN}; Nginx-$Variablen bleiben erhalten."""

    def replace(match: re.Match[str]) -> str:
        name = match[1]
        if name not in variables:
            raise ValueError(f"Nicht freigegebene/fehlende Templatevariable: {name}")
        return variables[name]

    return re.sub(r"\$\{([A-Z][A-Z0-9_]*)\}", replace, text)


def render(config: Config) -> None:
    """Schreibe nur kontrollierte Konfiguration und ein minimales TLS-Snapshotbundle."""
    certificate_preflight(config)
    v = dict(config.values)
    v["HSTS_VALUE"] = "max-age=31536000" if v["APP_ENV"] == "production" else ""
    v["HTTPS_SUFFIX"] = "" if v["INGRESS_HTTPS_PORT"] == "443" else ":" + v["INGRESS_HTTPS_PORT"]
    directory = config.directory
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name in ("snippets", "conf.d", "tls", "empty"):
        (directory / name).mkdir(exist_ok=True, mode=0o700)
    source = config.root / "infrastructure/nginx"
    inputs = [(source / "templates/http.conf.template", directory / "http.conf")]
    inputs += [
        (p, directory / "conf.d" / p.name.removesuffix(".template"))
        for p in (source / "conf.d").glob("*.template")
        if p.name in {"00-default.conf.template", "10-dashboard.conf.template"}
    ]
    inputs += [
        (p, directory / "snippets" / p.name.removesuffix(".template"))
        for p in (source / "snippets").iterdir()
        if p.is_file()
    ]
    for obsolete in ("20-api.conf", "30-inventory.conf", "40-n8n.conf"):
        (directory / "conf.d" / obsolete).unlink(missing_ok=True)
    for original, target in inputs:
        content = render_template(original.read_text(), v)
        target.write_text(content)
    for key, name in (
        ("TLS_CERT_FILE", "server.crt"),
        ("TLS_KEY_FILE", "server.key"),
        ("CLIENT_CA_FILE", "client-ca.crt"),
        ("CLIENT_CRL_FILE", "client-ca.crl"),
    ):
        target = directory / "tls" / name
        temporary = target.with_suffix(target.suffix + ".new")
        temporary.write_bytes(Path(v[key]).read_bytes())
        temporary.chmod(0o600)
        temporary.replace(target)
    # Alle bekannten öffentlichen Fachpfade außer technischen/administrativen Routen.
    spec = yaml.safe_load((config.root / "contracts/api/openapi.yaml").read_text())
    locations: list[str] = []
    for path in spec["paths"]:
        if (
            not path.startswith("/api/v1/")
            or path == "/api/v1/inventories"
            or path.startswith("/api/v1/dashboard/admin/")
            or path == "/api/v1/dashboard/inventories/upload"
        ):
            continue
        expression = re.escape(path)
        expression = re.sub(r"\\\{[^}]+\\\}", "[A-Za-z0-9_-]+", expression)
        locations.append(
            'location ~ "^'
            + expression
            + '$" { root /etc/nginx/cve/empty; try_files /__backend_absent__ =503; }'
        )
    from scripts.dashboard.manage import render_static

    render_static(config)
    from scripts.security.manage import render_auth_route

    inventory_base = config.secrets_base / "services" / config.project
    if (inventory_base / "inventory-gateway.key").is_file():
        from scripts.inventory.configuration import trust

        trust(config, inventory_base)
    render_auth_route(config)
    (directory / "snippets/api-routes.conf").write_text("\n".join(locations) + "\n")


def generate_certificates(config: Config, force: bool = False, fixtures: bool = False) -> Path:
    """Erzeuge lokale Test-PKI, ohne globale Vertrauensspeicher zu ändern."""
    if config.values["APP_ENV"] != "development":
        raise ValueError("Testzertifikate ausschließlich für development")
    directory = Path(config.values["TLS_CERT_FILE"]).parent
    if directory.exists() and any(directory.iterdir()) and not force:
        raise ValueError("PKI existiert bereits; nur mit --force ausdrücklich ersetzen")
    if (
        directory.exists()
        and any(directory.iterdir())
        and not (directory / "development.json").exists()
    ):
        raise ValueError("Unbekannte PKI wird auch mit --force nicht überschrieben")
    directory.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cve-pki-", dir=directory.parent) as temporary:
        work = Path(temporary)

        def openssl(args: list[str]) -> None:
            run(["openssl", *args], cwd=work)

        for name in ("server-ca", "client-ca", "rogue-ca"):
            openssl(
                [
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:3072",
                    "-nodes",
                    "-sha256",
                    "-days",
                    "365",
                    "-keyout",
                    name + ".key",
                    "-out",
                    name + ".crt",
                    "-subj",
                    "/CN=CVE Development " + name,
                    "-addext",
                    "basicConstraints=critical,CA:TRUE",
                    "-addext",
                    "keyUsage=critical,keyCertSign,cRLSign",
                ]
            )

        def leaf(
            name: str, ca: str, server: bool, days: str = "30", wrong_name: bool = False
        ) -> None:
            openssl(
                [
                    "req",
                    "-new",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-sha256",
                    "-keyout",
                    name + ".key",
                    "-out",
                    name + ".csr",
                    "-subj",
                    "/CN=CVE Development " + name,
                ]
            )
            san = (
                ",".join("DNS:" + config.values[k] for k in DOMAINS)
                if server
                else "URI:urn:cve-monitoring:dev-client"
            )
            if wrong_name:
                san = "DNS:wrong.example.test"
            (work / "leaf.ext").write_text(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage="
                + ("serverAuth" if server else "clientAuth")
                + "\nsubjectAltName="
                + san
                + "\n"
            )
            openssl(
                [
                    "x509",
                    "-req",
                    "-in",
                    name + ".csr",
                    "-CA",
                    ca + ".crt",
                    "-CAkey",
                    ca + ".key",
                    "-CAcreateserial",
                    "-out",
                    name + ".crt",
                    "-days",
                    days,
                    "-sha256",
                    "-extfile",
                    "leaf.ext",
                ]
            )

        leaf("server", "server-ca", True)
        leaf("client", "client-ca", False)
        if fixtures:
            leaf("client-new", "client-ca", False)
            leaf("revoked-client", "client-ca", False)
            leaf("wrong-purpose-client", "client-ca", True)
        if fixtures:
            leaf("untrusted-client", "rogue-ca", False)
            leaf("expired-client", "client-ca", False, "-1")
            leaf("server-new", "server-ca", True)
            leaf("expired-server", "server-ca", True, "-1")
            leaf("wrong-host", "server-ca", True, wrong_name=True)
            leaf("untrusted-server", "rogue-ca", True)
        (work / "development.json").write_text(
            json.dumps(
                {
                    "purpose": "LOCAL DEVELOPMENT ONLY",
                    "domains": [config.values[k] for k in DOMAINS],
                }
            )
        )
        directory.mkdir(exist_ok=True, mode=0o700)
        shutil.copyfile(work / "server.crt", work / "fullchain.pem")
        shutil.copyfile(work / "server.key", work / "privkey.pem")
        shutil.copyfile(work / "server-ca.crt", work / "ca.crt")
        config.values["TLS_TRUST_FILE"] = str(directory / "ca.crt")
        for original in work.iterdir():
            if original.suffix in {".key", ".crt", ".json", ".pem"}:
                target = directory / original.name
                shutil.copyfile(original, target)
                target.chmod(
                    0o600 if original.suffix == ".key" or original.name == "privkey.pem" else 0o644
                )
    return directory


def nginx_check(config: Config) -> None:
    """Nginx-Test ohne veröffentlichte Ports oder Netzwerkzugang."""
    mounted_config = config.root / "infrastructure/nginx/nginx.conf"
    image = resolved(config)["services"]["cve-nginx"]["image"]
    run(
        [
            *docker_command(),
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--user",
            config.values["NGINX_UID"] + ":" + config.values["NGINX_GID"],
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,mode=1777",
            "--label",
            "org.cve-monitoring.managed=phase-02-check",
            "--mount",
            f"type=bind,src={mounted_config},dst=/etc/nginx/nginx.conf,readonly",
            "--mount",
            f"type=bind,src={config.directory},dst=/etc/nginx/cve,readonly",
            "--entrypoint",
            "nginx",
            image,
            "-t",
        ]
    )


def reload_nginx(config: Config) -> None:
    """Validiere neue Konfiguration; bei Fehlern Snapshot ohne Workerwechsel zurücksetzen."""
    with tempfile.TemporaryDirectory(prefix="cve-reload-") as temporary:
        backup = Path(temporary) / "config"
        shutil.copytree(config.directory, backup)
        try:
            render(config)
            compose(config, ["exec", "-T", "cve-nginx", "nginx", "-t"])
            compose(config, ["exec", "-T", "cve-nginx", "nginx", "-s", "reload"])
        except (OSError, ValueError, subprocess.SubprocessError):
            shutil.copytree(backup, config.directory, dirs_exist_ok=True)
            raise


def main() -> int:
    """Führe ausschließlich den ausdrücklich gewählten Infrastrukturvorgang aus."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=[
            "compose-check",
            "preflight",
            "render",
            "certificates",
            "nginx-check",
            "up",
            "down",
            "reload",
        ],
    )
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--test-fixtures", action="store_true")
    args = parser.parse_args()
    try:
        config = load_config(args.env_file)
        if args.action == "certificates":
            generate_certificates(config, args.force, args.test_fixtures)
        else:
            errors = validate_model(
                resolved(config),
                config.values["APP_ENV"] == "development",
                config.root,
                mount_base=config.mount_base,
                secrets_base=config.secrets_base,
            ) + validate_networks(network_definitions(config), project=config.project)
            if errors:
                raise ValueError("; ".join(errors))
            if args.action == "preflight":
                certificate_preflight(config)
                run([*docker_command(), "info", "--format", "{{.ServerVersion}}"])
            elif args.action in {"render", "nginx-check", "up"}:
                render(config)
                if args.action != "render":
                    nginx_check(config)
                if args.action == "up":
                    compose(config, ["up", "-d", "--wait", "--wait-timeout", "30", "cve-nginx"])
            elif args.action == "down":
                compose(config, ["down"])
            elif args.action == "reload":
                reload_nginx(config)
        print(
            json.dumps(
                {"level": "info", "action": args.action, "project": config.project, "result": "ok"}
            )
        )
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        detail = exc.stderr if isinstance(exc, subprocess.CalledProcessError) else str(exc)
        print(
            json.dumps({"level": "error", "action": args.action, "detail": detail}), file=sys.stderr
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
