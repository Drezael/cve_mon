"""Explicit operator bootstrap and project-local authentication prerequisites."""

import argparse
import asyncio
import getpass
import json
import os
import re
import secrets
import sys
from pathlib import Path

from cve_api.auth.encryption import Keyring
from cve_api.auth.password_policy import validate_password
from cve_api.auth.passwords import Passwords
from cve_api.auth.settings import AuthSettings
from cve_common.config.secrets import read_secret
from cve_common.config.settings import DatabaseSettings

from scripts.database import manage as db
from scripts.infrastructure.manage import Config, load_config


def private_write(path: Path, value: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(value + "\n")


def prepare_auth(config: Config, base: Path) -> None:
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    smtp_keys = base / "smtp-keys.json"
    if not smtp_keys.exists() and config.manages_credentials:
        private_write(smtp_keys, json.dumps({"active": "1", "keys": {"1": secrets.token_hex(32)}}))
    from cve_common.smtp_settings import SMTPKeyring

    SMTPKeyring(smtp_keys)

    password = base / "api_security.password"
    if not password.exists() and config.manages_credentials:
        private_write(password, db.read_secret(db.secret_file(config, "api_security")))
    read_secret(password)
    keyring = base / "auth-keys.json"
    gateway = base / "auth-gateway.key"
    if not keyring.exists() and config.manages_credentials:
        private_write(keyring, json.dumps({"active": "1", "keys": {"1": secrets.token_hex(32)}}))
    if not gateway.exists() and config.manages_credentials:
        private_write(gateway, secrets.token_urlsafe(32))
    Keyring(keyring)
    if not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", read_secret(gateway).get_secret_value()):
        raise ValueError("Invalid private gateway credential")


def origin(config: Config) -> str:
    suffix = (
        ""
        if config.values["INGRESS_HTTPS_PORT"] == "443"
        else ":" + config.values["INGRESS_HTTPS_PORT"]
    )
    return "https://" + config.values["DASHBOARD_DOMAIN"] + suffix


def render_auth_route(config: Config) -> None:
    gateway = config.secrets_base / "services" / config.project / "auth-gateway.key"
    route = "location ^~ /api/v1/auth/ { return 503; }\n"
    if gateway.exists():
        key = read_secret(gateway).get_secret_value()
        if not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", key):
            raise ValueError("Invalid gateway credential")
        route = (
            '''location ^~ /api/v1/auth/ {
    client_max_body_size 8k;
    resolver 127.0.0.11 valid=10s ipv6=off;
    set $auth_backend "http://cve-api:8000";
    include /etc/nginx/cve/snippets/auth-proxy-headers.conf;
    proxy_set_header X-CVE-Auth-Gateway "'''
            + key
            + """";
    proxy_set_header X-CVE-Auth-Scheme "https";
    proxy_set_header X-User-ID "";
    proxy_set_header X-Role "";
    proxy_pass $auth_backend;
}
"""
        )
    administration = "location /api/v1/dashboard/admin/ { return 403; }\n"
    if gateway.exists():
        proxy = route[route.index("    client_max_body_size") : route.rindex("}")]
        probe_key = config.secrets_base / "services" / config.project / "status-probe.key"
        status_routes = "location ^~ /api/v1/status/ {\n" + proxy + "}\n"
        if probe_key.is_file():
            status_routes += (
                'location = /api/v1/status/proxy-health { if ($http_x_cve_status_probe != "'
                + read_secret(probe_key).get_secret_value()
                + '") { return 403; } resolver 127.0.0.11 valid=10s ipv6=off; '
                'set $status_backend "http://cve-api:8000"; '
                "proxy_pass $status_backend/health/ready; }\n"
            )
        route += status_routes
        large_proxy = proxy.replace("client_max_body_size 8k", "client_max_body_size 32k")
        administration = (
            'location ~ "^/api/v1/dashboard/admin/server-access/[0-9a-f-]{36}$" {\n'
            + large_proxy
            + "}\n"
            + 'location ~ "^/api/v1/dashboard/admin/(users(?:/[A-Za-z0-9_-]+(?:/(?:enab'
            "le|disable|archive|lock|revoke-sessions|roles|permissions|mfa-recovery))"
            '?)?|roles(?:/[A-Za-z0-9_-]+)?|server-access/[A-Za-z0-9_-]+|permissions)$" {\n'
            + proxy
            + "}\n"
            + "location /api/v1/dashboard/admin/ { return 403; }\n"
            + "location = /api/v1/dashboard/localization {\n"
            + proxy
            + "}\n"
            + "location = /api/v1/dashboard/me/locale {\n"
            + proxy
            + "}\n"
            + "location = /api/v1/dashboard/me/permissions {\n"
            + proxy
            + "}\n"
        )
    if gateway.exists():
        administration = (
            'location ~ "^/api/v1/dashboard/admin/servers(?:/(?:order|[A-Za-z'
            '0-9_-]+(?:/(?:archive|restore))?))?$" {\n'
            + proxy
            + "}\n"
            + 'location ~ "^/api/v1/dashboard/(servers(?:/[A-Za-z0-9_-]+(?:/(?:'
            "groups|scan|ansible(?:/(?:collect|test|probe|confirm-key))?))?)?|"
            'groups(?:/[A-Za-z0-9_-]+)?)$" {\n' + large_proxy + "}\n" + administration
        )
    if gateway.exists():
        yaml_proxy = proxy.replace("client_max_body_size 8k", "client_max_body_size 128k")
        administration += (
            'location ~ "^/api/v1/dashboard/custom-dashboards'
            '(?:/(?:validate|[0-9a-f-]{36}(?:/(?:shares|copy))?))?$" {\n'
            + yaml_proxy
            + "}\n"
            + "location ^~ /api/v1/dashboard/administration/ {\n"
            + large_proxy
            + "}\n"
            + "location = /api/v1/dashboard/notifications {\n"
            + proxy
            + "}\n"
            + "location ^~ /api/v1/dashboard/notifications/ {\n"
            + large_proxy
            + "}\n"
            + 'location ~ "^/api/v1/dashboard/(cve-data(?:/(?:refresh|documents'
            "(?:/CVE-[0-9]{4}-[0-9]{4,})?))?|"
            "orchestration(?:/(?:settings|runs/[0-9a-f-]{36}/(?:pause|resume|cancel)))?|"
            "overview(?:/(?:coverage|trends))?|"
            "security/servers(?:/[0-9a-f-]{36}(?:/(?:containers|container-software))?)?|"
            "security/findings/"
            '[0-9a-f-]{36}/context)$" {\n'
            + proxy
            + "}\n"
            + "location = /api/v1/findings {\n"
            + proxy
            + "}\n"
            + "location ^~ /api/v1/findings/ {\n"
            + proxy
            + "}\n"
        )
    inventory_key = config.secrets_base / "services" / config.project / "inventory-gateway.key"
    technical = (
        "location = /api/v1/inventories { if ($request_method != POST) { r"
        "eturn 405; } return 503; }\n"
    )
    dashboard = (
        "location = /api/v1/dashboard/inventories/upload { if ($request_me"
        "thod != POST) { return 405; } return 503; }\n"
    )
    if inventory_key.exists():
        from scripts.inventory.configuration import settings as inventory_settings

        limits = inventory_settings(config)
        capability = read_secret(inventory_key).get_secret_value()
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", capability):
            raise ValueError("Invalid inventory ingress capability")
        common = (
            "    resolver 127.0.0.11 valid=10s ipv6=off;\n"
            '    set $inventory_backend "http://cve-api:8000";\n'
            "    proxy_request_buffering off;\n"
        )
        technical = (
            'location ~ "^/api/v1/inventories(?:/submissions/[0-9a-f-]{36}'
            '|/collection/(?:targets|claim|finish))?$" {\n'
            + common
            + "    client_max_body_size "
            + str(limits.max_bytes)
            + ";\n"
            + "    include /etc/nginx/cve/snippets/technical-proxy-headers.conf;\n"
            + '    proxy_set_header X-CVE-Inventory-Gateway "'
            + capability
            + '";\n'
            + '    proxy_set_header X-CVE-Inventory-Scheme "https";\n'
            + "    proxy_set_header X-CVE-Inventory-Verify $ssl_client_verify;\n"
            + "    proxy_set_header X-CVE-Inventory-Certificate $ssl_client_escaped_cert;\n"
            + "    proxy_pass $inventory_backend;\n}\n"
        )
        if gateway.exists():
            dashboard = (
                "location = /api/v1/dashboard/inventories/upload {\n"
                + common
                + "    client_max_body_size "
                + str(limits.max_request_bytes)
                + ";\n"
                + "    limit_req zone=upload burst="
                + config.values["RATE_BURST"]
                + " nodelay;\n"
                + "    include /etc/nginx/cve/snippets/auth-proxy-headers.conf;\n"
                + '    proxy_set_header X-CVE-Auth-Gateway "'
                + key
                + '";\n'
                + '    proxy_set_header X-CVE-Auth-Scheme "https";\n'
                + "    proxy_pass $inventory_backend;\n}\n"
                + 'location ~ "^/api/v1/dashboard/inventories/submissions/[0-9a-f-]{36}$" {\n'
                + proxy
                + "}\n"
            )
            administration = (
                'location ~ "^/api/v1/dashboard/admin/(inventory-clients(?:/[0-9a-'
                "f-]{36}/(?:certificates|tokens|enable|disable))?|inventory-tokens"
                "/[0-9a-f-]{36}/(?:rotate|revoke|disable)|inventory-certificates/["
                '0-9a-f-]{36}/revoke)$" {\n' + proxy + "}\n" + administration
            )
    for filename, content in [
        ("inventory-technical-routes.conf", technical),
        ("inventory-dashboard-routes.conf", dashboard),
    ]:
        target_inventory = config.directory / "snippets" / filename
        target_inventory.write_text(content)
        target_inventory.chmod(0o600)
    admin_target = config.directory / "snippets/administration-routes.conf"
    admin_target.write_text(administration)
    admin_target.chmod(0o600)
    target = config.directory / "snippets/auth-routes.conf"
    target.write_text(route)
    target.chmod(0o600)


def settings(config: Config) -> AuthSettings:
    base = config.secrets_base / "services" / config.project
    return AuthSettings(
        database=DatabaseSettings(
            host="cve-postgres",
            hostaddr=db.address(config),
            username="api_security",
            password_file=base / "api_security.password",
            ca_file=base / "ca.crt",
        ),
        administration_database=DatabaseSettings(
            host="cve-postgres",
            hostaddr=db.address(config),
            username="dashboard_admin",
            password_file=base / "dashboard_admin.password",
            ca_file=base / "ca.crt",
        ),
        origin=origin(config),
        keyring_file=base / "auth-keys.json",
        gateway_file=base / "auth-gateway.key",
        argon_memory=int(config.values["AUTH_ARGON_MEMORY"]),
        argon_concurrency=int(config.values["AUTH_ARGON_CONCURRENCY"]),
        login_limit=int(config.values["AUTH_LOGIN_LIMIT"]),
        ip_limit=int(config.values["AUTH_IP_LIMIT"]),
    )


async def bootstrap(config: Config, username: str, email: str, password: str) -> str:
    policy = settings(config)
    encoded = await Passwords(policy).hash(validate_password(password, username))
    with db.connect(config, "cve_migrator") as connection:
        row = connection.execute(
            "SELECT security.bootstrap_admin(%s,%s,%s) AS id", (username, email, encoded)
        ).fetchone()
        assert row is not None
        return str(row["id"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=["bootstrap", "check", "secrets", "status", "cleanup", "purge-archived"]
    )
    parser.add_argument("--username")
    parser.add_argument("--email")
    from uuid import UUID

    parser.add_argument("--archive-receipt", type=UUID)
    parser.add_argument("--password-file", type=Path)
    args = parser.parse_args()
    try:
        config = load_config()
        if args.action == "bootstrap":
            if not args.username or not args.email:
                raise ValueError("Explicit administrator identity required")
            if args.password_file:
                password = read_secret(args.password_file).get_secret_value()
            elif sys.stdin.isatty():
                password = getpass.getpass("Initiales Administratorpasswort: ")
                if password != getpass.getpass("Passwort wiederholen: "):
                    raise ValueError("Password confirmation mismatch")
            else:
                raise ValueError("Private password file or terminal required")
            print(
                json.dumps(
                    {
                        "user_id": asyncio.run(
                            bootstrap(config, args.username, args.email, password)
                        ),
                        "mfa_setup_required": True,
                    }
                )
            )
        elif args.action == "status":
            with db.connect(config, "status_probe") as connection:
                row = connection.execute("SELECT security.auth_metrics() AS metrics").fetchone()
                assert row is not None
                print(json.dumps(row["metrics"]))
        elif args.action == "purge-archived":
            if args.archive_receipt is None:
                raise ValueError("Verified archive receipt required")
            with db.connect(config, "cve_migrator") as connection:
                row = connection.execute(
                    "SELECT security.auth_purge_archived(%s) AS result", (args.archive_receipt,)
                ).fetchone()
                assert row is not None
                print(json.dumps(row["result"]))
        elif args.action == "cleanup":
            with db.connect(config, "api_security") as connection:
                connection.execute("SELECT security.auth_cleanup()")
        else:
            policy = settings(config)
            Keyring(policy.keyring_file)
            read_secret(policy.gateway_file)
            read_secret(policy.database.password_file)
        print(json.dumps({"action": args.action, "result": "ok"}))
        return 0
    except Exception as error:
        print(
            json.dumps({"action": args.action, "result": "error", "code": type(error).__name__}),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
