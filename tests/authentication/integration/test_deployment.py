"""Real HTTPS ingress, API/PostgreSQL restarts and isolated operator bootstrap."""

import base64
import http.client
import json
import socket
import ssl
import subprocess
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlsplit

import psycopg
import pytest
from cve_api.auth.totp import code
from cve_common.config.secrets import read_secret

from scripts.database import manage as db
from scripts.infrastructure.manage import compose, docker_command, run
from scripts.security.manage import origin
from scripts.services import manage as api
from tests.authentication.integration.conftest import Browser, Lab
from tests.infrastructure.client import request

pytestmark = [pytest.mark.authentication, pytest.mark.security]


class TLSBrowser:
    def __init__(self, lab: Lab) -> None:
        self.lab = lab
        self.cookies: dict[str, str] = {}
        self.csrf = ""
        self.cookie_headers: list[str] = []

    def send(
        self, path: str, body: dict[str, object] | None = None, **headers: str
    ) -> tuple[int, dict[str, object]]:
        cfg = self.lab.config
        context = ssl.create_default_context(cafile=cfg.values["TLS_TRUST_FILE"])
        connection = http.client.HTTPConnection(
            "127.0.0.1", int(cfg.values["INGRESS_HTTPS_PORT"]), timeout=15
        )
        connection.sock = context.wrap_socket(
            socket.create_connection(
                ("127.0.0.1", int(cfg.values["INGRESS_HTTPS_PORT"])), timeout=15
            ),
            server_hostname=cfg.values["DASHBOARD_DOMAIN"],
        )
        try:
            values = {
                "Host": cfg.values["DASHBOARD_DOMAIN"],
                "Origin": origin(cfg),
                "Content-Type": "application/json",
                "Cookie": "; ".join(k + "=" + v for k, v in self.cookies.items()),
                "X-CSRF-Token": self.csrf,
                **headers,
            }
            connection.request(
                "POST" if body is not None else "GET",
                "/api/v1/auth/" + path,
                json.dumps(body) if body is not None else None,
                values,
            )
            response = connection.getresponse()
            self.cookie_headers = []
            for key, value in response.getheaders():
                if key.lower() == "set-cookie":
                    self.cookie_headers.append(value)
                    parsed = SimpleCookie()
                    parsed.load(value)
                    for name, morsel in parsed.items():
                        if morsel.value:
                            self.cookies[name] = morsel.value
                        else:
                            self.cookies.pop(name, None)
            raw = response.read()
            data = json.loads(raw) if raw else {}
            if "csrf_token" in data:
                self.csrf = data["csrf_token"]
            return response.status, data
        finally:
            connection.close()


def test_https_full_admin_enrollment_and_cookie_survives_api_restart(auth_lab: Lab) -> None:
    browser = TLSBrowser(auth_lab)
    assert browser.send("csrf")[0] == 200
    status, data = browser.send(
        "login",
        {"username": "initial-admin", "password": auth_lab.bootstrap_password},
        **{
            "X-User-ID": "forged",
            "X-Role": "admin",
            "X-CVE-Auth-Gateway": "forged",
            "X-Forwarded-For": "127.0.0.1",
        },
    )
    assert status == 200 and data["state"] == "authenticated"
    assert all(
        "secure" in h.lower() and "httponly" in h.lower() and "domain=" not in h.lower()
        for h in browser.cookie_headers
    )
    assert browser.send("reauthenticate", {"password": auth_lab.bootstrap_password})[0] == 200
    status, data = browser.send("mfa/enroll/start", {})
    assert status == 200
    encoded = parse_qs(urlsplit(str(data["provisioning_uri"])).query)["secret"][0]
    secret = base64.b32decode(encoded + "=" * ((-len(encoded)) % 8))
    status, data = browser.send("mfa/enroll/confirm", {"code": code(secret, auth_lab.clock_step())})
    assert status == 200 and data["state"] == "authenticated"
    assert browser.send("session")[1]["state"] == "authenticated"
    original = browser.cookies["__Host-cve-session"]
    compose(auth_lab.config, ["restart", "cve-api"])
    compose(auth_lab.config, ["up", "-d", "--wait", "--wait-timeout", "45", "cve-api"])
    assert browser.send("session")[0] == 200
    assert browser.cookies["__Host-cve-session"] == original
    assert browser.send("logout", {})[0] == 204
    browser.cookies["__Host-cve-session"] = original
    assert browser.send("session")[0] == 401


def test_https_only_and_authentication_not_on_public_api_domain(auth_lab: Lab) -> None:
    assert (
        request(auth_lab.config, "dashboard.example.test", "/api/v1/auth/csrf", tls=False).status
        == 308
    )
    assert (
        request(
            auth_lab.config, "dashboard.example.test", "/api/v1/auth/login", "POST", tls=False
        ).status
        == 426
    )
    assert request(auth_lab.config, "api.example.test", "/api/v1/auth/csrf").status == 404
    assert (
        request(
            auth_lab.config,
            "dashboard.example.test",
            "/api/v1/auth/csrf",
            headers={"Host": "api.example.test"},
        ).status
        == 421
    )
    context = ssl.create_default_context()
    with (
        socket.create_connection(
            ("127.0.0.1", int(auth_lab.config.values["INGRESS_HTTPS_PORT"]))
        ) as sock,
        pytest.raises(ssl.SSLCertVerificationError),
    ):
        context.wrap_socket(sock, server_hostname="dashboard.example.test")


def test_direct_backend_cannot_replace_ingress(auth_lab: Lab) -> None:
    import urllib.error
    import urllib.request

    container = api.container(auth_lab.config)
    network = container["NetworkSettings"]["Networks"][auth_lab.config.project + "_cve_internal"]
    req = urllib.request.Request(
        "http://" + network["IPAddress"] + ":8000/api/v1/auth/csrf",
        headers={
            "Host": "dashboard.example.test",
            "X-CVE-Auth-Gateway": "forged",
            "X-CVE-Auth-Scheme": "https",
            "X-Real-IP": "127.0.0.1",
            "X-Role": "admin",
        },
    )
    with pytest.raises(urllib.error.HTTPError) as result:
        urllib.request.urlopen(req, timeout=3)
    assert result.value.code == 403
    assert not container["HostConfig"]["PortBindings"]
    assert container["HostConfig"]["ReadonlyRootfs"]
    assert container["Config"]["User"].split(":")[0] != "0"
    assert container["HostConfig"]["CapDrop"] == ["ALL"]


def test_database_outage_fail_closed_then_recovers(auth_lab: Lab) -> None:
    browser = TLSBrowser(auth_lab)
    assert browser.send("csrf")[0] == 200
    try:
        compose(auth_lab.config, ["stop", "cve-postgres"])
        assert api.probe(auth_lab.config, "/health/live")["status"] == "alive"
        with pytest.raises(subprocess.CalledProcessError):
            api.probe(auth_lab.config)
        # A fresh request cannot fall back to an in-memory authenticated identity.
        assert browser.send("csrf")[0] == 503
    finally:
        compose(auth_lab.config, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-postgres"])
    assert browser.send("csrf")[0] == 200


def test_bootstrap_is_explicit_one_time_and_scoped(auth_lab: Lab) -> None:
    with auth_lab.owner() as connection:
        row = connection.execute(
            (
                "SELECT u.mfa_required,u.status,c.password_hash FRO"
                "M security.users u JOIN security.password_credenti"
                "als c ON c.user_id=u.id WHERE u.id=%s"
            ),
            (auth_lab.bootstrap_id,),
        ).fetchone()
        assert row["status"] == "active" and row["password_hash"].startswith("$argon2id$")
    with (
        db.connect(auth_lab.config, "cve_migrator") as connection,
        pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState),
    ):
        connection.execute(
            "SELECT security.bootstrap_admin('second-admin','second@example.test',%s)",
            (row["password_hash"],),
        )
    # Runtime identity cannot invoke the operator-only function.
    with (
        db.connect(auth_lab.config, "api_security") as connection,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        connection.execute(
            "SELECT security.bootstrap_admin('forged','forged@example.test',%s)",
            (row["password_hash"],),
        )


async def test_corrupted_mfa_ciphertext_cannot_grant_session(browser: Browser) -> None:
    from tests.authentication.integration.test_flows import enroll

    uid, name, password = await browser.user(admin=True)
    await browser.login(name, password)
    await enroll(browser)
    await browser.login(name, password)
    with browser.lab.owner() as connection:
        connection.execute(
            (
                "UPDATE security.mfa_methods SET ciphertext=decode("
                "repeat('00',48),'hex') WHERE user_id=%s AND revoke"
                "d_at IS NULL"
            ),
            (uid,),
        )
    response = await browser.post("mfa/verify", {"code": "123456"})
    assert response.status_code == 503
    assert (await browser.client.get("/api/v1/auth/_protected")).status_code == 403


def test_container_missing_mfa_key_fails_startup_validation(auth_lab: Lab) -> None:
    code = (
        "from cve_common.config.validation import load_sett"
        "ings;from cve_api.settings import ApiSettings;from"
        " cve_api.auth.encryption import Keyring;from pathl"
        "ib import Path;s=load_settings(ApiSettings);Keyrin"
        'g(Path("/run/cve-api/missing-key"))'
    )
    with pytest.raises(subprocess.CalledProcessError):
        run([*docker_command(), "exec", api.container(auth_lab.config)["Id"], "python", "-c", code])
    files = api.directory(auth_lab.config)
    keys = read_secret(files / "auth-keys.json").get_secret_value()
    gateway = read_secret(files / "auth-gateway.key").get_secret_value()
    logs = compose(auth_lab.config, ["logs", "--no-color", "cve-api", "cve-nginx"]).stdout
    for value in (
        keys,
        gateway,
        auth_lab.bootstrap_password,
        read_secret(files / "api_reader.password").get_secret_value(),
        read_secret(files / "api_security.password").get_secret_value(),
    ):
        assert value not in logs
