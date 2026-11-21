"""Real PostgreSQL and independently built API/Nginx; no shared accounts or Docker resources."""

import asyncio
import os
import secrets
import socket
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any
from uuid import UUID, uuid4

import httpx
import pytest
from cve_api.auth.dependencies import authenticated_user
from cve_api.auth.service import AuthService
from cve_api.factory import create_app
from cve_api.settings import ApiSettings
from cve_common.config.settings import DatabaseSettings
from fastapi import Depends

from scripts.database import manage as db
from scripts.infrastructure.manage import (
    Config,
    compose,
    generate_certificates,
    render,
)
from scripts.security import manage as auth
from scripts.services import manage as api
from tests.configuration import load_test_config as load_config


@dataclass
class Lab:
    config: Config
    bootstrap_password: str
    bootstrap_id: UUID

    def database(self, role: str) -> DatabaseSettings:
        return DatabaseSettings(
            host="cve-postgres",
            hostaddr=db.address(self.config),
            username=role,
            password_file=db.secret_file(self.config, role),
            ca_file=db.workdir(self.config) / "tls/ca.crt",
            pool_size=5,
        )

    def owner(self) -> Any:
        connection = db.connect(self.config, "cve_migrator")
        connection.execute("SET ROLE postgres_owner")
        return connection

    def clock_step(self) -> int:
        with self.owner() as connection:
            return int(
                connection.execute(
                    "SELECT floor(extract(epoch FROM clock_timestamp())/30)::bigint AS step"
                ).fetchone()["step"]
            )


@pytest.fixture(scope="session")
def auth_lab() -> Iterator[Lab]:
    def port() -> str:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return str(sock.getsockname()[1])

    project = "cve-db-test-phase08-" + uuid4().hex[:10]
    root = Path(__file__).resolve().parents[3]
    pki = root / ".runtime/auth-tests" / project / "pki"
    config = load_config(
        overrides={
            "COMPOSE_PROJECT_NAME": project,
            "STATUS_COLLECTOR_PAUSED": "true",
            "INGRESS_HTTP_PORT": port(),
            "INGRESS_HTTPS_PORT": port(),
            "MAILHOG_HTTP_PORT": port(),
            "SMTP_HOST": "",
            "NGINX_UID": str(os.getuid()),
            "NGINX_GID": str(os.getgid()),
            "TLS_CERT_FILE": str(pki / "server.crt"),
            "TLS_KEY_FILE": str(pki / "server.key"),
            "TLS_TRUST_FILE": str(pki / "server-ca.crt"),
            "CLIENT_CA_FILE": str(pki / "client-ca.crt"),
        }
    )
    db.prepare(config)
    try:
        compose(config, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-postgres"])
        db.provision(config)
        db.migrate(config)
        db.migrate(config)
        api.prepare(config)
        password = secrets.token_urlsafe(24)
        uid = UUID(
            asyncio.run(auth.bootstrap(config, "initial-admin", "initial@example.test", password))
        )
        api.build(config)
        generate_certificates(config)
        render(config)
        compose(config, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-api", "cve-nginx"])
        yield Lab(config, password, uid)
    finally:
        target = root / ".runtime/test-reports"
        target.mkdir(parents=True, exist_ok=True)
        (target / (project + ".log")).write_text(
            compose(config, ["logs", "--no-color", "cve-api"]).stdout
        )
        db.cleanup_test(config)


@dataclass
class Browser:
    client: httpx.AsyncClient
    service: AuthService
    lab: Lab
    csrf: str = ""
    login_password: str = field(default="", repr=False)

    async def prepare(self) -> httpx.Response:
        result = await self.client.get("/api/v1/auth/csrf")
        assert result.status_code == 200, result.text
        self.csrf = result.json()["csrf_token"]
        return result

    async def post(self, path: str, body: dict[str, object] | None = None) -> httpx.Response:
        result = await self.client.post(
            "/api/v1/auth/" + path, json=body or {}, headers={"x-csrf-token": self.csrf}
        )
        if result.status_code == 200 and "csrf_token" in result.json():
            self.csrf = result.json()["csrf_token"]
        return result

    async def login(self, name: str, password: str) -> httpx.Response:
        self.client.cookies.clear()
        await self.prepare()
        response = await self.post("login", {"username": name, "password": password})
        if response.status_code == 200:
            self.login_password = password
        return response

    async def user(self, *, admin: bool = False, status: str = "active") -> tuple[UUID, str, str]:
        name = "account-" + uuid4().hex[:12]
        password = secrets.token_urlsafe(24)
        encoded = await self.service.passwords.hash(password)
        with self.lab.owner() as connection:
            uid = connection.execute(
                "INSERT INTO security.users(username,email,display_name,status,archived_at) "
                "VALUES(%s,%s,%s,%s,CASE WHEN %s='archived' THEN clock_timestamp() ELSE NULL END) "
                "RETURNING id",
                (name, name + "@example.test", name, status, status),
            ).fetchone()["id"]
            connection.execute(
                "INSERT INTO security.password_credentials(user_id,password_hash) VALUES(%s,%s)",
                (uid, encoded),
            )
            if admin:
                connection.execute(
                    "INSERT INTO security.user_roles(user_id,role_id) "
                    "SELECT %s,id FROM security.roles WHERE code='admin'",
                    (uid,),
                )
        return uid, name, password


@pytest.fixture
async def browser(auth_lab: Lab) -> AsyncIterator[Browser]:
    with auth_lab.owner() as connection:
        connection.execute("DELETE FROM security.auth_rate_limits")
    policy = auth.settings(auth_lab.config)
    app = create_app(
        ApiSettings(
            app_env="test",
            database=auth_lab.database("api_reader"),
            auth=policy,
            allowed_hosts=["dashboard.example.test", "cve-api", "localhost", "127.0.0.1"],
        )
    )

    @app.get("/api/v1/auth/_protected")
    async def protected(
        user: Annotated[dict[str, Any], Depends(authenticated_user)],
    ) -> dict[str, Any]:
        return {"authenticated": True, "id": str(user["id"])}

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=policy.origin,
            headers={
                "origin": policy.origin,
                "x-cve-auth-gateway": app.state.auth.gateway,
                "x-cve-auth-scheme": "https",
                "x-real-ip": "192.0.2.8",
            },
        ) as client,
    ):
        yield Browser(client, app.state.auth, auth_lab)
