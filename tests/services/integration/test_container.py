"""Real container readiness recovery, hardening, DNS and disabled ingress routes."""

import asyncio
import json

import pytest

from scripts.database import manage as db
from scripts.infrastructure.manage import compose, docker_command, run
from scripts.services import manage as api
from tests.services.integration.conftest import Lab

pytestmark = [pytest.mark.services_integration, pytest.mark.security]


def request(lab: Lab, path: str) -> dict[str, object]:
    code = (
        "import json,urllib.request,urllib.error; "
        'u="http://127.0.0.1:8000' + path + '"; '
        'exec("try:\\n r=urllib.request.urlopen(u,timeout=3)\\n'
        'except urllib.error.HTTPError as e:\\n r=e"); '
        'print(json.dumps({"status":r.code,"body":json.loads(r.read())}))'
    )
    return dict(
        json.loads(
            run(
                [*docker_command(), "exec", api.container(lab.config)["Id"], "python", "-c", code]
            ).stdout
        )
    )


def test_container_and_nginx_dns(service_lab: Lab) -> None:
    lab = service_lab
    info = api.container(lab.config)
    assert info["State"]["Health"]["Status"] == "healthy"
    version = run(
        [
            *docker_command(),
            "exec",
            info["Id"],
            "python",
            "-c",
            "import sys; print(sys.version_info[:2])",
        ]
    ).stdout
    assert version.strip() == "(3, 12)"
    assert info["HostConfig"]["ReadonlyRootfs"] and not info["HostConfig"]["Privileged"]
    assert not info["HostConfig"]["CapAdd"] and not info["HostConfig"]["PortBindings"]
    assert set(info["NetworkSettings"]["Networks"]) == {
        lab.config.project + "_cve_internal",
        lab.config.project + "_cve_data",
    }
    assert info["Config"]["User"].split(":")[0] != "0"
    assert {m["Destination"] for m in info["Mounts"]} == {"/run/cve-api", "/run/cve-status"}
    assert all(m["RW"] is False for m in info["Mounts"])
    nginx = compose(lab.config, ["ps", "-q", "cve-nginx"]).stdout.strip()
    reply = run(
        [
            *docker_command(),
            "exec",
            nginx,
            "wget",
            "-q",
            "-O",
            "-",
            "http://cve-api:8000/health/ready",
        ]
    ).stdout
    assert json.loads(reply)["status"] == "ready"
    for path in (
        "/api/v1/servers",
        "/api/v1/users",
        "/api/v1/inventories",
        "/docs",
        "/openapi.json",
    ):
        assert request(lab, path)["status"] == (405 if path == "/api/v1/inventories" else 404)
    denied = run(
        [
            *docker_command(),
            "exec",
            info["Id"],
            "python",
            "-c",
            'import socket;s=socket.socket();s.settimeout(.5);print(s.connect_ex(("1.1.1.1",443)))',
        ]
    ).stdout
    assert denied.strip() != "0"


async def test_outage_recovery_and_restart(service_lab: Lab) -> None:
    lab = service_lab
    compose(lab.config, ["stop", "cve-postgres"])
    try:
        assert request(lab, "/health/live")["status"] == 200
        result = request(lab, "/health/ready")
        assert result["status"] == 503
        assert "password" not in json.dumps(result).lower()
    finally:
        compose(lab.config, ["up", "-d", "--wait", "--wait-timeout", "40", "cve-postgres"])
    for _ in range(20):
        if request(lab, "/health/ready")["status"] == 200:
            break
        await asyncio.sleep(0.3)
    else:
        raise AssertionError("Readiness did not recover")
    compose(lab.config, ["restart", "cve-api"])
    compose(lab.config, ["up", "-d", "--wait", "--wait-timeout", "40", "cve-api"])
    assert request(lab, "/health/ready")["status"] == 200
    logs = compose(lab.config, ["logs", "--no-color", "cve-api"]).stdout
    assert db.read_secret(db.secret_file(lab.config, "api_reader")) not in logs
    for line in logs.splitlines():
        if " | " in line:
            json.loads(line.split(" | ", 1)[1])


def test_shared_collection_contracts_are_in_installed_container(service_lab: Lab) -> None:
    result = run(
        [
            *docker_command(),
            "exec",
            api.container(service_lab.config)["Id"],
            "python",
            "-c",
            "from cve_api.inventories.parser import schema; "
            "assert schema('1.0')['properties']['schema_version']['const']=='1.0'; "
            "assert schema('1.1')['properties']['schema_version']['const']=='1.1'; "
            "assert 'images' in schema('1.1')['properties']; print('contracts packaged')",
        ]
    )
    assert result.stdout.strip() == "contracts packaged"
