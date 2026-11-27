"""Actual unprivileged findings image, native TLS/PG readiness and namespace isolation."""

import json
import os
import time
from collections.abc import Iterator
from typing import Any

import pytest

from scripts.cve_findings import manage
from scripts.infrastructure import envoy
from scripts.infrastructure.manage import Config, compose, docker_command, run
from scripts.infrastructure.topology import PORTS
from tests.authentication.integration.conftest import Lab

pytestmark = pytest.mark.findings


@pytest.fixture(scope="module")
def findings_container(upload_lab: Lab) -> Iterator[tuple[Config, str]]:
    cfg = upload_lab.config
    manage.build(cfg)
    manage.start(cfg)
    identity = compose(cfg, ["ps", "-q", "cve-findings"]).stdout.strip()
    try:
        yield cfg, identity
    finally:
        compose(cfg, ["stop", "cve-findings"])


def execute(identity: str, code: str) -> dict[str, Any]:
    code = code.replace("127.0.0.1:8000", f"127.0.0.1:{PORTS['cve-findings']}")
    value = json.loads(run([*docker_command(), "exec", identity, "python", "-c", code]).stdout)
    assert isinstance(value, dict)
    return value


def test_e2e_container_health_and_metrics(findings_container: tuple[Config, str]) -> None:
    _, identity = findings_container
    data = execute(
        identity,
        (
            "import json,urllib.request; print(json.dumps({p:json.load(urllib."
            "request.urlopen('http://127.0.0.1:8000/'+p)) for p in ['health/li"
            "ve','health/ready','metrics']}))"
        ),
    )
    assert data["health/ready"]["status"] == "ready"
    assert "queued" in data["metrics"]


def test_network_allows_https_and_blocks_private_peers(
    findings_container: tuple[Config, str],
) -> None:
    cfg, identity = findings_container
    api = envoy.inspect_container(compose(cfg, ["ps", "-q", "cve-api"]).stdout.strip())
    networks = api["NetworkSettings"]["Networks"]
    peer = next(iter(networks.values()))["IPAddress"]
    code = """import socket,json
out={}
for host,port in [("1.1.1.1",443),("169.254.169.254",80),("172.17.0.1",22),("PEER",8000)]:
 try:
  s=socket.create_connection((host,port),timeout=1);s.close();out[host]=True
 except OSError:out[host]=False
print(json.dumps(out))""".replace("PEER", peer)
    result = execute(identity, code)
    assert result.pop("1.1.1.1") is True
    assert not any(result.values())


def test_container_security_configuration(findings_container: tuple[Config, str]) -> None:
    _, identity = findings_container
    value = envoy.inspect_container(identity)
    host = value["HostConfig"]
    assert not host["Privileged"] and host["ReadonlyRootfs"] and host["CapDrop"] == ["ALL"]
    assert not host["PortBindings"]
    assert all("docker.sock" not in m["Source"] for m in value["Mounts"])
    assert value["Config"]["User"].split(":")[0] != "0"
    assert (
        execute(identity, "import os,json;print(json.dumps({'uid':os.getuid()}))")["uid"]
        == os.getuid()
    )


def test_guard_proof_fail_closed(findings_container: tuple[Config, str]) -> None:
    cfg, identity = findings_container
    path = manage.directory(cfg) / "guard.ready"
    before = path.read_bytes()
    path.unlink()
    try:
        value = execute(
            identity,
            (
                "import urllib.request,urllib.error,json\ntry:\n r=urllib.request.ur"
                "lopen('http://127.0.0.1:8000/health/ready');code=r.status\nexcept "
                "urllib.error.HTTPError as e:code=e.code\nprint(json.dumps({'status"
                "':code}))"
            ),
        )
        assert value["status"] == 503
    finally:
        path.write_bytes(before)
        path.chmod(0o600)


def test_worker_sigkill_restart_and_guard_recovery(findings_container: tuple[Config, str]) -> None:
    cfg, identity = findings_container
    run([*docker_command(), "kill", "--signal", "KILL", identity])
    compose(cfg, ["up", "-d", "cve-findings"])
    for _ in range(40):
        if envoy.inspect_container(identity)["State"]["Running"]:
            break
        time.sleep(0.1)
    manage.guard(cfg)
    envoy.wait_client_ready(cfg, "cve-findings")
    assert envoy.inspect_container(identity)["State"]["Health"]["Status"] == "healthy"


def test_postgres_outage_readiness_and_recovery(findings_container: tuple[Config, str]) -> None:
    cfg, identity = findings_container
    compose(cfg, ["stop", "cve-postgres"])
    try:
        value = execute(
            identity,
            (
                "import urllib.request,urllib.error,json\ntry:\n r=urllib.request.ur"
                "lopen('http://127.0.0.1:8000/health/ready');code=r.status\nexcept "
                "urllib.error.HTTPError as e:code=e.code\nprint(json.dumps({'status"
                "':code}))"
            ),
        )
        assert value["status"] == 503
    finally:
        compose(cfg, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-postgres"])
        manage.guard(cfg)
        envoy.wait_client_ready(cfg, "cve-findings")


def test_real_container_worker_reconcile(findings_container: tuple[Config, str]) -> None:
    from cve_findings.contracts import Request

    from scripts.database import manage as db

    cfg, _ = findings_container
    job = manage.enqueue(cfg, "reconcile", Request())
    for _ in range(100):
        with db.connect(cfg, "findings_writer") as c:
            row = c.execute("SELECT status FROM automation.jobs WHERE id=%s", (job,)).fetchone()
            assert row is not None
            if row["status"] in {"succeeded", "failed", "timed_out"}:
                assert row["status"] == "succeeded"
                return
        time.sleep(0.1)
    raise AssertionError("Real finding worker did not finish")


def test_image_source_hashes_match_workspace(findings_container: tuple[Config, str]) -> None:
    import hashlib
    from pathlib import Path

    _, identity = findings_container
    data = execute(
        identity,
        "import cve_findings,hashlib,json;from pathlib import Path;"
        "r=Path(cve_findings.__file__).parent;"
        "print(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() "
        "for p in r.glob('*.py')}))",
    )
    expected = {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in Path("services/findings/src/cve_findings").glob("*.py")
    }
    assert data == expected
