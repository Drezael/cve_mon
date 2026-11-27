"""Actual importer image, HTTPS CONNECT, namespace isolation and PostgreSQL effects."""

import base64
import json
import os
import shutil
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

import httpx
import pytest
from cve_importer.contracts import Configuration
from cve_importer.transport import HOSTS

from scripts.cve_importer import manage
from scripts.infrastructure import envoy
from scripts.infrastructure.manage import compose, docker_command, run
from scripts.infrastructure.topology import PORTS
from tests.cve_importer import direct
from tests.cve_importer.conftest import Lab
from tests.cve_importer.test_pipeline import Wire
from tests.database.helpers import required_row

pytestmark = pytest.mark.cve_importer


@dataclass
class Container:
    lab: Lab
    name: str
    sink: str
    configuration: Configuration

    def execute(self, code: str) -> str:
        code = code.replace("127.0.0.1:8000", f"127.0.0.1:{PORTS['cve-importer']}")
        return run([*docker_command(), "exec", self.name, "python", "-c", code]).stdout.strip()

    def import_source(self, source: str) -> Any:
        # Pause during fixture-only timestamp pinning; scheduling itself uses the real API role.
        run([*docker_command(), "pause", self.name])
        try:
            run_id = manage.enqueue(self.lab.config, source, "initial", str(uuid4()))
            if source == "nvd":
                with self.lab.owner() as c:
                    c.execute(
                        "UPDATE cve.import_runs SET created_at='1970-01-02T00:00:00Z' WHERE id=%s",
                        (run_id,),
                    )
        finally:
            run([*docker_command(), "unpause", self.name])
        end = time.monotonic() + 90
        while time.monotonic() < end:
            with self.lab.owner() as c:
                row = required_row(
                    c.execute("SELECT * FROM cve.import_run_status WHERE id=%s", (run_id,))
                )
            if row["effective_status"] in {"completed", "partial", "failed", "cancelled"}:
                return row
            time.sleep(0.25)
        raise AssertionError("Container source import exceeded fixture deadline")


@pytest.fixture(scope="module")
def container(import_lab: Lab) -> Iterator[Container]:
    config = import_lab.config
    # Never test a stale generated build context left by an earlier phase.
    manage.build(config)
    manage.prepare(config)
    configuration = Configuration(
        enabled=["cve_list", "nvd", "cisa_kev", "ubuntu", "osv"],
        cve_list_transport="release",
        epss_enabled=True,
        osv_ecosystems=["PyPI"],
        minimum_delay=0,
        max_retry_delay=1,
    )
    base = manage.directory(config)
    (base / "sources.json").write_text(configuration.model_dump_json(indent=2))
    files = base / "fixture"
    files.mkdir(mode=0o700)
    support = config.root / "tests/infrastructure/envoy/fixtures/servers.py"
    shutil.copyfile(support, files / "support.py")
    hosts = sorted(set().union(*HOSTS.values()))
    config = direct.configuration(config, hosts)
    run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-keyout",
            str(files / "server.key"),
            "-out",
            str(files / "server.crt"),
            "-subj",
            "/CN=phase15.fixture",
            "-addext",
            "subjectAltName=" + ",".join("DNS:" + h for h in hosts),
        ]
    )
    (files / "server.key").chmod(0o600)
    shutil.copyfile(files / "server.crt", base / "external-ca.crt")
    (base / "external-ca.crt").chmod(0o600)
    wire = Wire()
    urls = [
        "https://api.github.com/repos/CVEProject/cvelistV5/releases?per_page=1",
        "https://github.com/CVEProject/cvelistV5/releases/download/cve_202"
        "6-11-07_2100Z/2026-11-07_all_CVEs_at_midnight.zip.zip",
        "https://github.com/CVEProject/cvelistV5/releases/download/cve_202"
        "6-11-07_2100Z/2026-11-07_delta_CVEs_at_2100Z.zip",
        "https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=0&resultsPerPage=1000",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip",
    ]
    for status in ["active", "not-in-ubuntu", "rejected"]:
        urls.append(
            "https://ubuntu.com/security/cves.json?limit=20&offset=0&order=des"
            "cending&sort_by=updated&cve_status=" + status
        )
    urls.append("https://ubuntu.com/security/notices.json?limit=20&offset=0&order=newest")
    responses = []
    for url in urls:
        request = httpx.Request("GET", url)
        response = wire(request)
        response.read()
        responses.append(
            {
                "host": request.url.host,
                "path": request.url.path,
                "status": request.url.params.get("cve_status"),
                "content_type": response.headers["content-type"],
                "body": base64.b64encode(response.content).decode(),
            }
        )
    (files / "responses.json").write_text(json.dumps(responses))
    (files / "hosts.json").write_text(json.dumps(hosts))
    (files / "server.py").write_text("""import base64,json,threading
from pathlib import Path
from urllib.parse import urlsplit,parse_qs
import support as s
responses=json.loads(Path('/fixture/responses.json').read_text())
hosts=json.loads(Path('/fixture/hosts.json').read_text())
s.state['records']={h:['A','93.184.216.34'] for h in hosts}
class Handler(s.HTTP):
 def do_GET(self):
  path=urlsplit(self.path)
  status=parse_qs(path.query).get('cve_status',[None])[0]
  row=next((r for r in responses if r['path']==path.path and r['status']==status),None)
  if row is None:
   self.send_error(404);return
  payload=base64.b64decode(row['body'])
  self.send_response(200)
  self.send_header('Content-Type',row['content_type'])
  self.send_header('Content-Length',str(len(payload)))
  self.end_headers();self.wfile.write(payload)
servers=[s.TLSHTTP(('0.0.0.0',443),Handler),s.socketserver.ThreadingUDPServer(('0.0.0.0',53),s.DNS)]
for server in servers: threading.Thread(target=server.serve_forever,daemon=True).start()
Path('/tmp/fixture-ready').touch()
threading.Event().wait()
""")
    external = config.project + "_cve_egress_external"
    sink = config.project + "-source-fixture"
    container_id = ""
    try:
        run(
            [
                *docker_command(),
                "network",
                "create",
                "--label",
                "com.docker.compose.project=" + config.project,
                "--label",
                "com.docker.compose.network=cve_egress_external",
                external,
            ]
        )
        run(
            [
                *docker_command(),
                "run",
                "-d",
                "--name",
                sink,
                "--network",
                external,
                "--label",
                "org.cve-monitoring.importer-test=" + config.project,
                "--user",
                f"{os.getuid()}:{os.getgid()}",
                "--cap-drop",
                "ALL",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,size=8m",
                "-v",
                str(files) + ":/fixture:ro",
                "python@sha256:e064671ca452259bab50e8e2c7bd896e39e9a343bb06ca25234adf6fe18d0fc7",
                "python",
                "/fixture/server.py",
            ]
        )
        info = envoy.inspect_container(sink)
        envoy.namespace_command(
            int(info["State"]["Pid"]), ["ip", "address", "add", "93.184.216.34/32", "dev", "lo"]
        )
        compose(config, ["up", "-d", "cve-importer"])
        container_id = compose(config, ["ps", "-q", "cve-importer"]).stdout.strip()
        direct.route(config, sink)
        compose(config, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-importer"])
        yield Container(Lab(config), container_id, sink, configuration)
    finally:
        try:
            if container_id:
                logs = subprocess.run(
                    [*docker_command(), "logs", container_id],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                (base / "container-test.log").write_text(logs.stdout + logs.stderr)
                (base / "container-test.log").chmod(0o600)
                compose(config, ["rm", "-s", "-f", "cve-processing"])
        finally:
            from tests.resources import remove

            try:
                remove("container", sink, "org.cve-monitoring.importer-test", config.project)
            finally:
                remove("network", external, "com.docker.compose.project", config.project)


@pytest.mark.parametrize("source", ["cve_list", "nvd", "cisa_kev", "ubuntu", "osv"])
def test_e2e_actual_container_direct_https(container: Container, source: str) -> None:
    row = container.import_source(source)
    assert row["effective_status"] == "completed", row
    assert row["read_count"] >= 1 and row["download_bytes"] > 0


def test_container_security_egress_and_tls(container: Container) -> None:
    result = container.execute("""import httpx,json
results={}
for kind,url,proxy,verify in [
 ('plaintext','http://93.184.216.34/',None,False),
 ('metadata','http://169.254.169.254/latest/meta-data',None,False),
 ('unauthorized','https://forbidden.example.test/',None,True),
 ('wrong_ca','https://ubuntu.com/security/cves.json',None,True)]:
 try:
  with httpx.Client(proxy=proxy,verify=verify,trust_env=False,timeout=2) as c: c.get(url)
  results[kind]=False
 except Exception: results[kind]=True
print(json.dumps(results))
""")
    assert all(json.loads(result).values())
    info = envoy.inspect_container(container.name)
    assert info["HostConfig"]["ReadonlyRootfs"] and info["HostConfig"]["CapDrop"] == ["ALL"]
    assert not info["HostConfig"]["PortBindings"]
    assert not any("docker.sock" in m["Source"] for m in info["Mounts"])
    assert info["HostConfig"]["Memory"] > 0


def rebind(container: Container) -> None:
    direct.rebind(container.lab.config, container.sink)


def test_container_postgres_outage_recovery(container: Container) -> None:
    compose(container.lab.config, ["stop", "cve-postgres"])
    try:
        assert (
            container.execute("""import urllib.request,urllib.error
try: urllib.request.urlopen('http://127.0.0.1:8000/health/ready',timeout=15);print('unexpected')
except urllib.error.HTTPError as e: print(e.code)
""")
            == "503"
        )
    finally:
        compose(container.lab.config, ["up", "-d", "--wait", "cve-postgres"])
    assert container.import_source("cisa_kev")["effective_status"] == "completed"


def test_container_upstream_outage_no_partial_commit_and_recovery(container: Container) -> None:
    config = container.lab.config
    with container.lab.owner() as c:
        previous = c.execute(
            "SELECT cursor FROM cve.source_streams WHERE source_id='cisa_kev'"
        ).fetchall()
    direct.outage(config)
    try:
        run_id = manage.enqueue(config, "cisa_kev", "reconcile", str(uuid4()))
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            with container.lab.owner() as c:
                row = required_row(
                    c.execute("SELECT * FROM cve.import_run_status WHERE id=%s", (run_id,))
                )
            if row["job_status"] == "retry_pending":
                break
            time.sleep(0.25)
        assert row["effective_status"] != "completed" and row["read_count"] == 0
        with container.lab.owner() as c:
            assert (
                c.execute(
                    "SELECT cursor FROM cve.source_streams WHERE source_id='cisa_kev'"
                ).fetchall()
                == previous
            )
    finally:
        rebind(container)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        with container.lab.owner() as c:
            row = required_row(
                c.execute("SELECT * FROM cve.import_run_status WHERE id=%s", (run_id,))
            )
        if row["effective_status"] == "completed":
            break
        time.sleep(0.25)
    assert row["effective_status"] == "completed", row


def test_container_worker_sigkill_recovery(container: Container) -> None:
    config = container.lab.config
    with container.lab.owner() as c:
        c.execute(
            "INSERT INTO cve.request_limits "
            "VALUES('cisa_kev',clock_timestamp()+interval '15 seconds') ON "
            "CONFLICT(source_id) DO UPDATE SET next_at=excluded.next_at"
        )
    run_id = manage.enqueue(config, "cisa_kev", "reconcile", str(uuid4()))
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        with container.lab.owner() as c:
            row = required_row(
                c.execute("SELECT * FROM cve.import_run_status WHERE id=%s", (run_id,))
            )
        if row["job_status"] == "running":
            break
        time.sleep(0.1)
    assert row["job_status"] == "running"
    run([*docker_command(), "kill", "--signal", "KILL", container.name])
    # Reinstallation binds the new process namespace before any resumed source request.
    rebind(container)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        with container.lab.owner() as c:
            row = required_row(
                c.execute("SELECT * FROM cve.import_run_status WHERE id=%s", (run_id,))
            )
        if row["effective_status"] in {"completed", "failed", "partial"}:
            break
        time.sleep(0.25)
    assert row["effective_status"] == "completed" and row["attempts"] >= 2, row


def test_container_installed_sources_match_workspace(container: Container) -> None:
    result = container.execute("""import hashlib,json
from pathlib import Path
import cve_importer
root=Path(cve_importer.__file__).parent
files=(p for p in root.rglob('*') if p.is_file())
values={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()
 for p in files if p.suffix in {'.py','.json'} or p.name=='py.typed'}
print(json.dumps(values))
""")
    root = container.lab.config.root / "services/importer/src/cve_importer"
    import hashlib

    expected = {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in root.rglob("*")
        if p.is_file() and (p.suffix in {".py", ".json"} or p.name == "py.typed")
    }
    assert json.loads(result) == expected
