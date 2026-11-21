"""Actual importer image, HTTPS CONNECT, namespace isolation and PostgreSQL effects."""

import base64
import gzip
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
from cve_enricher.contracts import Configuration as EnrichmentConfiguration
from cve_importer.contracts import Configuration
from cve_importer.transport import HOSTS

from scripts.cve_enricher import manage as enrichment_ops
from scripts.cve_importer import manage
from scripts.infrastructure import envoy
from scripts.infrastructure.manage import compose, docker_command, run
from tests.cve_importer.conftest import Lab
from tests.cve_importer.test_pipeline import Wire
from tests.database.helpers import required_row

pytestmark = pytest.mark.cve_enricher


@dataclass
class Container:
    lab: Lab
    name: str
    sink: str
    configuration: Configuration

    def execute(self, code: str) -> str:
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
def runtime(enrich_lab: Lab) -> Iterator["Runtime"]:
    import_lab = enrich_lab
    config = import_lab.config
    manage.build(config)
    enrichment_ops.build(config)
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
    hosts = sorted(set().union(*HOSTS.values()) | {"epss.empiricalsecurity.com"})
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
    epss_body = gzip.compress(
        b"#model_version:v2026.06.15,score_date:2026-11-07T12:00:00Z\ncve,epss,percentile\nCVE-2026-12345,0.123456789,0.987654321\n",
        mtime=0,
    )
    responses.append(
        {
            "host": "epss.empiricalsecurity.com",
            "path": "/epss_scores-current.csv.gz",
            "status": None,
            "content_type": "application/gzip",
            "body": base64.b64encode(epss_body).decode(),
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
  if path.path.startswith('/epss_scores-') and Path('/fixture/slow').exists():
   import time;time.sleep(15)
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
    enricher_id = ""
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
        sinkip = info["NetworkSettings"]["Networks"][external]["IPAddress"]
        envoy.namespace_command(
            int(info["State"]["Pid"]), ["ip", "address", "add", "93.184.216.34/32", "dev", "lo"]
        )
        compose(config, ["up", "-d", "cve-importer"])
        container_id = compose(config, ["ps", "-q", "cve-importer"]).stdout.strip()
        policy = envoy.policy()
        policy["rules"] = [r for r in policy["rules"] if r["client"] == "importer"]
        policy["dns"] = {"address": sinkip, "port": 53, "refresh_seconds": 1, "timeout_seconds": 1}
        envoy.start(config, policy, {"importer": container_id})
        _, proxy_pid = envoy.netns(config)
        envoy.namespace_command(
            proxy_pid, ["ip", "route", "add", "93.184.216.34/32", "via", sinkip]
        )
        info = envoy.inspect_container(container_id)
        namespace = envoy.namespace_command(
            int(info["State"]["Pid"]), ["readlink", "/proc/self/ns/net"]
        ).stdout.strip()
        (base / "egress.ready").write_text(namespace + "\n")
        (base / "egress.ready").chmod(0o600)
        compose(config, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-importer"])
        source = Container(import_lab, container_id, sink, configuration)
        for source_name in ["cve_list", "nvd", "cisa_kev", "ubuntu", "osv"]:
            assert source.import_source(source_name)["effective_status"] == "completed"
        enrichment_ops.prepare(config)
        enrichment_base = enrichment_ops.directory(config)
        (enrichment_base / "sources.json").write_text(
            EnrichmentConfiguration(epss_enabled=True, epss_min_rows=1).model_dump_json(indent=2)
        )
        shutil.copyfile(files / "server.crt", enrichment_base / "external-ca.crt")
        (enrichment_base / "external-ca.crt").chmod(0o600)
        compose(config, ["up", "-d", "cve-enricher"])
        enricher_id = compose(config, ["ps", "-q", "cve-enricher"]).stdout.strip()
        policy["rules"] += [r for r in envoy.policy()["rules"] if r["client"] == "enricher"]
        envoy.start(config, policy, {"importer": container_id, "enricher": enricher_id})
        _, proxy_pid = envoy.netns(config)
        envoy.namespace_command(
            proxy_pid, ["ip", "route", "add", "93.184.216.34/32", "via", sinkip]
        )
        info = envoy.inspect_container(enricher_id)
        namespace = envoy.namespace_command(
            int(info["State"]["Pid"]), ["readlink", "/proc/self/ns/net"]
        ).stdout.strip()
        (enrichment_base / "egress.ready").write_text(namespace + "\n")
        (enrichment_base / "egress.ready").chmod(0o600)
        compose(config, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-enricher"])
        yield Runtime(import_lab, source, enricher_id)

    finally:
        if enricher_id:
            logs = run([*docker_command(), "logs", enricher_id])
            (base / "enricher-container.log").write_text(logs.stdout + logs.stderr)
            (base / "enricher-container.log").chmod(0o600)
            compose(config, ["stop", "cve-enricher"])
            compose(config, ["rm", "-f", "cve-enricher"])
        if container_id:
            logs = run([*docker_command(), "logs", container_id])
            (base / "container-test.log").write_text(logs.stdout + logs.stderr)
            (base / "container-test.log").chmod(0o600)
            compose(config, ["stop", "cve-importer"])
            compose(config, ["rm", "-f", "cve-importer"])
        compose(config, ["stop", "cve-egress-proxy"])
        compose(config, ["rm", "-f", "cve-egress-proxy"])
        subprocess.run([*docker_command(), "rm", "-f", sink], capture_output=True, check=False)


@dataclass
class Runtime:
    lab: Lab
    importer: Container
    enricher: str

    def execute(self, code: str) -> str:
        return run([*docker_command(), "exec", self.enricher, "python", "-c", code]).stdout.strip()

    def wait(self, job: Any) -> None:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            with self.lab.owner() as c:
                row = required_row(
                    c.execute("SELECT status,error_code FROM automation.jobs WHERE id=%s", (job,))
                )
            if row["status"] in {"succeeded", "failed", "timed_out"}:
                assert row["status"] == "succeeded", row
                return
            time.sleep(0.25)
        raise AssertionError("Enricher fixture job exceeded deadline")


def test_e2e_importer_envoy_enricher_and_first_dataset(runtime: Runtime) -> None:
    job = enrichment_ops.enqueue(runtime.lab.config, "cve.enrich.record", "CVE-2026-12345")
    runtime.wait(job)
    with runtime.lab.owner() as c:
        enriched = required_row(
            c.execute("SELECT * FROM cve.current_enrichment WHERE identity='CVE-2026-12345'")
        )
        assert enriched["result"]["lifecycle"]["value"] == "published"
        assert {r["source_id"] for r in enriched["result"]["inputs"]} >= {
            "cve_list",
            "nvd",
            "osv",
            "ubuntu",
            "cisa_kev",
        }
    job = enrichment_ops.enqueue(runtime.lab.config, "cve.epss.sync_daily")
    runtime.wait(job)
    with runtime.lab.owner() as c:
        score = required_row(
            c.execute("SELECT * FROM cve.current_epss_scores WHERE cve_id='CVE-2026-12345'")
        )
        assert str(score["score"]).startswith("0.123456789")
        assert (
            required_row(
                c.execute("SELECT id FROM cve.current_enrichment WHERE identity='CVE-2026-12345'")
            )["id"]
            == enriched["id"]
        )


def test_container_security_only_epss_proxy_and_verified_tls(runtime: Runtime) -> None:
    data = runtime.execute("""import httpx,json
results={}
for kind,url,proxy,verify in [
 ('direct','https://93.184.216.34/',None,False),
 ('metadata','http://169.254.169.254/latest/meta-data',None,False),
 ('non_epss','https://ubuntu.com/security/cves.json','http://cve-egress-proxy:3128',
  '/run/cve-enricher/external-ca.crt'),
 ('wrong_ca','https://epss.empiricalsecurity.com/epss_scores-current.csv.gz',
  'http://cve-egress-proxy:3128',True)]:
 try:
  with httpx.Client(proxy=proxy,verify=verify,trust_env=False,timeout=2) as client: client.get(url)
  results[kind]=False
 except Exception: results[kind]=True
print(json.dumps(results))
""")
    assert all(json.loads(data).values())
    info = envoy.inspect_container(runtime.enricher)
    assert info["HostConfig"]["ReadonlyRootfs"] and info["HostConfig"]["CapDrop"] == ["ALL"]
    assert not info["HostConfig"]["PortBindings"]
    assert not any("docker.sock" in m["Source"] for m in info["Mounts"])


def test_container_source_code_matches_image(runtime: Runtime) -> None:
    value = runtime.execute("""import cve_enricher,hashlib,json
from pathlib import Path
root=Path(cve_enricher.__file__).parent
print(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.glob('*.py')}))
""")
    import hashlib

    root = runtime.lab.config.root / "services/enricher/src/cve_enricher"
    assert json.loads(value) == {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.glob("*.py")
    }


def rebind(runtime: Runtime) -> None:
    config = runtime.lab.config
    base = enrichment_ops.directory(config)
    (base / "egress.ready").unlink(missing_ok=True)
    compose(config, ["up", "-d", "cve-enricher"])
    policy = json.loads((envoy.directory(config) / "policy.json").read_text())
    envoy.start(config, policy, {"importer": runtime.importer.name, "enricher": runtime.enricher})
    sinkinfo = envoy.inspect_container(runtime.importer.sink)
    sinkip = sinkinfo["NetworkSettings"]["Networks"][config.project + "_cve_egress_external"][
        "IPAddress"
    ]
    _, pid = envoy.netns(config)
    envoy.namespace_command(pid, ["ip", "route", "add", "93.184.216.34/32", "via", sinkip])
    client = envoy.inspect_container(runtime.enricher)
    namespace = envoy.namespace_command(
        int(client["State"]["Pid"]), ["readlink", "/proc/self/ns/net"]
    ).stdout.strip()
    (base / "egress.ready").write_text(namespace + "\n")
    (base / "egress.ready").chmod(0o600)
    compose(config, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-enricher"])


def test_container_postgres_outage_recovery(runtime: Runtime) -> None:
    compose(runtime.lab.config, ["stop", "cve-postgres"])
    try:
        assert (
            runtime.execute("""import urllib.request,urllib.error
try: urllib.request.urlopen('http://127.0.0.1:8000/health/ready',timeout=15);print('unexpected')
except urllib.error.HTTPError as e: print(e.code)
""")
            == "503"
        )
    finally:
        compose(runtime.lab.config, ["up", "-d", "--wait", "cve-postgres"])
    runtime.wait(enrichment_ops.enqueue(runtime.lab.config, "cve.enrich.record", "CVE-2026-12345"))


def test_container_proxy_outage_no_direct_fallback(runtime: Runtime) -> None:
    config = runtime.lab.config
    with runtime.lab.owner() as c:
        old = required_row(c.execute("SELECT dataset_id FROM cve.epss_current_dataset"))[
            "dataset_id"
        ]
    compose(config, ["stop", "cve-egress-proxy"])
    try:
        job = enrichment_ops.enqueue(config, "cve.epss.sync_daily")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            with runtime.lab.owner() as c:
                row = required_row(
                    c.execute("SELECT status FROM automation.jobs WHERE id=%s", (job,))
                )
            if row["status"] == "retry_pending":
                break
            time.sleep(0.25)
        assert row["status"] == "retry_pending"
        with runtime.lab.owner() as c:
            assert (
                required_row(c.execute("SELECT dataset_id FROM cve.epss_current_dataset"))[
                    "dataset_id"
                ]
                == old
            )
    finally:
        rebind(runtime)
    runtime.wait(job)


def test_container_worker_sigkill_lease_recovery(runtime: Runtime) -> None:
    marker = manage.directory(runtime.lab.config) / "fixture/slow"
    marker.touch()
    job = enrichment_ops.enqueue(runtime.lab.config, "cve.epss.sync_daily")
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        with runtime.lab.owner() as c:
            row = required_row(c.execute("SELECT status FROM automation.jobs WHERE id=%s", (job,)))
        if row["status"] == "running":
            break
        time.sleep(0.1)
    assert row["status"] == "running"
    run([*docker_command(), "kill", "--signal", "KILL", runtime.enricher])
    marker.unlink()
    rebind(runtime)
    runtime.wait(job)
    with runtime.lab.owner() as c:
        assert (
            required_row(c.execute("SELECT attempts FROM automation.jobs WHERE id=%s", (job,)))[
                "attempts"
            ]
            >= 2
        )
