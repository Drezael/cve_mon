"""Native Docker dispatcher, authenticated HTTPS, retries and recovery, with no hostports."""

import json
import os
import secrets
import shutil
import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pytest
from cve_common.database.transactions import transaction
from cve_common.events.outbox import Outbox
from cve_common.jobs.repository import JobRepository

from scripts.automation import manage as automation
from scripts.database import manage as db
from scripts.infrastructure.manage import compose, docker_command, run
from scripts.services.manage import PYTHON_IMAGE
from tests.automation.integration.conftest import Lab, event_registry
from tests.automation.integration.test_events import event

pytestmark = [pytest.mark.automation, pytest.mark.security]


@dataclass
class DispatcherLab:
    lab: Lab
    sink: str

    def control(self, **values: Any) -> dict[str, Any]:
        code = (
            'import sys,json,urllib.request;v=json.load(sys.stdin);u="http://127.0.0.1:8080/control";'
            'r=urllib.request.Request(u,data=json.dumps(v).encode(),method="POST") if v else u;'
            "print(urllib.request.urlopen(r).read().decode())"
        )
        return dict(
            json.loads(
                run(
                    [*docker_command(), "exec", "-i", self.sink, "python", "-c", code],
                    input=json.dumps(values),
                ).stdout
            )
        )

    def inspect(self) -> dict[str, Any]:
        name = compose(self.lab.config, ["ps", "-aq", "cve-event-dispatcher"]).stdout.strip()
        return dict(json.loads(run([*docker_command(), "inspect", name]).stdout)[0])

    def status(self, event_id: object) -> str:
        with db.connect(self.lab.config, "event_dispatcher") as connection:
            row = connection.execute(
                "SELECT status FROM automation.event_deliveries WHERE event_id=%s "
                "AND destination='https_sink'",
                (event_id,),
            ).fetchone()
            assert row is not None
            return str(row["status"])

    def wait(self, predicate: Any, timeout: float = 15) -> None:
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            if predicate():
                return
            time.sleep(0.1)
        raise AssertionError("Dispatcher condition did not become true")


@pytest.fixture(scope="module")
def dispatcher_lab(automation_lab: Lab) -> Iterator[DispatcherLab]:
    config = automation_lab.config
    automation.build(config)
    automation.prepare(config)
    base = automation.directory(config)
    fixture = base / "receiver"
    fixture.mkdir(mode=0o700)
    private = base / "private"
    private.mkdir(mode=0o700)
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
            str(private / "ca.key"),
            "-out",
            str(base / "receiver-ca.crt"),
            "-subj",
            "/CN=Phase07 Receiver CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ]
    )
    for name, host in [("server", "cve-automation-sink"), ("wrong", "cve-wrong-sink")]:
        run(
            [
                "openssl",
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(fixture / (name + ".key")),
                "-out",
                str(private / (name + ".csr")),
                "-subj",
                "/CN=" + host,
            ]
        )
        ext = private / (name + ".ext")
        ext.write_text("subjectAltName=DNS:" + host + "\nextendedKeyUsage=serverAuth\n")
        run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(private / (name + ".csr")),
                "-CA",
                str(base / "receiver-ca.crt"),
                "-CAkey",
                str(private / "ca.key"),
                "-CAcreateserial",
                "-out",
                str(fixture / (name + ".crt")),
                "-days",
                "2",
                "-sha256",
                "-extfile",
                str(ext),
            ]
        )
        (fixture / (name + ".key")).chmod(0o600)
    token = secrets.token_urlsafe(48)
    for path in (base / "receiver-token", fixture / "auth_token"):
        path.write_text(token)
        path.chmod(0o600)
    targets = [
        {
            "id": "https_sink",
            "origin": "https://cve-automation-sink:8443",
            "token_file": "/run/cve-dispatcher/receiver-token",
            "ca_file": "/run/cve-dispatcher/receiver-ca.crt",
            "timeout": 0.4,
        }
    ]
    (base / "targets.json").write_text(json.dumps(targets))
    shutil.copyfile(config.root / "tests/automation/fixtures/receiver.py", fixture / "receiver.py")
    with db.connect(config, "cve_migrator") as connection:
        connection.execute("SET ROLE postgres_owner")
        connection.execute(
            "INSERT INTO automation.delivery_targets(id,enabled,retry_base,ret"
            "ry_cap,max_attempts) VALUES ('https_sink',true,.5,1,3)"
        )
        connection.execute(
            "INSERT INTO automation.event_routes VALUES ('technical.event','https_sink')"
        )
    compose(config, ["create", "cve-event-dispatcher"])
    sink = config.project + "-https-sink"
    run(
        [
            *docker_command(),
            "run",
            "-d",
            "--name",
            sink,
            "--label",
            "org.cve-monitoring.automation-test=" + config.project,
            "--network",
            config.project + "_cve_internal",
            "--network-alias",
            "cve-automation-sink",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--user",
            str(os.getuid()) + ":" + str(os.getgid()),
            "-v",
            str(fixture) + ":/fixture:ro",
            PYTHON_IMAGE,
            "python",
            "/fixture/receiver.py",
        ]
    )
    try:
        compose(config, ["up", "-d", "--wait", "--wait-timeout", "40", "cve-event-dispatcher"])
        yield DispatcherLab(automation_lab, sink)
    finally:
        compose(config, ["stop", "cve-event-dispatcher"])
        info = json.loads(run([*docker_command(), "inspect", sink]).stdout)[0]
        assert info["Config"]["Labels"].get("org.cve-monitoring.automation-test") == config.project
        run([*docker_command(), "rm", "-f", sink])


async def test_https_delivery_and_container_hardening(
    producer: JobRepository, dispatcher_lab: DispatcherLab
) -> None:
    lab = dispatcher_lab
    lab.control(mode="ok", messages=[])
    value = event()
    async with transaction(producer.database) as session:
        await Outbox(event_registry()).emit(session, value)
    lab.wait(lambda: lab.status(value.event_id) == "delivered")
    assert any(
        message["event_id"] == str(value.event_id) and message["idempotency"] == str(value.event_id)
        for message in lab.control()["messages"]
    )
    info = lab.inspect()
    assert info["State"]["Health"]["Status"] == "healthy"
    assert (
        not info["HostConfig"]["PortBindings"]
        and not info["HostConfig"]["Privileged"]
        and not info["HostConfig"]["CapAdd"]
    )
    assert info["HostConfig"]["ReadonlyRootfs"] and info["Config"]["User"].split(":")[0] != "0"
    assert set(info["NetworkSettings"]["Networks"]) == {
        lab.lab.config.project + "_cve_internal",
        lab.lab.config.project + "_cve_data",
    }


@pytest.mark.parametrize("mode", ["bad_auth", "wrong_tls", "perm", "redirect"])
async def test_secure_failures_never_deliver(
    producer: JobRepository, dispatcher_lab: DispatcherLab, mode: str
) -> None:
    lab = dispatcher_lab
    lab.control(mode=mode, messages=[])
    value = event()
    async with transaction(producer.database) as session:
        await Outbox(event_registry()).emit(session, value)
    lab.wait(lambda: lab.status(value.event_id) == "failed")
    assert not any(
        message["event_id"] == str(value.event_id) for message in lab.control()["messages"]
    )
    lab.control(mode="ok")


async def test_receiver_outage_retry_and_uncertain_ack(
    producer: JobRepository, dispatcher_lab: DispatcherLab
) -> None:
    lab = dispatcher_lab
    lab.control(mode="temp", messages=[])
    value = event()
    async with transaction(producer.database) as session:
        await Outbox(event_registry()).emit(session, value)
    lab.wait(lambda: lab.status(value.event_id) == "retry_pending")
    lab.control(mode="ok")
    lab.wait(lambda: lab.status(value.event_id) == "delivered")
    lab.control(mode="drop_after_accept", messages=[])
    uncertain = event()
    async with transaction(producer.database) as session:
        await Outbox(event_registry()).emit(session, uncertain)
    lab.wait(lambda: len(lab.control()["messages"]) >= 1)
    lab.control(mode="ok")
    lab.wait(lambda: lab.status(uncertain.event_id) == "delivered")
    ids = [message["event_id"] for message in lab.control()["messages"]]
    assert ids.count(str(uncertain.event_id)) >= 2


async def test_dispatcher_restart_and_db_outage(
    producer: JobRepository, dispatcher_lab: DispatcherLab
) -> None:
    lab = dispatcher_lab
    config = lab.lab.config
    compose(config, ["stop", "cve-event-dispatcher"])
    value = event()
    async with transaction(producer.database) as session:
        await Outbox(event_registry()).emit(session, value)
    compose(config, ["up", "-d", "--wait", "--wait-timeout", "40", "cve-event-dispatcher"])
    lab.wait(lambda: lab.status(value.event_id) == "delivered")
    compose(config, ["stop", "cve-postgres"])
    try:
        info = lab.inspect()
        reply = run(
            [
                *docker_command(),
                "exec",
                info["Id"],
                "python",
                "-c",
                'import urllib.request; print(urllib.request.urlopen("http://localhost:8000/health/live").status)',
            ]
        ).stdout
        assert reply.strip() == "200"
    finally:
        compose(config, ["up", "-d", "--wait", "--wait-timeout", "40", "cve-postgres"])
    compose(config, ["up", "-d", "--wait", "--wait-timeout", "40", "cve-event-dispatcher"])
    logs = compose(config, ["logs", "--no-color", "cve-event-dispatcher"]).stdout
    for name in ("event_dispatcher.password", "receiver-token"):
        assert (automation.directory(config) / name).read_text().strip() not in logs


async def test_no_database_lock_during_slow_https(
    producer: JobRepository, dispatcher_lab: DispatcherLab
) -> None:
    lab = dispatcher_lab
    lab.control(mode="slow", messages=[])
    value = event()
    async with transaction(producer.database) as session:
        await Outbox(event_registry()).emit(session, value)
    lab.wait(lambda: lab.status(value.event_id) == "running")
    with db.connect(lab.lab.config, "cve_migrator") as connection:
        connection.execute("SET ROLE postgres_owner")
        row = connection.execute(
            "SELECT event_id FROM automation.event_deliveries WHERE event_id=%"
            "s AND destination='https_sink' FOR UPDATE NOWAIT",
            (value.event_id,),
        ).fetchone()
        assert row is not None
    lab.control(mode="ok")
    lab.wait(lambda: lab.status(value.event_id) == "delivered")


async def test_sigkill_dispatcher_reclaims_persistent_delivery(
    producer: JobRepository, dispatcher_lab: DispatcherLab
) -> None:
    from cve_common.database.engine import Database
    from cve_common.events.delivery import Delivery, DeliveryRepository

    lab = dispatcher_lab
    lab.control(mode="slow", messages=[])
    value = event()
    async with transaction(producer.database) as session:
        await Outbox(event_registry()).emit(session, value)
    old = None
    for _ in range(100):
        with db.connect(lab.lab.config, "event_dispatcher") as connection:
            oldrow = connection.execute(
                "SELECT * FROM automation.event_deliveries WHERE event_id=%s "
                "AND destination='https_sink' AND status='running'",
                (value.event_id,),
            ).fetchone()
            if oldrow is not None:
                old = Delivery.model_validate(oldrow)
                break
        time.sleep(0.02)
    assert old is not None
    info = lab.inspect()
    assert info["Config"]["Labels"]["org.cve-monitoring.project"] == lab.lab.config.project
    run([*docker_command(), "kill", "--signal", "KILL", info["Id"]])
    lab.control(mode="ok")
    compose(lab.lab.config, ["up", "-d", "--wait", "--wait-timeout", "40", "cve-event-dispatcher"])
    lab.wait(lambda: lab.status(value.event_id) == "delivered")
    database = Database(lab.lab.settings("event_dispatcher"))
    database.open()
    try:
        assert not await DeliveryRepository(database).finish(old, "delivered")
    finally:
        await database.close()
    with db.connect(lab.lab.config, "event_dispatcher") as connection:
        rows = connection.execute(
            "SELECT outcome FROM automation.delivery_attempts WHERE event_id=%"
            "s AND destination='https_sink' ORDER BY attempt",
            (value.event_id,),
        ).fetchall()
        assert len(rows) >= 2 and rows[-1]["outcome"] == "delivered"
