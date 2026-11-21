"""Real database, worker groups, namespace restrictions and supervised process recovery."""

import json
import os
import subprocess
from collections.abc import Iterator
from uuid import uuid4

import pytest

from scripts.application.build import build
from scripts.application.manage import identity, start
from scripts.database import manage as db
from scripts.infrastructure.manage import Config, compose, docker_command, load_config, run

pytestmark = pytest.mark.services_integration


@pytest.fixture(scope="module")
def compact() -> Iterator[Config]:
    config = load_config(
        overrides={"COMPOSE_PROJECT_NAME": "cve-db-test-compact-" + uuid4().hex[:10]}
    )
    db.prepare(config)
    try:
        compose(config, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-postgres"])
        db.provision(config)
        db.migrate(config)
        build(config)
        start(config, "cve-processing")
        start(config, "cve-sources")
        compose(
            config,
            [
                "up",
                "-d",
                "--no-deps",
                "--no-recreate",
                "--wait",
                "--wait-timeout",
                "90",
                "cve-processing",
                "cve-sources",
            ],
            managed=False,
        )
        yield config
    finally:
        for group in ["cve-processing", "cve-sources"]:
            result = compose(config, ["logs", "--no-color", group])
            path = config.root / ".runtime/test-reports" / ("compact-native-" + group + ".log")
            path.write_text(result.stdout + result.stderr)
            path.chmod(0o600)
        db.cleanup_test(config)


def test_shared_image_and_all_seven_worker_processes(compact: Config) -> None:
    groups = [identity(compact, g) for g in ["cve-processing", "cve-sources"]]
    assert len({v["Image"] for v in groups}) == 1
    for item, expected in zip(groups, [7, 1], strict=True):
        state = json.loads(
            run(
                [*docker_command(), "exec", item["Id"], "cat", "/tmp/cve-application-state.json"]
            ).stdout
        )
        assert len(state["children"]) == expected
        assert item["State"]["Health"]["Status"] == "healthy"
        assert item["Config"]["User"] == f"{os.getuid()}:{os.getgid()}"
        assert item["HostConfig"]["ReadonlyRootfs"]


def test_groups_cannot_bypass_network_guards(compact: Config) -> None:
    code = (
        "import socket;s=socket.socket();s.settimeout(1);"
        "print(s.connect_ex(('169.254.169.254',80)))"
    )
    for group in ["cve-processing", "cve-sources"]:
        result = run(
            [*docker_command(), "exec", identity(compact, group)["Id"], "python", "-c", code]
        ).stdout.strip()
        assert result != "0"


def test_worker_restart_stays_gated_until_controlled_release(compact: Config) -> None:
    import time

    group = "cve-processing"
    before = identity(compact, group)
    compose(compact, ["restart", group])
    time.sleep(1)
    current = identity(compact, group)
    state = subprocess.run(
        [*docker_command(), "exec", current["Id"], "test", "-f", "/tmp/cve-application-state.json"],
        capture_output=True,
        check=False,
    )
    assert state.returncode != 0
    assert current["State"]["StartedAt"] != before["State"]["StartedAt"]
    start(compact, group)
    compose(
        compact,
        ["up", "-d", "--no-deps", "--no-recreate", "--wait", "--wait-timeout", "60", group],
        managed=False,
    )


def test_child_failure_keeps_container_and_peers_until_process_recovery(compact: Config) -> None:
    import time

    group = "cve-processing"
    before = identity(compact, group)
    state = json.loads(
        run(
            [*docker_command(), "exec", before["Id"], "cat", "/tmp/cve-application-state.json"]
        ).stdout
    )
    malformed = run(
        [
            *docker_command(),
            "exec",
            before["Id"],
            "python",
            "-c",
            "import socket,json;s=socket.socket(socket.AF_UNIX);"
            "s.connect('/tmp/cve-application-control.sock');s.sendall(bytes([91,93,10]));"
            "print(s.recv(4096).decode())",
        ]
    )
    assert not json.loads(malformed.stdout)["ok"]
    child = int(state["children"]["cve-inventory"])
    run(
        [
            *docker_command(),
            "exec",
            before["Id"],
            "python",
            "-c",
            f"import os,signal;os.kill({child},signal.SIGKILL)",
        ]
    )
    time.sleep(1)
    current = identity(compact, group)
    assert current["State"]["Pid"] == before["State"]["Pid"]
    assert current["State"]["StartedAt"] == before["State"]["StartedAt"]
    result = json.loads(
        run(
            [
                *docker_command(),
                "exec",
                before["Id"],
                "python",
                "-m",
                "cve_common.application",
                "restart",
                "cve-inventory",
                str(uuid4()),
            ]
        ).stdout
    )
    assert result["ok"] and result["old_pid"] == child and result["new_pid"] != child
    recovered = json.loads(
        run(
            [*docker_command(), "exec", before["Id"], "cat", "/tmp/cve-application-state.json"]
        ).stdout
    )
    assert all(
        recovered["children"][role] == pid
        for role, pid in state["children"].items()
        if role != "cve-inventory"
    )


def test_eight_enrichments_run_in_two_processes(compact: Config) -> None:
    """Hold independent identity locks to observe the real process/concurrency limit."""
    import time

    identities = [f"CVE-2099-{900000 + i}" for i in range(12)]
    jobs = []
    held = db.connect(compact, "cve_migrator")
    held.execute("SET ROLE postgres_owner")
    try:
        for value in identities:
            held.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,16))", (value,))
        with db.connect(compact, "api_security") as connection:
            for value in identities:
                row = connection.execute(
                    "SELECT cve.enqueue_enrichment(%s,%s,%s) id", (value, uuid4().hex, uuid4())
                ).fetchone()
                assert row is not None
                jobs.append(row["id"])
        end = time.monotonic() + 20
        while time.monotonic() < end:
            with db.connect(compact) as connection:
                row = connection.execute(
                    "SELECT count(*) n,count(DISTINCT lease_owner) workers FROM automation.jobs "
                    "WHERE id=ANY(%s) AND status='running'",
                    (jobs,),
                ).fetchone()
            if row and row["n"] == 8:
                assert row["workers"] == 2
                break
            time.sleep(0.1)
        else:
            raise AssertionError("Expected eight active jobs across two native workers")
    finally:
        held.rollback()
        held.close()
    end = time.monotonic() + 30
    while time.monotonic() < end:
        with db.connect(compact) as connection:
            row = connection.execute(
                "SELECT count(*) n FROM automation.jobs WHERE id=ANY(%s) AND status='succeeded'",
                (jobs,),
            ).fetchone()
        if row and row["n"] == len(jobs):
            return
        time.sleep(0.1)
    raise AssertionError("Parallel jobs did not commit after releasing their identity locks")


def test_eight_matching_jobs_run_in_two_processes(compact: Config) -> None:
    import time

    identities = [f"CVE-2093-{910000 + i}" for i in range(12)]
    # Earlier tests publish CVEs asynchronously; let their matching jobs release the slots first.
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        with db.connect(compact) as connection:
            outstanding = connection.execute(
                "SELECT count(*) n FROM automation.jobs "
                "WHERE job_type='matching.evaluate_vulnerability' "
                "AND status IN ('queued','retry_pending','running')"
            ).fetchone()
        if outstanding and outstanding["n"] == 0:
            break
        time.sleep(0.1)
    else:
        raise AssertionError("Previous fixture matching jobs did not drain")
    held = db.connect(compact)
    held.execute("LOCK TABLE matching.indexed_revisions IN ACCESS EXCLUSIVE MODE")
    try:
        with db.connect(compact, "api_security") as connection:
            for value in identities:
                connection.execute(
                    "SELECT cve.enqueue_enrichment(%s,%s,%s)", (value, uuid4().hex, uuid4())
                )
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            with db.connect(compact) as connection:
                active = connection.execute(
                    "SELECT count(*) n,count(DISTINCT lease_owner) workers "
                    "FROM automation.jobs WHERE job_type='matching.evaluate_vulnerability' "
                    "AND status='running' AND payload->>'identity'=ANY(%s)",
                    (identities,),
                ).fetchone()
            if active and active["n"] == 8 and active["workers"] == 2:
                break
            time.sleep(0.1)
        else:
            raise AssertionError(
                f"Expected eight active matching jobs in two processes; last={active}"
            )
    finally:
        held.rollback()
        held.close()
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        with db.connect(compact) as connection:
            count = connection.execute(
                "SELECT count(*) n FROM matching.indexed_revisions i "
                "JOIN cve.enrichment_revisions r ON r.id=i.enrichment_revision_id "
                "WHERE r.identity=ANY(%s)",
                (identities,),
            ).fetchone()
        if count and count["n"] == 12:
            return
        time.sleep(0.1)
    raise AssertionError("Matching package did not finish after releasing its table lock")
