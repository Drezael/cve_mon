"""Real isolated PostgreSQL, existing roles, technical-only type catalog."""

import uuid
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass

import pytest
from cve_common.config.settings import DatabaseSettings
from cve_common.database.engine import Database
from cve_common.events.registry import EventDefinition, EventRegistry
from cve_common.jobs.contracts import Payload
from cve_common.jobs.execution import ExecutionContext
from cve_common.jobs.registry import JobDefinition, Registry
from cve_common.jobs.repository import JobRepository
from pydantic import BaseModel

from scripts.database import manage as db
from scripts.infrastructure.manage import Config, compose
from tests.configuration import load_test_config as load_config


class Value(Payload):
    value: int


async def noop(_context: ExecutionContext, _value: BaseModel) -> None:
    pass


def registry() -> Registry:
    result = Registry()
    for name in ("technical.success", "technical.retry", "technical.slow"):
        result.register(JobDefinition(name, 1, Value, None, noop, max_runtime=30, max_attempts=3))
    return result


def event_registry() -> EventRegistry:
    result = EventRegistry()
    result.register(EventDefinition("technical.event", 1, "technical-producer", Value))
    return result


@dataclass
class Lab:
    config: Config

    def settings(self, role: str) -> DatabaseSettings:
        return DatabaseSettings(
            host="cve-postgres",
            hostaddr=db.address(self.config),
            username=role,
            password_file=db.secret_file(self.config, role),
            ca_file=db.workdir(self.config) / "tls/ca.crt",
            pool_size=5,
        )


@pytest.fixture(scope="session")
def automation_lab() -> Iterator[Lab]:
    config = load_config(
        overrides={
            "COMPOSE_PROJECT_NAME": "cve-db-test-phase07-" + uuid.uuid4().hex[:10],
            "DISPATCHER_LEASE_SECONDS": "0.6",
            "DISPATCHER_HEARTBEAT_SECONDS": "0.1",
            "DISPATCHER_POLL_SECONDS": "0.1",
            "DISPATCHER_SHUTDOWN_SECONDS": "0.2",
        }
    )
    db.prepare(config)
    try:
        compose(config, ["up", "-d", "--wait", "--wait-timeout", "60", "cve-postgres"])
        db.provision(config)
        db.migrate(config, "00012_original_identity")
        with db.connect(config, "api_ingest") as connection:
            connection.execute(
                "INSERT INTO automation.jobs(job_type,idempotency_key) VALUES ('in"
                "ventory.process','legacy-preserved')"
            )
        db.migrate(config)
        db.migrate(config)
        with db.connect(config, "cve_migrator") as connection:
            connection.execute("SET ROLE postgres_owner")
            connection.execute(
                "CREATE TABLE automation.test_effects(id uuid PRIMARY KEY,value integer NOT NULL)"
            )
            connection.execute(
                "GRANT SELECT,INSERT,UPDATE ON automation.test_effects TO importer,api_security"
            )
            connection.execute(
                "INSERT INTO automation.job_types(code,handler_role,producer_roles"
                ",runtime_seconds,retry_base,retry_cap) SELECT x,'importer',ARRAY["
                "'api_security']::name[],30,.1,.2 FROM unnest(ARRAY['technical.suc"
                "cess','technical.retry','technical.slow']) x"
            )
            connection.execute(
                "INSERT INTO automation.event_types(code,producer_role,source,requ"
                "ires_order) VALUES ('technical.event','api_security','technical-p"
                "roducer',true)"
            )
            connection.execute(
                "INSERT INTO automation.delivery_targets(id,enabled,retry_base,ret"
                "ry_cap,max_attempts) VALUES ('test_sink',true,.1,.2,3)"
            )
            connection.execute(
                "INSERT INTO automation.event_routes VALUES ('technical.event','test_sink')"
            )
            connection.execute(
                "INSERT INTO automation.event_consumers VALUES ('technical_consume"
                "r','importer',ARRAY['technical.event'])"
            )
        yield Lab(config)
    finally:
        db.cleanup_test(config)


@pytest.fixture
async def producer(automation_lab: Lab) -> AsyncIterator[JobRepository]:
    database = Database(automation_lab.settings("api_security"))
    database.open()
    try:
        yield JobRepository(database, registry())
    finally:
        await database.close()


@pytest.fixture
async def worker(automation_lab: Lab) -> AsyncIterator[JobRepository]:
    database = Database(automation_lab.settings("importer"))
    database.open()
    try:
        yield JobRepository(database, registry())
    finally:
        await database.close()
