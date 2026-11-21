"""Real database authorization, persisted streaks, maintenance and restart budgets."""

from typing import Any

import psycopg
import pytest

from scripts.database import manage as db
from scripts.infrastructure.manage import Config
from tests.database.helpers import required_row

pytestmark = pytest.mark.database


def observe(config: Config, service: str, ok: bool, restartable: bool = True) -> None:
    with db.connect(config, "dashboard_admin") as s:
        s.execute(
            "SELECT status.watchdog_observe(%s,%s,%s,%s)",
            (service, ok, restartable, "OK" if ok else "UNRESPONSIVE"),
        )


def failure(config: Config) -> None:
    with db.connect(config) as s:
        s.execute(
            "UPDATE status.watchdog_probes SET checked_at=clock_timestamp()-interval '31 seconds' "
            "WHERE service_id='importer'"
        )
    observe(config, "importer", False)


def tick(config: Config) -> dict[str, Any]:
    with db.connect(config, "workflow_control") as s:
        value = required_row(
            s.execute("SELECT status.watchdog_tick('test-1','cve-control-watchdog') AS v")
        )["v"]
        assert isinstance(value, dict)
        return value


def test_watchdog_persists_probes_authorizes_only_n8n_and_bounds_restarts(
    db_config: Config,
) -> None:
    observe(db_config, "cve-postgres", True, False)
    observe(db_config, "importer", False)
    # Repeated calls in the same instant cannot fabricate confirmed failures.
    observe(db_config, "importer", False)
    assert tick(db_config)["restarts"] == 0
    failure(db_config)
    assert tick(db_config)["restarts"] == 0
    failure(db_config)
    with db.connect(db_config) as s:
        s.execute(
            "UPDATE status.watchdog_probes SET "
            "first_failure_at=clock_timestamp()-interval '61 seconds' "
            "WHERE service_id='importer'"
        )
    with (
        db.connect(db_config, "dashboard_admin") as s,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        s.execute("SELECT status.watchdog_tick('forged','cve-control-watchdog')")
    with (
        db.connect(db_config, "workflow_control") as s,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        s.execute("SELECT status.watchdog_tick('test-1','cve-control-platform')")
    observe(db_config, "cve-postgres", False, False)
    assert tick(db_config)["restarts"] == 0
    observe(db_config, "cve-postgres", True, False)
    assert tick(db_config)["restarts"] == 1
    assert tick(db_config)["restarts"] == 0
    with db.connect(db_config) as s:
        request = required_row(
            s.execute("SELECT * FROM status.service_restarts WHERE origin='watchdog'")
        )
        assert request["actor_id"] is None and request["state"] == "authorized"
        audit = required_row(
            s.execute(
                "SELECT actor_service FROM dashboard.administration_audit WHERE object_id=%s",
                (str(request["id"]),),
            )
        )
        assert audit["actor_service"] == "n8n-service-watchdog"
        s.execute(
            "UPDATE automation.n8n_queue SET finished_at=clock_timestamp()-interval '3 seconds' "
            "WHERE id=%s",
            (request["queue_id"],),
        )
    # Recovery between decision and execution cancels a now unnecessary restart.
    observe(db_config, "importer", True)
    with db.connect(db_config, "dashboard_admin") as s:
        assert required_row(s.execute("SELECT status.claim_restart() AS v"))["v"] is None
    with db.connect(db_config) as s:
        assert (
            required_row(
                s.execute("SELECT state FROM status.service_restarts WHERE id=%s", (request["id"],))
            )["state"]
            == "cancelled"
        )
    observe(db_config, "importer", False)
    failure(db_config)
    failure(db_config)
    with db.connect(db_config) as s:
        s.execute(
            "UPDATE status.watchdog_probes SET "
            "first_failure_at=clock_timestamp()-interval '61 seconds' "
            "WHERE service_id='importer'"
        )
    assert tick(db_config)["restarts"] == 0  # cooldown persists after recovery
    with db.connect(db_config) as s:
        s.execute("UPDATE status.watchdog_probes SET last_restart_at=NULL")
        s.execute("UPDATE status.watchdog_settings SET hourly_limit=1")
    assert tick(db_config)["restarts"] == 0  # hourly budget survives cancellations
    with db.connect(db_config) as s:
        s.execute("UPDATE status.watchdog_settings SET hourly_limit=3,enabled=false")
    assert tick(db_config)["restarts"] == 0
    with db.connect(db_config) as s:
        s.execute("UPDATE status.watchdog_settings SET enabled=true")
        s.execute(
            "UPDATE status.watchdog_probes SET checked_at=clock_timestamp()-interval '2 minutes'"
        )
    assert tick(db_config)["restarts"] == 0  # stale observers cannot authorize anything


def test_vendor_targets_and_observations_are_restricted(db_config: Config) -> None:
    with (
        db.connect(db_config, "workflow_control") as s,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        s.execute("SELECT status.watchdog_tick('test-1',NULL)")
    with (
        db.connect(db_config, "dashboard_admin") as s,
        pytest.raises(psycopg.errors.InvalidParameterValue),
    ):
        s.execute("SELECT status.watchdog_observe('cve-n8n',false,true,'UNRESPONSIVE')")
    with (
        db.connect(db_config, "workflow_control") as s,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        s.execute("SELECT status.watchdog_observe('api',false,true,'UNRESPONSIVE')")


def test_watchdog_respects_maintenance_and_finishes_a_durable_lease(db_config: Config) -> None:
    observe(db_config, "cve-postgres", True, False)
    observe(db_config, "ansible", False)
    with db.connect(db_config) as s:
        user = required_row(
            s.execute(
                "INSERT INTO security.users(username,email,display_name) "
                "VALUES('watchdog-admin','watchdog@example.test','Watchdog Admin') RETURNING id"
            )
        )["id"]
        maintenance = required_row(
            s.execute(
                "INSERT INTO status.maintenance_windows(service_ids,starts_at,ends_at,description,"
                "actor_user_id) VALUES(ARRAY['ansible'],clock_timestamp()-interval '1 minute',"
                "clock_timestamp()+interval '1 hour','Planned maintenance',%s) RETURNING id",
                (user,),
            )
        )["id"]
        s.execute(
            "UPDATE status.watchdog_probes SET consecutive_failures=3,"
            "first_failure_at=clock_timestamp()-interval '61 seconds' WHERE service_id='ansible'"
        )
    assert tick(db_config)["restarts"] == 0
    with db.connect(db_config) as s:
        s.execute(
            "UPDATE status.maintenance_windows SET cancelled=true WHERE id=%s", (maintenance,)
        )
    assert tick(db_config)["restarts"] == 1
    with db.connect(db_config) as s:
        s.execute(
            "UPDATE automation.n8n_queue SET finished_at=clock_timestamp()-interval '3 seconds' "
            "WHERE producer='n8n-service-watchdog'"
        )
    with db.connect(db_config, "dashboard_admin") as s:
        request = required_row(s.execute("SELECT status.claim_restart() AS v"))["v"]
        assert request["service_id"] == "ansible"
        s.execute(
            "SELECT status.finish_restart(%s,%s,true,NULL,42,43)",
            (request["id"], request["lease_token"]),
        )
    with db.connect(db_config) as s:
        assert (
            required_row(
                s.execute("SELECT state FROM status.service_restarts WHERE id=%s", (request["id"],))
            )["state"]
            == "succeeded"
        )
        assert (
            required_row(
                s.execute(
                    "SELECT actor_service,action FROM dashboard.administration_audit "
                    "WHERE object_id=%s AND action='service.watchdog.restart.finished'",
                    (request["id"],),
                )
            )["actor_service"]
            == "n8n-service-watchdog"
        )
