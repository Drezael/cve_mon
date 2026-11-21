"""Strict data-only contracts, bounded policies and registered code references."""

from datetime import datetime
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from cve_common.events.contracts import EventEnvelope
from cve_common.events.registry import EventDefinition, EventRegistry
from cve_common.events.transport import Target
from cve_common.jobs.contracts import JobEnvelope, Payload
from cve_common.jobs.errors import ErrorCode, JobError, classify
from cve_common.jobs.registry import JobDefinition, Registry
from cve_common.jobs.retries import RetryPolicy
from pydantic import BaseModel, ValidationError


class Value(Payload):
    value: int


async def handler(_context: object, _payload: BaseModel) -> None:
    pass


def test_registered_contract_and_duplicate() -> None:
    registry = Registry()
    definition = JobDefinition("technical.test", 1, Value, None, handler)
    registry.register(definition)
    assert registry.get("technical.test", 1) is definition
    with pytest.raises(ValueError):
        registry.register(definition)
    with pytest.raises(ValueError):
        registry.get("os.system", 1)
    with pytest.raises(ValidationError):
        Value.model_validate({"unknown": 1})


@pytest.mark.parametrize(
    "payload",
    [
        {"command": "echo unsafe"},
        {"nested": {"module": "os"}},
        {"token": "hidden"},
        {"url": "http://169.254.169.254"},
        {"list": [{"authorization": "hidden"}]},
        {"value": "x" * 17000},
        {"value": float("nan")},
    ],
)
def test_unsafe_job_and_event_payload(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        JobEnvelope(job_type="technical.test", payload=payload, idempotency_key="k")
    with pytest.raises(ValidationError):
        EventEnvelope(
            event_type="technical.event",
            source="test-service",
            aggregate_type="test",
            aggregate_id="x",
            aggregate_version=1,
            payload=payload,
            idempotency_key="k",
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("payload_version", 0),
        ("payload_version", True),
        ("priority", 101),
        ("max_attempts", 0),
        ("max_attempts", 101),
        ("job_type", "os;evil"),
        ("idempotency_key", ""),
        ("scheduled_at", datetime(2026, 1, 1)),
        ("scope", "bad\nkey"),
    ],
)
def test_job_envelope_bounds(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        JobEnvelope.model_validate(
            {
                "job_type": "technical.test",
                "payload": {"value": 1},
                "idempotency_key": "k",
                field: value,
            }
        )


def test_retry_jitter_and_cap() -> None:
    policy = RetryPolicy(base=2, cap=10, max_attempts=3)
    assert policy.delay(1, jitter=0) == 1.6
    assert policy.delay(2, jitter=1) == 4
    assert policy.delay(100, jitter=1) == 10
    assert 8 <= policy.delay(100) <= 10
    with pytest.raises(ValueError):
        RetryPolicy(base=0)
    with pytest.raises(ValueError):
        policy.delay(0)
    with pytest.raises(ValueError):
        policy.delay(1, jitter=2)


@pytest.mark.parametrize(
    "error,code,retry",
    [
        (JobError(ErrorCode.TEMPORARY), ErrorCode.TEMPORARY, True),
        (JobError(ErrorCode.PERMANENT), ErrorCode.PERMANENT, False),
        (JobError(ErrorCode.RATE_LIMIT), ErrorCode.RATE_LIMIT, True),
        (TimeoutError(), ErrorCode.TIMEOUT, True),
        (httpx.ConnectError("private-data"), ErrorCode.NETWORK, True),
        (httpx.RemoteProtocolError("private-data"), ErrorCode.NETWORK, True),
        (PermissionError("private-data"), ErrorCode.FORBIDDEN, False),
        (RuntimeError("private-data"), ErrorCode.PERMANENT, False),
    ],
)
def test_error_classification(error: Exception, code: ErrorCode, retry: bool) -> None:
    classified = classify(error)
    assert classified.code == code and classified.retry == retry
    assert "private-data" not in str(classified)


@pytest.mark.parametrize(
    "origin",
    [
        "http://cve-test",
        "https://127.0.0.1",
        "https://169.254.169.254",
        "https://localhost",
        "https://example.com",
        "https://cve-test/path",
        "https://cve-test?secret=x",
    ],
)
def test_target_not_free_url(origin: str) -> None:
    with pytest.raises(ValidationError):
        Target(
            id="test", origin=origin, token_file=Path("/private/token"), ca_file=Path("/private/ca")
        )


def test_event_registry_binds_source_and_version() -> None:
    registry = EventRegistry()
    registry.register(EventDefinition("technical.event", 1, "test-service", Value))
    registry.validate("technical.event", 1, "test-service", {"value": 1})
    with pytest.raises(ValueError):
        registry.validate("technical.event", 2, "test-service", {"value": 1})
    with pytest.raises(ValueError):
        registry.validate("technical.event", 1, "wrong-service", {"value": 1})
    assert (
        EventEnvelope(
            event_type="technical.event",
            source="test-service",
            aggregate_type="test",
            aggregate_id="x",
            aggregate_version=1,
            payload={"value": 1},
            idempotency_key="k",
            correlation_id=uuid4(),
        ).schema_version
        == 1
    )


def test_committed_json_schemas_reject_control_and_secret_fields() -> None:
    import json
    from pathlib import Path

    from jsonschema import Draft202012Validator, FormatChecker
    from jsonschema import ValidationError as SchemaError

    root = Path(__file__).resolve().parents[3]
    for kind in ("jobs", "events"):
        file = "job-envelope-v1.schema.json" if kind == "jobs" else "event-envelope-v1.schema.json"
        validator = Draft202012Validator(
            json.loads((root / "contracts" / kind / file).read_text()),
            format_checker=FormatChecker(),
        )
        if kind == "jobs":
            data = JobEnvelope(
                job_type="technical.test", payload={"value": 1}, idempotency_key="key"
            ).model_dump(mode="json")
        else:
            from datetime import UTC

            data = EventEnvelope(
                event_type="technical.event",
                source="test-service",
                aggregate_type="test",
                aggregate_id="x",
                aggregate_version=1,
                occurred_at=datetime.now(UTC),
                payload={"value": 1},
                idempotency_key="key",
            ).model_dump(mode="json")
        validator.validate(data)
        data["payload"] = {"nested": {"Authorization": "private-marker"}}
        with pytest.raises(SchemaError):
            validator.validate(data)


def test_job_and_event_inherit_correlation_context() -> None:
    from cve_common.logging.correlation import correlation_id

    identity = uuid4()
    token = correlation_id.set(str(identity))
    try:
        job = JobEnvelope(job_type="technical.test", payload={"value": 1}, idempotency_key="k")
        event = EventEnvelope(
            event_type="technical.event",
            source="test-service",
            aggregate_type="test",
            aggregate_id="x",
            aggregate_version=1,
            payload={"value": 1},
            idempotency_key="k",
        )
        assert job.correlation_id == event.correlation_id == identity
    finally:
        correlation_id.reset(token)
