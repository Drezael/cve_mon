"""Arbitrary messages/tracebacks/bodies are excluded; structured fields are redacted."""

import datetime
import json
import logging

import pytest
from cve_common.logging.redaction import redact, register_secret
from cve_common.logging.setup import JSONFormatter
from pydantic import SecretStr

pytestmark = pytest.mark.security


@pytest.mark.parametrize(
    "message",
    [
        "private-log-marker",
        # pragma: allowlist nextline secret (synthetic rejection/redaction fixture)
        {"password": "private-log-marker"},
        # pragma: allowlist nextline secret (synthetic rejection/redaction fixture)
        "postgresql://user:private-log-marker@db",
    ],
)
def test_logs_allowlist_metadata_only(message: object) -> None:
    record = logging.LogRecord("cve.test", logging.ERROR, "", 1, message, (), None)
    data = json.loads(JSONFormatter("cve-test").format(record))
    assert "private-log-marker" not in json.dumps(data)
    assert data["service"] == "cve-test"
    assert datetime.datetime.fromisoformat(data["time"]).utcoffset() == datetime.timedelta(0)


@pytest.mark.parametrize(
    "field",
    [
        "password",
        "Authorization",
        "Cookie",
        "body",
        "mfa_secret",
        "private_key",
        "smtp_credentials",
    ],
)
def test_sensitive_fields(field: str) -> None:
    assert "private-marker" not in json.dumps(redact({field: "private-marker"}))


def test_registered_secret_and_url() -> None:
    register_secret(SecretStr("registered-marker"))
    output = redact({"detail": "failure registered-marker postgresql://u:private-url-marker@host"})
    assert "registered-marker" not in str(output) and "private-url-marker" not in str(output)


def test_exception_class_without_traceback_or_message() -> None:
    error = RuntimeError("private-exception-marker")
    record = logging.LogRecord(
        "cve.test", logging.ERROR, "", 1, "internal_error", (), (RuntimeError, error, None)
    )
    output = JSONFormatter("cve-test").format(record)
    assert json.loads(output)["error_class"] == "RuntimeError"
    assert "private-exception-marker" not in output and "Traceback" not in output
