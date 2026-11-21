"""Missing risk evidence, explicitly approved suppression, DST, safe MIME and SMTP ambiguity."""

from datetime import UTC, datetime, time
from decimal import Decimal
from email.message import EmailMessage
from pathlib import Path
from typing import Any
from unittest.mock import Mock
from uuid import uuid4

import pytest
from cve_notification.contracts import Preferences, Quiet, Rule, Template
from cve_notification.rendering import dashboard, message
from cve_notification.rules import address, applies, next_allowed, preference_reason, window
from cve_notification.smtp import Adapter
from pydantic import ValidationError

pytestmark = pytest.mark.notifications


def finding(**values: Any) -> dict[str, Any]:
    return {
        "current_priority": "critical",
        "status": "open",
        "latest_matching_status": "affected",
        "priority_basis": {},
        **values,
    }


def test_missing_and_stale_risk_are_not_zero_or_confirmed() -> None:
    f = finding()
    assert applies(Rule(), "created", f)
    assert not applies(Rule(minimum_cvss=Decimal("7")), "created", f)
    assert not applies(Rule(minimum_epss=Decimal("0.5")), "created", f)
    f["priority_basis"] = {"epss": {"score": 0.9, "is_stale": True}}
    assert not applies(Rule(minimum_epss=Decimal("0.5")), "created", f)
    f["priority_basis"]["epss"]["is_stale"] = False
    assert applies(Rule(minimum_epss=Decimal("0.5")), "created", f)
    assert not applies(Rule(kev_only=True), "created", f)


@pytest.mark.parametrize("kind", ["smtp.send", "cve.imported", "updated", "untrusted"])
def test_unsupported_event_is_not_a_notification(kind: str) -> None:
    assert not applies(Rule(), kind, finding())
    with pytest.raises(ValidationError):
        Rule(event_types=[kind])


def test_mandatory_and_exception_policies_are_explicit() -> None:
    f = finding(has_active_exception=True)
    prefs = Preferences(enabled=False)
    assert preference_reason(Rule(), prefs, "created", f) == "user_preference"
    assert preference_reason(Rule(mandatory=True), prefs, "created", f) is None
    assert (
        preference_reason(Rule(mandatory=True, suppress_active_exception=True), prefs, "created", f)
        == "approved_exception_policy"
    )


@pytest.mark.parametrize("value", ["alice@example.test", "valid+alias@example.test"])
def test_valid_registered_address(value: str) -> None:
    assert address(value, ["example.test"])


@pytest.mark.parametrize(
    "value",
    [
        "x@other.test",
        "x@example.test\r\nBcc: bad@evil.test",
        "name <x@example.test>",
        "a,b@example.test",
        "@example.test",
    ],
)
def test_no_free_or_injected_addresses(value: str) -> None:
    assert not address(value, ["example.test"])


@pytest.mark.parametrize(
    "instant",
    [
        datetime(2026, 3, 29, 0, 30, tzinfo=UTC),
        datetime(2026, 10, 25, 0, 30, tzinfo=UTC),
        datetime(2026, 10, 25, 1, 30, tzinfo=UTC),
    ],
)
def test_quiet_hours_release_once_through_both_dst_transitions(instant: datetime) -> None:
    q = Quiet(start=time(1), end=time(7))
    release = next_allowed(instant, q)
    assert release > instant
    assert release.astimezone(__import__("zoneinfo").ZoneInfo(q.timezone)).hour == 7
    assert next_allowed(release, q) == release
    start, end = window(instant, 24)
    assert start <= instant < end and (end - start).total_seconds() == 86400


@pytest.mark.parametrize(
    "base",
    [
        "http://dashboard.test",
        "https://x.test/?token=abc",
        "https://" + "user" + ":" + "pass" + "@x.test",
        "https://x.test/#fragment",
        "https://x.test/path",
    ],
)
def test_dashboard_link_cannot_carry_credentials_or_query(base: str) -> None:
    with pytest.raises(ValueError):
        dashboard(base)


@pytest.mark.parametrize(
    "html",
    [
        "<script>${items}</script>",
        '<img src="https://evil.test/pixel">',
        '<a href="https://evil.test">link</a>',
        '<p onclick="alert(1)">${items}</p>',
        "${unknown}",
        "${items.__class__}",
    ],
)
def test_template_has_no_executable_or_remote_content(html: str) -> None:
    with pytest.raises(ValidationError):
        Template(name="finding", subject="Sicherheitsmeldung", text="${items}", html=html)


def test_mime_escapes_all_dynamic_html_and_stable_message_id() -> None:
    template = Template(
        name="finding",
        subject="Sicherheit: ${title}",
        text="${items}\n${link}",
        html='<p>${items}</p><a href="${link}">Dashboard</a>',
    )
    identity = str(uuid4())
    result = message(
        template,
        notification_id=identity,
        sender="security@example.test",
        recipient="user@example.test",
        base="https://dashboard.example.test",
        items=["<script>alert(1)</script>"],
    )
    assert result["Message-ID"] == f"<{identity}@cve-monitoring.invalid>"
    content = result.get_body(preferencelist=("html",))
    assert content
    assert "<script>" not in content.get_content() and "&lt;script&gt;" in content.get_content()
    assert result.get_body(preferencelist=("plain",)) is not None


@pytest.mark.parametrize(
    ("phase", "status"),
    [
        ("connect", "retryable_failure"),
        ("starttls", "permanent_failure"),
        ("data", "submission_uncertain"),
    ],
)
def test_smtp_failures_distinguish_before_and_after_data(
    monkeypatch: Any, phase: str, status: str
) -> None:
    import ssl

    client = Mock()
    client.mail.return_value = (250, b"ok")
    client.rcpt.return_value = (250, b"ok")
    getattr(client, phase).side_effect = (
        ssl.SSLError("invalid") if phase == "starttls" else OSError("connection lost")
    )

    def create(**kw: Any) -> Any:
        if phase == "connect":
            raise OSError("connection lost")
        return client

    monkeypatch.setattr("cve_notification.smtp.smtplib.SMTP", create)
    adapter = object.__new__(Adapter)
    adapter.context = ssl.create_default_context()
    adapter.host = "cve-mail-relay"
    adapter.port = 2525
    adapter.timeout = 1
    mail = EmailMessage()
    mail["From"] = "security@example.test"
    mail["To"] = "user@example.test"
    mail.set_content("Test")
    assert adapter.submit(mail).status == status
    if phase != "connect":
        client.close.assert_called_once()


@pytest.mark.parametrize(
    ("code", "expected"),
    [(250, "relay_accepted"), (450, "retryable_failure"), (550, "permanent_failure")],
)
def test_smtp_final_response_and_queue_correlation(
    monkeypatch: Any, code: int, expected: str
) -> None:
    import ssl

    client = Mock()
    client.mail.return_value = (250, b"ok")
    client.rcpt.return_value = (250, b"ok")
    client.data.return_value = (code, b"2.0.0 queued as TESTQUEUE123")
    monkeypatch.setattr("cve_notification.smtp.smtplib.SMTP", lambda **kw: client)
    adapter = object.__new__(Adapter)
    adapter.context = ssl.create_default_context()
    adapter.host = "cve-mail-relay"
    adapter.port = 2525
    adapter.timeout = 1
    mail = EmailMessage()
    mail["From"] = "security@example.test"
    mail["To"] = "user@example.test"
    mail.set_content("Test")
    result = adapter.submit(mail)
    assert result.status == expected
    assert (result.queue_id == "TESTQUEUE123") == (code == 250)


def test_adapter_rejects_external_destinations() -> None:
    with pytest.raises(ValueError):
        Adapter(
            ca=Path("none"), certificate=Path("none"), key=Path("none"), host="smtp.external.test"
        )


def test_service_key_rotation_has_bounded_previous_key(tmp_path: Path) -> None:
    import os
    import time

    from cve_notification.orchestration import service_authorized

    current = tmp_path / "service-key.current"
    previous = tmp_path / "service-key.previous"
    current.write_text("current_" + "a" * 40)
    previous.write_text("previous_" + "b" * 40)
    current.chmod(0o600)
    previous.chmod(0o600)
    assert service_authorized(tmp_path, current.read_text())
    assert service_authorized(tmp_path, previous.read_text())
    os.utime(previous, (time.time() - 3601, time.time() - 3601))
    assert not service_authorized(tmp_path, previous.read_text())
    assert not service_authorized(tmp_path, "arbitrary_" + "z" * 40)


def test_internal_smtp_route_retains_canonical_tls_identity(monkeypatch: Any) -> None:
    import ssl

    client = Mock()
    client.mail.return_value = (250, b"ok")
    client.rcpt.return_value = (250, b"ok")
    client.data.return_value = (250, b"queued as QUEUE123")
    create = Mock(return_value=client)
    monkeypatch.setattr("cve_notification.smtp.smtplib.SMTP", create)
    adapter = object.__new__(Adapter)
    adapter.context = ssl.create_default_context()
    adapter.host = "cve-mail-relay"
    adapter.port = 2525
    adapter.timeout = 1
    message = EmailMessage()
    message["From"] = "security@example.test"
    message["To"] = "user@example.test"
    message.set_content("Fixture")
    assert adapter.submit(message).status == "relay_accepted"
    create.assert_called_once_with(host="cve-mail-submit", port=2525, timeout=1)
    assert client._host == "cve-mail-relay"
    client.starttls.assert_called_once_with(context=adapter.context)
    assert adapter.context.check_hostname


def test_multiple_envelope_recipients_are_submitted_atomically(monkeypatch: Any) -> None:
    import ssl

    client = Mock()
    client.mail.return_value = (250, b"ok")
    client.rcpt.side_effect = [(250, b"ok"), (450, b"temporary")]
    monkeypatch.setattr("cve_notification.smtp.smtplib.SMTP", lambda **kw: client)
    adapter = object.__new__(Adapter)
    adapter.context, adapter.host, adapter.port, adapter.timeout = (
        ssl.create_default_context(),
        "cve-mail-relay",
        2525,
        1,
    )
    mail = EmailMessage()
    mail["From"], mail["To"] = "visible@example.org", "one@example.org, two@example.org"
    mail.set_content("private fixture")
    outcome = adapter.submit(
        mail,
        envelope_sender="user123@cve-routing.invalid",
        recipients=["one@example.org", "two@example.org"],
    )
    assert outcome.status == "retryable_failure"
    client.mail.assert_called_once_with("user123@cve-routing.invalid")
    assert [call.args[0] for call in client.rcpt.call_args_list] == [
        "one@example.org",
        "two@example.org",
    ]
    client.data.assert_not_called()
