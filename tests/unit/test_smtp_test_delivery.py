"""Test mail preserves verified STARTTLS and treats ambiguous DATA as non-retryable."""

import secrets
import smtplib
import ssl
from unittest.mock import MagicMock, patch

import pytest
from cve_common.smtp_settings import SMTPConfig

from scripts.smtp.testing import deliver


@pytest.mark.parametrize(
    ("stage", "failure", "expected"),
    [
        ("connect", OSError("unreachable"), "SMTP_CONNECTION_FAILED"),
        ("starttls", ssl.SSLError("untrusted"), "SMTP_TLS_FAILED"),
        (
            "login",
            smtplib.SMTPAuthenticationError(535, b"private reply"),
            "SMTP_AUTHENTICATION_FAILED",
        ),
        ("login", smtplib.SMTPNotSupportedError("AUTH unavailable"), "SMTP_AUTHENTICATION_FAILED"),
        (
            "send_message",
            smtplib.SMTPRecipientsRefused({"user@example.test": (550, b"rejected")}),
            "SMTP_REJECTED",
        ),
        ("send_message", smtplib.SMTPDataError(550, b"private reply"), "SMTP_REJECTED"),
        ("send_message", smtplib.SMTPServerDisconnected("lost"), "SMTP_OUTCOME_UNKNOWN"),
    ],
)
def test_delivery_returns_safe_errors_without_retry(
    stage: str, failure: Exception, expected: str
) -> None:
    client = MagicMock()
    factory = MagicMock(return_value=client)
    if stage == "connect":
        factory.side_effect = failure
    else:
        getattr(client, stage).side_effect = failure
    with patch("scripts.smtp.testing.smtplib.SMTP", factory):
        result = deliver(
            SMTPConfig(enabled=True, host="mail.example.test", sender="monitor@example.test"),
            {"username": "account", "password": secrets.token_urlsafe(32)},
            ["user@example.test"],
            "test-id",
        )
    assert result == expected
    assert factory.call_count == 1
    assert client.send_message.call_count <= 1
    if stage != "connect":
        client.close.assert_called_once()


def test_success_verifies_tls_before_auth_and_sends_no_credentials_in_message() -> None:
    client = MagicMock()
    password = secrets.token_urlsafe(32)
    client.send_message.return_value = {}
    with patch("scripts.smtp.testing.smtplib.SMTP", return_value=client):
        result = deliver(
            SMTPConfig(enabled=True, host="mail.example.test", sender="monitor@example.test"),
            {"username": "account", "password": password},
            ["one@example.test", "two@example.test"],
            "test-id",
        )
    assert result is None
    context = client.starttls.call_args.kwargs["context"]
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    methods = [call[0] for call in client.method_calls]
    assert methods.index("starttls") < methods.index("login") < methods.index("send_message")
    message = client.send_message.call_args.args[0]
    assert password not in message.as_string()
    assert client.send_message.call_args.kwargs["to_addrs"] == [
        "one@example.test",
        "two@example.test",
    ]
