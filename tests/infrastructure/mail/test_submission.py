"""Real internal mTLS/relay grants, not a mock Postfix server."""

import pytest

from tests.infrastructure.mail.conftest import Lab

pytestmark = [pytest.mark.mail, pytest.mark.security]


def test_end_to_end_verified_tls_auth_and_delivery(mail_lab: Lab) -> None:
    lab = mail_lab
    lab.clean()
    result = lab.submit()
    assert result.get("accepted"), result
    lab.wait(lambda: len(lab.control()["messages"]) == 1)
    status = lab.control()
    assert status["counters"].get("auth_before_tls", 0) == 0
    assert status["counters"]["auth"] >= 1 and status["counters"]["tls"] >= 1
    assert status["sni"][-1] == "mail.allowed.test"
    assert "private-body-marker" in status["messages"][0]["body"]


@pytest.mark.parametrize(
    "arguments",
    [
        {"tls": False},
        {"cert": "none"},
        {"cert": "unlisted"},
        {"cert": "foreign-client"},
        {"cert": "expired-client"},
        {"sender": "intruder@evil.invalid"},
        {"recipient": "not-allowed@evil.invalid"},
        {"sender": ""},
        {"message": "From: admin@evil.invalid\r\nSubject: bad\r\n\r\nbody\r\n"},
        {
            "message": (
                "From: alerts@notifications.invalid\r\n"
                "Reply-To: attacker@evil.invalid\r\n\r\nbody\r\n"
            )
        },
        {"message": "From: alerts@notifications.invalid\r\n\r\n" + "x" * 1048577},
    ],
)
def test_unauthorized_submission_rejected(mail_lab: Lab, arguments: dict[str, object]) -> None:
    lab = mail_lab
    lab.clean()
    result = lab.submit(**arguments)
    assert not result.get("accepted"), result
    assert not lab.control()["messages"]
