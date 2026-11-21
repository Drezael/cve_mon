"""Daemon-independent mail policy, secret permissions and locked build checks."""

import copy
import json
from pathlib import Path

import pytest

from scripts.infrastructure import mail
from scripts.infrastructure.manage import load_config, resolved, validate_model


def policy() -> dict[str, object]:
    return {
        "enabled": False,
        "smarthost": "smtp.example.invalid",
        "port": 587,
        "clients": [],
        "recipients": [],
        "settings": {},
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("smarthost", "127.0.0.1"),
        ("smarthost", "host\nINJECT"),
        ("port", 0),
        ("recipients", ["*"]),
        ("settings", {"relayhost": 1}),
        ("settings", {"queue_minfree": -1}),
        ("enabled", "false"),
    ],
)
def test_policy_denies_unsafe_values(field: str, value: object) -> None:
    data = policy()
    data[field] = value
    with pytest.raises((ValueError, TypeError)):
        mail.validate(data)


def test_default_policy_has_no_grants() -> None:
    assert mail.validate(policy())["clients"] == []


@pytest.mark.parametrize(
    "change", ["ports", "capabilities", "network", "socket", "credentials", "privileged"]
)
def test_compose_guard_rejects_mail_mutations(change: str) -> None:
    config = load_config()
    model = copy.deepcopy(resolved(config))
    service = model["services"]["cve-mail-relay"]
    if change == "ports":
        service["ports"] = [{"target": 2525, "published": "2525"}]
    elif change == "capabilities":
        service["cap_add"].append("NET_ADMIN")
    elif change == "network":
        service["networks"]["cve_egress_external"] = {}
    elif change == "socket":
        service["volumes"].append(
            {
                "source": "/var/run/docker.sock",
                "target": "/docker.sock",
                "type": "bind",
                "read_only": True,
            }
        )
    elif change == "credentials":
        service["environment"] = {"SMTP_PASSWORD": "forbidden"}  # pragma: allowlist secret
    else:
        service["privileged"] = True
    assert validate_model(model, True)


def test_mail_uses_original_registry_image_without_local_build_inputs() -> None:
    root = Path(__file__).resolve().parents[1]
    lock = json.loads((root / "infrastructure/images.lock.json").read_text())
    assert lock["mail"] == mail.IMAGE
    assert mail.IMAGE.startswith("boky/postfix:5.2.1-alpine@sha256:")
    assert len(mail.IMAGE.split("@sha256:")[1]) == 64
    assert not (root / "infrastructure/mail/Dockerfile").exists()
    assert not (root / "infrastructure/mail/packages.lock.json").exists()


@pytest.mark.parametrize(
    "fault", ["missing", "public", "symlink", "newline", "empty", "username_colon"]
)
def test_private_secret_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    monkeypatch.setattr(mail, "directory", lambda _config: tmp_path)
    folder = tmp_path / "secrets"
    folder.mkdir(mode=0o700)
    for name in ("smtp_username", "smtp_password", "server.key"):
        path = folder / name
        path.write_text("synthetic-test-file\n")
        path.chmod(0o600)
    target = folder / "smtp_password"
    if fault == "missing":
        target.unlink()
    elif fault == "public":
        target.chmod(0o644)
    elif fault == "symlink":
        target.unlink()
        target.symlink_to(folder / "smtp_username")
    elif fault == "newline":
        target.write_text("first\nsecond\n")
    elif fault == "empty":
        target.write_text("")
    else:
        (folder / "smtp_username").write_text("invalid:user\n")
    with pytest.raises(ValueError):
        mail.check_secrets(load_config())


def test_log_redaction_ignores_attacker_data() -> None:
    from infrastructure.mail.runtime import event

    raw = (
        "postfix/smtp[12]: ABC123: to=<private@example.invalid>, "
        "dsn=4.7.0, status=deferred (AUTH private-body-marker)"
    )
    entry = event(raw)
    assert entry["event"] == "deferred"
    assert entry["queue_id"] == "ABC123"
    assert entry["dsn"] == "4.7.0"
    assert "private" not in json.dumps(entry)
