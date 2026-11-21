"""Cloudflare-only issuance boundaries, protected credentials and renewal failure handling."""

import importlib.util
import json
import subprocess
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from scripts.infrastructure import acme, manage
from scripts.infrastructure.manage import Config, load_config, resolved, validate_model


@pytest.fixture
def acme_config(tmp_path: Path, repository_root: Path) -> Config:
    return load_config(
        repository_root / ".env.example",
        overrides={
            "APP_ENV": "production",
            "LETSENCRYPT_ENABLED": "true",
            "LETSENCRYPT_EMAIL": "operator@example.org",
            "LETSENCRYPT_AGREE_TOS": "true",
            "CLOUDFLARE_API_TOKEN": "test-token-" + "x" * 32,
            "MOUNT_BASE": str(tmp_path / "data"),
            "SECRETS_BASE": str(tmp_path / "private"),
        },
    )


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"APP_ENV": "development"}, "production"),
        ({"LETSENCRYPT_AGREE_TOS": "false"}, "AGREE_TOS"),
        ({"CLOUDFLARE_API_TOKEN": ""}, "CLOUDFLARE"),
        ({"LETSENCRYPT_EMAIL": "invalid"}, "Kontaktadresse"),
        ({"LETSENCRYPT_ENABLED": "yes"}, "true oder false"),
    ],
)
def test_activation_requires_valid_explicit_inputs(
    acme_config: Config, overrides: dict[str, str], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        load_config(overrides={**acme_config.external_values, **overrides})


def test_optional_compose_has_no_challenge_port_or_socket(acme_config: Config) -> None:
    model = resolved(acme_config)
    assert not validate_model(
        model, False, mount_base=acme_config.mount_base, secrets_base=acme_config.secrets_base
    )
    certbot = model["services"]["cve-certbot"]
    assert not certbot.get("ports")
    assert set(certbot["networks"]) == {"cve_outbound"}
    assert not any("TOKEN" in key for key in certbot["environment"])
    assert len(model["services"]["cve-nginx"]["volumes"]) == 2
    certbot["ports"] = [{"target": 80, "published": "80"}]
    assert acme.validate(model, acme_config.mount_base, acme_config.secrets_base, acme_config.root)


def test_credentials_are_private_and_never_passed_to_certbot_arguments(
    acme_config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.hardening import runtime_images

    calls: list[tuple[list[str], Any]] = []
    monkeypatch.setattr(runtime_images, "ensure", lambda _: None)
    monkeypatch.setattr(manage, "compose", lambda _c, args, **kw: calls.append((args, kw)))
    acme.bootstrap(acme_config)
    credential = (
        acme_config.secrets_base / "acme-credentials" / acme_config.project / "cloudflare.ini"
    )
    assert credential.stat().st_mode & 0o777 == 0o600
    assert credential.read_text() == (
        "dns_cloudflare_api_token = " + acme_config.values["CLOUDFLARE_API_TOKEN"] + "\n"
    )
    request = calls[-1][0]
    assert "--dns-cloudflare" in request and "dns-01" in request
    assert (
        "--publish" not in request and "--standalone" not in request and "--webroot" not in request
    )
    assert acme_config.values["CLOUDFLARE_API_TOKEN"] not in " ".join(request)
    assert calls[-1][1]["timeout"] == 600


def test_existing_valid_certificate_does_not_request_another(
    acme_config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.hardening import runtime_images

    folder = Path(acme_config.values["TLS_DIR"])
    folder.mkdir(parents=True)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "3",
            "-subj",
            "/CN=" + acme_config.values["DASHBOARD_DOMAIN"],
            "-addext",
            "subjectAltName=DNS:" + acme_config.values["DASHBOARD_DOMAIN"],
            "-keyout",
            str(folder / "privkey.pem"),
            "-out",
            str(folder / "fullchain.pem"),
        ],
        check=True,
        capture_output=True,
    )
    monkeypatch.setattr(runtime_images, "ensure", lambda _: None)

    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("Unnecessary certificate request")

    monkeypatch.setattr(manage, "compose", forbidden)
    acme.bootstrap(acme_config)


@pytest.fixture
def scheduler(repository_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "cve_acme_scheduler", repository_root / "infrastructure/acme/renew.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "STATE", tmp_path / "renewal.json")
    monkeypatch.setattr(module, "CERTIFICATE", tmp_path / "fullchain.pem")
    monkeypatch.setenv("ACME_DOMAIN", "dashboard.example.org")
    monkeypatch.setenv("ACME_EMAIL", "operator@example.org")
    return module


def test_scheduler_never_falls_back_to_http(scheduler: ModuleType) -> None:
    for dry_run in (False, True):
        args = scheduler.arguments(dry_run=dry_run)
        assert args[args.index("--preferred-challenges") + 1] == "dns-01"
        assert "--dns-cloudflare" in args
        assert not {"--webroot", "--standalone", "--force-renewal"} & set(args)
        assert ("--dry-run" in args) == dry_run
        assert ("acme-staging-" in args[args.index("--server") + 1]) == dry_run


@pytest.mark.parametrize("returncode", [0, 1])
def test_failed_renewal_preserves_certificate_and_reports_unhealthy(
    scheduler: ModuleType, monkeypatch: pytest.MonkeyPatch, returncode: int
) -> None:
    scheduler.CERTIFICATE.write_text("existing-certificate")
    monkeypatch.setattr(
        scheduler.subprocess, "Popen", lambda *a, **kw: SimpleNamespace(wait=lambda **_: returncode)
    )
    assert scheduler.cycle() is (returncode == 0)
    assert scheduler.healthy() is (returncode == 0)
    assert scheduler.CERTIFICATE.read_text() == "existing-certificate"
    state = json.loads(scheduler.STATE.read_text())
    state["checked_at"] -= 15 * 3600
    scheduler.STATE.write_text(json.dumps(state))
    assert not scheduler.healthy()


def test_shutdown_forwards_signal_to_certbot(
    scheduler: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    import signal

    received: list[int] = []
    monkeypatch.setattr(scheduler, "CURRENT", SimpleNamespace(send_signal=received.append))
    scheduler.stop(signal.SIGTERM, None)
    assert scheduler.STOP.is_set()
    assert received == [signal.SIGTERM]
