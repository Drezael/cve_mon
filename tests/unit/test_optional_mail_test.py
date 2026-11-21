"""Mail capture is an explicit development-only profile, never a core dependency."""

from dataclasses import replace

import pytest
from cve_common.deployment import SERVICES

from scripts.infrastructure.manage import load_config, resolved, validate_model


def test_normal_stack_has_seven_services_and_no_capture() -> None:
    config = load_config()
    model = resolved(config)
    assert len(SERVICES) == 7
    assert set(model["services"]) == set(SERVICES)
    assert "cve-mailhog" not in model["services"]
    assert not any(
        service.get("ports") for name, service in model["services"].items() if name != "cve-nginx"
    )


def test_mail_capture_requires_its_explicit_profile() -> None:
    config = load_config()
    config = replace(
        config, compose_overrides=(config.root / "infrastructure/compose/mail-test.yml",)
    )
    model = resolved(config)
    assert model["services"]["cve-mailhog"]["profiles"] == ["mail-test"]
    assert (
        validate_model(model, True, mount_base=config.mount_base, secrets_base=config.secrets_base)
        == []
    )
    model["services"]["cve-mailhog"].pop("profiles")
    assert any(
        "mail-test-Profil" in error
        for error in validate_model(
            model, True, mount_base=config.mount_base, secrets_base=config.secrets_base
        )
    )


def test_server_has_only_a_canonical_dashboard_origin() -> None:
    config = load_config(overrides={"APP_ENV": "production", "INGRESS_HTTPS_PORT": "443"})
    model = resolved(config)
    assert model["services"]["cve-api"]["environment"]["CVE_API_AUTH__ORIGIN"] == (
        "https://" + config.values["DASHBOARD_DOMAIN"]
    )
    for key in ("API_DOMAIN", "N8N_DOMAIN", "INVENTORY_DOMAIN"):
        with pytest.raises(ValueError):
            load_config(overrides={key: "outside.example.org"})
