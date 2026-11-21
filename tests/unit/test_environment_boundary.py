"""Public configuration cannot replace versioned internal architecture settings."""

import os
import re
from pathlib import Path

import pytest

from scripts.infrastructure.manage import load_config, resolved, validate_model
from scripts.infrastructure.policy import CONTAINER_POLICY, EXTERNAL_KEYS, INTERNAL_DEFAULTS


def test_environment_templates_only_contain_external_inputs(repository_root: Path) -> None:
    for relative in (
        ".env.example",
        "configuration/examples/server.env",
        "configuration/examples/development.env",
    ):
        keys = {
            line.partition("=")[0]
            for line in (repository_root / relative).read_text().splitlines()
            if line and not line.startswith("#")
        }
        assert keys <= EXTERNAL_KEYS
        assert not keys & INTERNAL_DEFAULTS.keys()


def test_internal_variables_are_rejected_even_with_their_current_value(
    repository_root: Path,
    tmp_path: Path,
) -> None:
    source = (repository_root / ".env.example").read_text()
    candidate = tmp_path / "settings.env"
    for key, value in INTERNAL_DEFAULTS.items():
        candidate.write_text(source + key + "=" + value + "\n")
        with pytest.raises(ValueError, match="Interne Architekturvariable"):
            load_config(candidate)
        with pytest.raises(ValueError, match="Nur externe"):
            load_config(overrides={key: value})


def test_shell_variables_cannot_change_internal_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key in (*INTERNAL_DEFAULTS, "NGINX_UID", "NGINX_GID", "PG_WORK_DIR"):
        monkeypatch.setenv(key, "injected")
    config = load_config()
    assert all(config.values[key] == value for key, value in INTERNAL_DEFAULTS.items())
    assert config.values["NGINX_UID"] == str(os.getuid())
    assert config.values["PG_WORK_DIR"] == str(config.secrets_base / "database")
    assert not config.external_values.keys() & INTERNAL_DEFAULTS.keys()


def test_compose_does_not_interpolate_internal_architecture(repository_root: Path) -> None:
    source = (repository_root / "compose.yml").read_text()
    interpolated = set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)(?=[:}])", source))
    # UID/GID are derived host identities supplied by the controller, never .env inputs.
    assert interpolated <= EXTERNAL_KEYS | {"NGINX_UID", "NGINX_GID", "DASHBOARD_ORIGIN"}


def test_container_architecture_changes_are_rejected() -> None:
    config = load_config()
    model = resolved(config)
    for service, environment in CONTAINER_POLICY.items():
        assert all(
            model["services"][service]["environment"][key] == value
            for key, value in environment.items()
        )
    model["services"]["cve-processing"]["environment"]["CVE_MATCHER_CONCURRENCY"] = "999"
    assert any(
        "feste interne Architekturvariable" in error
        for error in validate_model(
            model, True, mount_base=config.mount_base, secrets_base=config.secrets_base
        )
    )


def test_exported_external_configuration_can_be_loaded_again(tmp_path: Path) -> None:
    original = load_config()
    path = tmp_path / "roundtrip.env"
    path.write_text(
        "".join(key + "=" + value + "\n" for key, value in original.external_values.items())
    )
    assert load_config(path).values == original.values
