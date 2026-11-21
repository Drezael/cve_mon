"""Aufgelöste Compose-Modelle und sichere Konfigurationswerte prüfen."""

import copy
import os
from pathlib import Path

import pytest

from scripts.infrastructure.manage import load_config, resolved, validate_model


@pytest.mark.parametrize("environment", ["development", "production"])
def test_resolved_compose(environment: str) -> None:
    config = load_config(overrides={"APP_ENV": environment})
    assert validate_model(resolved(config), environment == "development") == []


@pytest.mark.parametrize("mutation", ["privileged", "socket", "host", "network", "port"])
def test_unsafe_compose_changes_fail(mutation: str) -> None:
    model = copy.deepcopy(resolved(load_config()))
    service = model["services"]["cve-nginx"]
    if mutation == "privileged":
        service["privileged"] = True
    elif mutation == "socket":
        service["volumes"].append(
            {"source": "/var/run/docker.sock", "target": "/var/run/docker.sock", "read_only": True}
        )
    elif mutation == "host":
        service["network_mode"] = "host"
    elif mutation == "network":
        service["networks"]["cve_data"] = {}
    else:
        service["ports"].append({"target": 5432, "published": "5432", "host_ip": "0.0.0.0"})
    assert validate_model(model, True)


@pytest.mark.parametrize(
    "key,value",
    [
        ("DASHBOARD_DOMAIN", "host; return 200;"),
        ("N8N_DOMAIN", "$(touch /tmp/unwanted)"),
        ("TLS_KEY_FILE", "file`id`.key"),
        ("INGRESS_BIND_IP", "0.0.0.0"),
        ("COMPOSE_PROJECT_NAME", "../other"),
        ("INGRESS_HTTPS_PORT", "0"),
        ("NGINX_UID", "0"),
        ("WEB_RATE", "10r/m;"),
        ("CLIENT_TIMEOUT", "0s"),
        ("TLS_CERT_FILE", ""),
    ],
)
def test_bad_configuration_is_rejected(key: str, value: str) -> None:
    with pytest.raises(ValueError):
        load_config(overrides={key: value})


def test_missing_variable_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in tuple(os.environ):
        if name.endswith("_DOMAIN"):
            monkeypatch.delenv(name)
    file = tmp_path / ".env"
    file.write_text("APP_ENV=development\n")
    with pytest.raises(ValueError, match="Pflichtvariablen"):
        load_config(file)


def test_projects_do_not_share_global_names() -> None:
    first = resolved(load_config(overrides={"COMPOSE_PROJECT_NAME": "cve-test-one"}))
    second = resolved(load_config(overrides={"COMPOSE_PROJECT_NAME": "cve-test-two"}))
    assert {v["name"] for v in first["networks"].values()}.isdisjoint(
        {v["name"] for v in second["networks"].values()}
    )
    assert (
        first["services"]["cve-nginx"]["volumes"][1]["source"]
        != second["services"]["cve-nginx"]["volumes"][1]["source"]
    )


def test_persistent_stores_are_project_scoped_bind_mounts() -> None:
    config = load_config()
    model = resolved(config)
    assert not model.get("volumes")
    for service in model["services"].values():
        assert all(mount["type"] == "bind" for mount in service.get("volumes", []))
    stores = {
        "cve-postgres": {
            "/var/lib/postgresql": "postgres-data",
            "/var/run/postgresql/tls": "postgres-tls",
        },
        "cve-mail-relay": {"/var/spool/postfix": "postfix-queue"},
    }
    for service, targets in stores.items():
        mounts = {m["target"]: m for m in model["services"][service]["volumes"]}
        for target, folder in targets.items():
            expected = config.root / ".runtime" if folder == "postgres-tls" else config.mount_base
            assert mounts[target]["source"] == str(expected / "storage" / model["name"] / folder)
            assert mounts[target]["bind"]["create_host_path"] is False


def test_named_storage_volume_is_rejected() -> None:
    model = resolved(load_config())
    model["services"]["cve-postgres"]["volumes"][0] = {
        "type": "volume",
        "source": "postgres_data",
        "target": "/var/lib/postgresql",
    }
    assert validate_model(model, True)


def test_vendor_services_use_locked_original_images_and_fixed_entrypoints() -> None:
    from scripts.infrastructure.images import REFERENCES

    model = resolved(load_config())
    vendors = {
        "cve-nginx": "nginx",
        "cve-postgres": "postgres",
        "cve-mail-relay": "mail",
        "cve-n8n": "n8n",
    }
    for service, upstream in vendors.items():
        definition = model["services"][service]
        assert definition["image"] == REFERENCES[upstream]
        assert not definition.get("build")
        if service == "cve-n8n":
            assert definition["entrypoint"] == ["/bin/sh", "/opt/cve-n8n/start.sh"]
        else:
            assert not definition.get("entrypoint")
    root = Path(__file__).resolve().parents[2]
    for dockerfile in (root / "services").glob("*/Dockerfile"):
        assert "FROM " + REFERENCES["python"] in dockerfile.read_text()
