"""Gepinnte Konfiguration und tatsächliche Envoy-v3-Validierung, auch bei Fehlern."""

import copy
import subprocess
from pathlib import Path

import pytest
import yaml

from scripts.infrastructure.envoy import check, generate, policy
from scripts.infrastructure.manage import load_config, resolved, validate_model


def test_direct_application_services_are_isolated() -> None:
    config = load_config()
    model = resolved(config)
    assert validate_model(model, True) == []
    for mutation in ("ports", "network", "capability", "socket", "admin-user"):
        changed = copy.deepcopy(model)
        service = changed["services"]["cve-processing"]
        if mutation == "ports":
            service["ports"] = [{"target": 3128, "published": "3128"}]
        elif mutation == "network":
            service["networks"]["cve_ingress"] = {}
        elif mutation == "capability":
            service["cap_add"] = ["NET_ADMIN"]
        elif mutation == "socket":
            service["volumes"].append({"read_only": True, "source": "/var/run/docker.sock"})
        else:
            service["user"] = "0:0"
        assert validate_model(changed, True)


@pytest.mark.egress
@pytest.mark.parametrize("mutation", ["valid", "yaml", "filter", "listener", "cluster", "missing"])
def test_actual_envoy_validation(tmp_path: Path, mutation: str) -> None:
    config = load_config()
    model = generate(policy(), {})
    file = tmp_path / "envoy.yaml"
    if mutation == "filter":
        model["static_resources"]["listeners"][0]["default_filter_chain"]["filters"][0][
            "typed_config"
        ]["@type"] = "type.googleapis.com/unsupported.Filter"
    elif mutation == "listener":
        model["static_resources"]["listeners"].pop()
    elif mutation == "cluster":
        model["static_resources"]["clusters"][0]["type"] = "NOT_A_CLUSTER_TYPE"
    file.write_text("invalid: [yaml" if mutation == "yaml" else yaml.safe_dump(model))
    if mutation == "missing":
        file.unlink()
    if mutation == "valid":
        check(config, file)
    else:
        with pytest.raises((ValueError, yaml.YAMLError, subprocess.CalledProcessError)):
            check(config, file)
