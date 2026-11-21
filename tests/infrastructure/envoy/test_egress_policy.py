"""Daemonfreie Prüfung der maßgeblichen Policy; Runtime-Suite prüft deren Wirkung."""

import copy
from pathlib import Path

import pytest
import yaml
from jsonschema.exceptions import ValidationError

from scripts.infrastructure.envoy import ROOT, generate, policy


def test_default_policy_and_closed_baseline() -> None:
    value = policy()
    assert all(rule["port"] == 443 and rule["protocol"] == "https" for rule in value["rules"])
    assert not value["smtp"]["enabled"]
    model = generate(value, {})
    assert yaml.safe_load((ROOT / "infrastructure/envoy/envoy.yaml").read_text()) == model
    assert not model["static_resources"]["listeners"][0]["filter_chains"]
    assert not model["static_resources"]["listeners"][1]["filter_chains"]
    assert model["admin"]["address"]["pipe"]["path"] == "/tmp/envoy-admin.sock"


@pytest.mark.parametrize(
    "mutation",
    [
        "host",
        "port",
        "protocol",
        "client",
        "wildcard",
        "duplicate",
        "suffix",
        "unicode",
        "trailing-dot",
        "https-method",
        "http-port",
        "unknown-key",
        "enabled-missing",
        "dns",
        "bounds",
        "duplicate-target",
    ],
)
def test_invalid_policy_fails(tmp_path: Path, mutation: str) -> None:
    value = copy.deepcopy(policy())
    rule = value["rules"][0]
    if mutation == "host":
        rule.pop("host")
    elif mutation == "port":
        rule["port"] = 0
    elif mutation == "protocol":
        rule["protocol"] = "tcp"
    elif mutation == "client":
        rule["client"] = "untrusted"
    elif mutation == "wildcard":
        rule["host"] = "*.github.com"
    elif mutation == "duplicate":
        value["rules"].append(copy.deepcopy(rule))
    elif mutation == "suffix":
        rule["host"] = "github.com@evil.invalid"
    elif mutation == "unicode":
        rule["host"] = "gıthub.com"
    elif mutation == "trailing-dot":
        rule["host"] = "github.com."
    elif mutation == "https-method":
        rule["methods"] = ["POST"]
    elif mutation == "http-port":
        rule.update(protocol="http", port=443, methods=["GET"])
    elif mutation == "unknown-key":
        rule["allow_any"] = True
    elif mutation == "enabled-missing":
        rule.pop("enabled")
    elif mutation == "dns":
        value["dns"]["address"] = "example.invalid"
    elif mutation == "bounds":
        value["limits"]["max_connections"] = 100000
    elif mutation == "duplicate-target":
        duplicate = copy.deepcopy(rule)
        duplicate["id"] = "duplicate-target"
        value["rules"].append(duplicate)
    file = tmp_path / "policy.yml"
    file.write_text(yaml.safe_dump(value))
    with pytest.raises((ValueError, ValidationError)):
        policy(file)
