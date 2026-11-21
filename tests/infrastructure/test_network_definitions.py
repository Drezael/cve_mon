"""Netzwerkdefinitionen nach der echten Compose-Auflösung."""

import copy

import pytest

from scripts.infrastructure.manage import load_config, network_definitions, validate_networks


def test_all_five_network_definitions() -> None:
    assert validate_networks(network_definitions(load_config())) == []


@pytest.mark.parametrize("mutation", ["internal", "ipv6", "external", "subnet"])
def test_unsafe_network_definitions_fail(mutation: str) -> None:
    networks = copy.deepcopy(network_definitions(load_config()))
    target = networks["cve_data"]
    if mutation == "internal":
        target["internal"] = False
    elif mutation == "ipv6":
        target["enable_ipv6"] = True
    elif mutation == "external":
        target["external"] = True
    else:
        target["ipam"] = {"config": [{"subnet": "10.0.0.0/8"}]}
    assert validate_networks(networks)
