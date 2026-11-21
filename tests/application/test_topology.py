"""Logical selectors must not mutate commands or create duplicate physical services."""

from cve_common.deployment import GROUPS, PORTS, SERVICES

from scripts.infrastructure.manage import load_config, resolved, validate_model
from scripts.infrastructure.topology import arguments


def test_exactly_three_profiles_and_one_application_image() -> None:
    config = load_config()
    model = resolved(config)
    assert set(model["services"]) == set(SERVICES) and len(SERVICES) == 7
    assert len({model["services"][group]["image"] for group in GROUPS}) == 1
    assert [group for group in GROUPS if model["services"][group].get("build")] == ["cve-api"]
    assert validate_model(model, True) == []
    for roles in GROUPS.values():
        assert len({PORTS[role] for role in roles}) == len(roles)


def test_selectors_deduplicate_groups_without_mutating_exec_arguments() -> None:
    assert arguments(
        ["up", "-d", "cve-inventory", "cve-findings", "cve-importer", "cve-enricher"]
    ) == ["up", "-d", "cve-processing"]
    assert arguments(["exec", "-T", "cve-matcher", "python", "-c", "cve-inventory"]) == [
        "exec",
        "-T",
        "cve-processing",
        "python",
        "-c",
        "cve-inventory",
    ]


def test_parallel_enrichment_has_bounded_process_and_connection_budgets() -> None:
    config = load_config()
    for field, value in [
        ("CVE_ENRICHER_PROCESSES", "3"),
        ("CVE_ENRICHER_CONCURRENCY", "5"),
        ("CVE_ENRICHER_DATABASE__POOL_SIZE", "4"),
        ("CVE_ENRICHER_DATABASE__POOL_SIZE", "10"),
    ]:
        model = resolved(config)
        model["services"]["cve-processing"]["environment"][field] = value
        assert any("heartbeat pool" in e for e in validate_model(model, True))
