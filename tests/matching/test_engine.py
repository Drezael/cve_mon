"""Evidence conflicts, incomplete inputs, native source ranges and bounded CPE trees."""

import copy
from typing import Any

import pytest
from cve_matcher.cpe import attribute, configuration
from cve_matcher.engine import cna, component_keys, components, evaluate, source_keys, ubuntu
from cve_matcher.ranges import osv, osv_range

pytestmark = [pytest.mark.matching, pytest.mark.domain]
CPE = "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"


def package(**changes: Any) -> dict[str, Any]:
    return {
        "id": "package",
        "name": "example",
        "version": "1.5.0",
        "kind": "package",
        "context": "host",
        "ecosystem": "npm",
        "vendor": "vendor",
        "product": "product",
        **changes,
    }


def assertion(kind: str, value: Any, **changes: Any) -> dict[str, Any]:
    return {
        "kind": kind,
        "value": value,
        "matching_usable": True,
        "provenance": {
            "source_revision_id": "00000000-0000-4000-8000-000000000001",
            "json_pointer": "/affected/0",
        },
        **changes,
    }


def enrichment(*items: dict[str, Any]) -> dict[str, Any]:
    return {"lifecycle": {"value": "published"}, "affected": list(items)}


def osv_value(**changes: Any) -> dict[str, Any]:
    return {
        "package": {"ecosystem": "npm", "name": "example"},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
        **changes,
    }


@pytest.mark.parametrize(
    ("version", "expected"), [("0.0.0", True), ("1.9.9", True), ("2.0.0", False), ("2.0.1", False)]
)
def test_osv_fixed_boundary(version: str, expected: bool) -> None:
    assert osv(version, osv_value())[0] is expected


@pytest.mark.parametrize(
    ("op", "version", "expected"),
    [
        ("last_affected", "2.0.0", True),
        ("last_affected", "2.0.1", False),
        ("limit", "2.0.0", False),
        ("limit", "1.9.0", True),
    ],
)
def test_osv_end_semantics(op: str, version: str, expected: bool | None) -> None:
    assert (
        osv_range(
            version, {"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {op: "2.0.0"}]}, "npm"
        )[0]
        is expected
    )


@pytest.mark.parametrize(
    ("kind", "ecosystem", "reason"),
    [
        ("GIT", "npm", "git_graph_unavailable"),
        ("ECOSYSTEM", "Maven", "unsupported_comparator"),
        ("NEW", "npm", "unsupported_comparator"),
    ],
)
def test_osv_unknown(kind: str, ecosystem: str, reason: str) -> None:
    assert osv_range("1.0.0", {"type": kind}, ecosystem) == (None, reason)


def test_pypi_name_normalization_and_pep440_ranges_keep_global_negative_conservative() -> None:
    affected = {
        "kind": "osv_package",
        "matching_usable": True,
        "value": {
            "package": {"name": "my-pkg", "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}],
        },
    }
    component = {
        "id": "python-package",
        "kind": "package",
        "context": "host",
        "name": "My_Pkg",
        "version": "1.0",
        "ecosystem": "PyPI",
    }
    result = evaluate({"affected": [affected]}, [component], {"packages": "complete"})
    assert result.status == "affected" and result.components[0].adapter == "pep440"
    component["version"] = "2.0"
    result = evaluate({"affected": [affected]}, [component], {"packages": "complete"})
    assert result.components[0].status == "not_affected"
    assert result.status == "unknown" and result.coverage["global_negative"] is False


def test_osv_multiple_intervals_and_explicit_versions() -> None:
    value = osv_value(
        ranges=[
            {
                "type": "SEMVER",
                "events": [
                    {"introduced": "1.0.0"},
                    {"fixed": "2.0.0"},
                    {"introduced": "3.0.0"},
                    {"fixed": "4.0.1"},
                ],
            }
        ],
        versions=["5.0.0"],
    )
    for version, expected in [
        ("0.9.0", False),
        ("1.0.0", True),
        ("2.5.0", False),
        ("3.0.0", True),
        ("4.0.0", True),
        ("5.0.0", True),
    ]:
        assert osv(version, value)[0] is expected


@pytest.mark.parametrize(
    "events",
    [
        [{"fixed": "1.0.0"}],
        [{"introduced": "2.0.0"}, {"fixed": "2.0.0"}],
        [{"introduced": "1.0.0", "fixed": "2.0.0"}],
        [{"introduced": "0"}, {"fixed": "1.0.0"}, {"last_affected": "2.0.0"}],
    ],
)
def test_invalid_osv(events: list[dict[str, str]]) -> None:
    assert osv_range("1.0.0", {"type": "SEMVER", "events": events}, "npm")[0] is None


@pytest.mark.parametrize(
    ("source", "target", "expected"),
    [
        ("*", "-", True),
        ("-", "*", None),
        ("-", "-", True),
        ("-", "value", False),
        ("value", "*", None),
        ("v*", "value", True),
        (r"v\*", "value", False),
        ("v?", "v1", True),
    ],
)
def test_cpe_attributes(source: str, target: str, expected: bool | None) -> None:
    assert attribute(source, target) is expected


def leaf(criteria: str = CPE, vulnerable: bool = True) -> dict[str, Any]:
    return {"criteria": criteria, "vulnerable": vulnerable}


def test_nvd_and_or_negate_and_environment() -> None:
    inventory = [{"cpe": CPE, "adapter": "semver"}]
    platform = "cpe:2.3:o:vendor:os:1:*:*:*:*:*:*:*"
    node: dict[str, Any] = {"operator": "AND", "cpeMatch": [leaf(), leaf(platform, False)]}
    assert configuration(node, inventory) == (None, False)
    assert configuration(node, inventory, True) == (False, False)
    node["operator"] = "OR"
    assert configuration(node, inventory) == (True, True)
    node["negate"] = True
    assert configuration(node, inventory) == (False, False)
    assert configuration({"negate": True, "cpeMatch": [leaf(platform)]}, inventory) == (None, False)
    assert configuration({"cpeMatch": [leaf(CPE, False)]}, inventory) == (True, False)


@pytest.mark.parametrize(
    ("field", "boundary", "expected"),
    [
        ("versionStartIncluding", "1.0.0", True),
        ("versionStartExcluding", "1.0.0", False),
        ("versionEndIncluding", "1.0.0", True),
        ("versionEndExcluding", "1.0.0", False),
    ],
)
def test_cpe_version_bounds(field: str, boundary: str, expected: bool) -> None:
    criterion = {**leaf(CPE.replace(":1.0.0:", ":*:")), field: boundary}
    assert (
        configuration({"cpeMatch": [criterion]}, [{"cpe": CPE, "adapter": "semver"}], True)[0]
        is expected
    )
    assert configuration({"cpeMatch": [criterion]}, [{"cpe": CPE}], True)[0] is None


def test_bounded_nested_nvd() -> None:
    tree: dict[str, Any] = {"cpeMatch": [leaf()]}
    for _ in range(34):
        tree = {"nodes": [tree]}
    from cve_matcher.limits import EvaluationLimit

    with pytest.raises(EvaluationLimit):
        configuration(tree, [{"cpe": CPE}])
    with pytest.raises(EvaluationLimit):
        configuration({"cpeMatch": [leaf()] * 4097}, [{"cpe": CPE}])


@pytest.mark.parametrize(
    ("installed", "verified", "status"),
    [
        ("1:2.4.58-1ubuntu8.2", False, "affected"),
        ("1:2.4.58-1ubuntu8.4", False, "potentially_affected"),
        ("1:2.4.58-1ubuntu8.4", True, "not_affected"),
        ("2:2.0-1", True, "not_affected"),
    ],
)
def test_ubuntu_backport(installed: str, verified: bool, status: str) -> None:
    p = package(
        distribution="ubuntu",
        release="noble",
        source_package="example",
        version=installed,
        source_version=installed,
    )
    value = {
        "name": "example",
        "statuses": [
            {
                "release_codename": "noble",
                "status": "released",
                "description": "1:2.4.58-1ubuntu8.4",
            }
        ],
    }
    assert ubuntu(p, value, verified=verified)[0] == status


@pytest.mark.parametrize(
    "status", ["ignored", "needs_evaluation", "pending", "deferred", "unknown"]
)
def test_ubuntu_uncertain(status: str) -> None:
    assert (
        ubuntu(
            package(distribution="ubuntu", release="noble", source_package="example"),
            {"name": "example", "statuses": [{"release_codename": "noble", "status": status}]},
        )[0]
        == "unknown"
    )


def test_ubuntu_context_must_match() -> None:
    value = {
        "name": "example",
        "statuses": [{"release_codename": "jammy", "status": "not-affected"}],
    }
    assert (
        ubuntu(
            package(distribution="ubuntu", release="noble", source_package="example"),
            value,
            verified=True,
        )[0]
        == "unknown"
    )
    assert (
        ubuntu(
            package(distribution="debian", release="jammy", source_package="example"),
            value,
            verified=True,
        )[0]
        == "unknown"
    )
    assert (
        ubuntu(package(distribution="ubuntu", release="jammy"), value, verified=True)[0]
        == "potentially_affected"
    )


def test_cna_default_exact_identity_and_version_type() -> None:
    value: dict[str, Any] = {
        "vendor": "vendor",
        "product": "product",
        "defaultStatus": "unaffected",
        "versions": [
            {
                "version": "1.0.0",
                "lessThan": "2.0.0",
                "versionType": "semver",
                "status": "affected",
                "changes": [{"at": "1.6.0", "status": "unaffected"}],
            }
        ],
    }
    assert cna(package(), value)[0] == "affected"
    assert cna(package(version="1.6.0"), value)[0] == "not_affected"
    assert cna(package(version="2.0.0"), value)[0] == "not_affected"
    assert cna(package(vendor=None), value)[0] == "potentially_affected"
    value["versions"][0]["versionType"] = "custom"
    assert cna(package(), value)[0] == "potentially_affected"


def test_risk_is_not_affectedness_and_partial_absence_is_unknown() -> None:
    base = enrichment(assertion("osv_package", osv_value()))
    first = evaluate(base, [], {"packages": "partial"})
    changed = copy.deepcopy(base)
    changed.update(cvss=[{"base_score": 10}], kev={"status": "present"}, epss=1)
    assert evaluate(changed, [], {"packages": "partial"}) == first
    assert first.status == "unknown"
    assert evaluate(changed, [package()], {"packages": "partial"}).status == "affected"


def test_inactive_ambiguous_and_rejected() -> None:
    value = enrichment(assertion("osv_package", osv_value(), matching_usable=False))
    assert evaluate(value, [package()], {}).status == "potentially_affected"
    value["lifecycle"]["value"] = "rejected"
    assert evaluate(value, [package()], {}).status == "not_applicable"


def test_negative_component_is_not_global_clearance() -> None:
    result = evaluate(
        enrichment(assertion("osv_package", osv_value())),
        [package(version="2.0.0")],
        {"packages": "complete"},
    )
    assert result.components[0].status == "not_affected"
    assert result.status == "unknown"


def test_source_conflict_preserved() -> None:
    value = enrichment(
        assertion("osv_package", osv_value()),
        assertion(
            "cna_product",
            {
                "vendor": "vendor",
                "product": "product",
                "defaultStatus": "unaffected",
                "versions": [],
            },
        ),
    )
    result = evaluate(value, [package()], {})
    assert result.status == "potentially_affected"
    assert result.components[0].conflicts


def test_identity_namespace_source_multiarch_and_kernel_container() -> None:
    rows = [
        {
            "id": str(i),
            "name": "example",
            "version": "1.0-1",
            "package_manager": "dpkg",
            "architecture": arch,
            "source_package": "example-source",
            "original_data": {},
        }
        for i, arch in enumerate(["amd64", "arm64"])
    ]
    values = components(
        rows,
        {"distribution": "ubuntu", "release": "noble"},
        {"version_raw": "6.8.0-old"},
        [{"container_id": "id", "image_reference": "example:latest", "image_digest": "sha256:abc"}],
    )
    assert len(values) == 4
    assert "osv:Ubuntu:example" in component_keys(values[0])
    assert "source:example-source" in component_keys(values[0])
    assert not any(k.startswith("cpe:") for k in component_keys(values[0]))
    assert source_keys([assertion("osv_package", osv_value())]) & component_keys(values[0]) == set()
    assert values[2]["context"] == "running-kernel"
    assert values[3]["sbom_available"] is False


def test_osv_distro_source_release_and_pro_channel() -> None:
    value = osv_value(
        package={"ecosystem": "Ubuntu:24.04:LTS", "name": "example-source"},
        ranges=[
            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1:2.0-2ubuntu1"}]}
        ],
    )
    p = package(
        ecosystem="Ubuntu",
        source_package="example-source",
        source_version="1:2.0-1ubuntu1",
        version="9.0-1",
        distribution="ubuntu",
        release="24.04",
    )
    result = evaluate(enrichment(assertion("osv_package", value)), [p], {})
    assert result.status == "affected"
    assert result.components[0].comparison_version == "1:2.0-1ubuntu1"
    changes: list[dict[str, Any]] = [
        {"source_package": None},
        {"source_version": None},
        {"release": "22.04"},
        {"ecosystem": "Debian"},
    ]
    for change in changes:
        assert (
            evaluate(enrichment(assertion("osv_package", value)), [{**p, **change}], {}).status
            != "affected"
        )
    value["package"]["ecosystem"] = "Ubuntu:Pro:24.04:LTS"
    assert evaluate(enrichment(assertion("osv_package", value)), [p], {}).status != "affected"
    assert (
        evaluate(enrichment(assertion("osv_package", value)), [{**p, "channel": "esm"}], {}).status
        == "affected"
    )


def test_osv_unordered_timeline_multiple_limits_and_infinity() -> None:
    value = {
        "type": "SEMVER",
        "events": [
            {"fixed": "2.0.0"},
            {"limit": "4.0.0"},
            {"introduced": "1.0.0"},
            {"limit": "3.0.0"},
        ],
    }
    assert osv_range("1.5.0", value, "npm")[0] is True
    assert osv_range("2.0.0", value, "npm")[0] is False
    assert osv_range("3.5.0", value, "npm") == (False, "outside_osv_intervals")
    assert osv_range("4.0.0", value, "npm") == (False, "outside_osv_limit")
    assert (
        osv_range(
            "99.0.0", {"type": "SEMVER", "events": [{"introduced": "0"}, {"limit": "*"}]}, "npm"
        )[0]
        is True
    )


def test_explicit_rpm_epoch_comparison_preserves_input() -> None:
    original = {
        "id": "rpm-package",
        "name": "example",
        "version": "1.0-1.el9",
        "epoch": "2",
        "package_manager": "rpm",
        "original_data": {"vendor": "vendor", "product": "product"},
    }
    p = components([original], {"distribution": "rhel", "release": "9"}, {}, [])[0]
    assert p["version"] == original["version"]
    value = {
        "vendor": "vendor",
        "product": "product",
        "versions": [
            {"version": "0", "lessThan": "1:9.0-1.el9", "versionType": "rpm", "status": "affected"}
        ],
        "defaultStatus": "unaffected",
    }
    assert cna(p, value)[0] == "not_affected"
    assert p["comparison_version"] == "2:1.0-1.el9"


def test_cpe_wildcard_dos_is_bounded() -> None:
    assert attribute("*a" * 50 + "b", "a" * 1000) is False


def test_decision_limits_fail_without_partial_success() -> None:
    from cve_matcher.engine import EvaluationLimit

    with pytest.raises(EvaluationLimit):
        evaluate(enrichment(*[assertion("osv_package", osv_value())] * 4097), [package()], {})


@pytest.mark.performance
def test_performance_large_inventory(record_property: Any) -> None:
    import time
    import tracemalloc

    inventory = [
        package(id=str(i), architecture="amd64" if i % 2 else "arm64") for i in range(10000)
    ]
    tracemalloc.start()
    start = time.monotonic()
    result = evaluate(
        enrichment(assertion("osv_package", osv_value())), inventory, {"packages": "complete"}
    )
    duration = time.monotonic() - start
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    record_property("packages_10000_seconds", duration)
    record_property("packages_10000_peak_bytes", peak)
    assert result.status == "affected" and len(result.components) == 10000
    assert duration < 20 and peak < 256 * 1024 * 1024


def test_matching_json_schemas_validate_actual_decision() -> None:
    import json
    from pathlib import Path

    from jsonschema import Draft202012Validator

    result = evaluate(
        enrichment(assertion("osv_package", osv_value())), [package()], {"packages": "complete"}
    )
    for name, value in [
        ("result", result.model_dump(mode="json")),
        ("evidence", result.components[0].model_dump(mode="json")),
        ("coverage", result.coverage),
    ]:
        schema = json.loads(Path("contracts/matching/" + name + ".schema.json").read_text())
        Draft202012Validator(schema).validate(value)


def test_running_old_kernel_is_not_cleared_by_new_installed_kernel() -> None:
    rows = [
        {
            "id": str(i),
            "name": "linux-image-" + str(i),
            "version": version,
            "source_package": "linux",
            "source_version": version,
            "package_manager": "dpkg",
            "original_data": {},
        }
        for i, version in enumerate(["6.1.0-1", "6.1.0-3"])
    ]
    inventory = components(
        rows, {"distribution": "debian", "release": "12"}, {"version_raw": "6.1.0-old-running"}, []
    )
    source = assertion(
        "osv_package",
        osv_value(
            package={"ecosystem": "Debian:12", "name": "linux"},
            ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "6.1.0-2"}]}],
        ),
    )
    result = evaluate(enrichment(source), inventory, {"packages": "complete"})
    assert result.status == "affected"
    assert {d.status for d in result.components} == {"affected", "not_affected"}
    fixed_only = evaluate(enrichment(source), inventory[1:], {"packages": "complete"})
    assert fixed_only.status == "unknown"
    assert fixed_only.coverage["running_kernel"] == "unmapped"
    assert inventory[2]["version"] == "6.1.0-old-running"


def test_cpe_wildcard_index_preserves_candidate() -> None:
    value = assertion(
        "nvd_configuration_logic",
        [{"nodes": [{"cpeMatch": [leaf(CPE.replace(":vendor:", ":vend*:"))]}]}],
    )
    assert source_keys([value]) & component_keys(package(cpe=CPE))
    assert evaluate(enrichment(value), [package(cpe=CPE)], {}).status == "affected"
