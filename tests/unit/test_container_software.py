"""Container inventory boundaries: actual packages, runtime replacement and mount provenance."""

from typing import Any

from cve_matcher.container_software import software_components
from cve_matcher.engine import evaluate

from scripts.container_inventory.collector import project
from tests.matching.test_engine import assertion, enrichment, osv_value


def container(state: str = "running") -> dict[str, Any]:
    return {"container_id": "c1", "image_id": "sha256:" + "a" * 64, "name": "web", "state": state}


def bill(scope: str = "image", version: str = "1.5.0", **extra: object) -> dict[str, Any]:
    return {
        "container_id": "c1",
        "image_id": "sha256:" + "a" * 64,
        "scope": scope,
        "status": "complete",
        "document": {
            "os": {"id": "debian", "version": "12"},
            "packages": [
                {
                    "name": "example",
                    "version": version,
                    "type": "npm",
                    "purl": "pkg:npm/example@" + version,
                    "locations": ["/app/node_modules/example/package.json"],
                }
            ],
        },
        **extra,
    }


def test_container_packages_match_with_own_context_and_distribution() -> None:
    components = software_components([container()], [bill()])
    assert components[0]["distribution"] == "debian"
    assert components[0]["ecosystem"] == "npm"
    evaluation = evaluate(enrichment(assertion("osv_package", osv_value())), components, {})
    assert evaluation.status == "affected"
    assert evaluation.components[0].context == "container:c1"
    assert evaluation.components[0].evidence[0]["component"]["container_name"] == "web"


def test_complete_runtime_replaces_vulnerable_image_and_stopped_container_is_excluded() -> None:
    values = [bill(), bill("runtime", "2.0.0")]
    components = software_components([container()], values)
    assert len(components) == 1 and components[0]["version"] == "2.0.0"
    assert software_components([container("stopped")], values) == []


def test_mount_shadows_image_and_has_separate_origin() -> None:
    values = [bill(), bill("mount", "2.0.0", target="/app")]
    components = software_components([container()], values)
    assert len(components) == 1 and components[0]["origin"] == "mount"


def test_failed_runtime_does_not_remove_image_evidence() -> None:
    values = [bill(), bill("runtime", document=None, status="failed")]
    assert software_components([container()], values)[0]["version"] == "1.5.0"


def test_sbom_projection_does_not_include_image_environment_or_file_contents() -> None:
    value = {
        "source": {"metadata": {"env": ["SECRET=private"]}},  # pragma: allowlist secret
        "artifacts": [
            {
                "name": "example",
                "version": "1.0.0",
                "type": "npm",
                "purl": "pkg:npm/example@1.0.0",
                "metadata": {"secret": "private"},  # pragma: allowlist secret
                "locations": [{"path": "/app/package.json"}],
            }
        ],
    }
    result = project(value, "1.57.1")
    assert "private" not in str(result)
    assert result["packages"][0]["name"] == "example"
