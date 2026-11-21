"""Validiere Phase-1-Struktur und vorhandene strukturierte Konfigurationen."""

import argparse
import hashlib
import json
import subprocess
import sys
import warnings
from pathlib import Path

import yaml
from jsonschema import SchemaError
from jsonschema.validators import validator_for

# Direkter Skriptaufruf und Import in Tests verwenden denselben Modulpfad.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.infrastructure.manage import validate_compose_files
from scripts.repository_files import repository_files
from scripts.validate_contracts import MANIFEST, load_json, validate_contracts

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_DIRS: tuple[str, ...] = (
    "infrastructure",
    "services",
    "integrations/ansible",
    "integrations/n8n",
    "database/migrations",
    "database/schemas",
    "contracts/api",
    "contracts/inventory",
    "contracts/security",
    "contracts/events",
    "docs/architecture",
    "docs/development",
    "docs/deployment",
    "docs/database",
    "docs/security",
    "docs/dashboard",
    "docs/statuspage",
    "docs/testing",
    "docs/operations",
    "tests/unit",
    "tests/integration",
    "tests/end-to-end",
    "tests/security",
    "tests/performance",
    "requirements",
    "scripts",
    ".github/workflows",
    "services/inventory",
    "services/uploads/technical",
    "services/uploads/dashboard",
    "services/dashboard/administration",
)
REQUIRED_FILES: tuple[str, ...] = (
    "cve_mon",
    "database/migrations/versions/00026_notifications.py",
    "database/migrations/versions/00027_notification_commands.py",
    "services/application/Dockerfile",
    "services/notification/pyproject.toml",
    "docs/architecture/notification-system.md",
    "docs/development/phase-19-status.md",
    "docs/development/phase-19-acceptance.md",
    "docs/development/phase-19-handover.md",
    "docs/testing/phase-19-test-matrix.md",
    "contracts/api/notification-management.openapi.yaml",
    "contracts/notifications/notification-event.schema.json",
    "contracts/notifications/notification-intent.schema.json",
    "contracts/notifications/notification-delivery.schema.json",
    "contracts/notifications/notification-rule.schema.json",
    "contracts/notifications/notification-template.schema.json",
    "contracts/notifications/workflow-command.schema.json",
    "workflows/n8n/finding-notification-dispatch.json",
    "workflows/n8n/finding-notification-digest.json",
    "workflows/n8n/finding-notification-escalation.json",
    "workflows/n8n/finding-notification-exception.json",
    "workflows/n8n/finding-notification-reconciliation.json",
    "workflows/n8n/finding-notification-health.json",
    "database/migrations/versions/00024_finding_management.py",
    "database/migrations/versions/00025_finding_commands.py",
    "services/application/Dockerfile",
    "services/findings/pyproject.toml",
    "docs/architecture/finding-management.md",
    "docs/development/phase-18-status.md",
    "docs/development/phase-18-acceptance.md",
    "docs/development/phase-18-handover.md",
    "contracts/findings/finding.schema.json",
    "contracts/api/finding-management.openapi.yaml",
    "database/migrations/versions/00023_matching_engine.py",
    "services/matcher/pyproject.toml",
    "services/application/Dockerfile",
    "docs/architecture/matching-engine.md",
    "docs/development/phase-17-status.md",
    "docs/development/phase-17-acceptance.md",
    "docs/development/phase-17-handover.md",
    "contracts/matching/result.schema.json",
    "contracts/matching/evidence.schema.json",
    "contracts/matching/event.schema.json",
    "contracts/matching/coverage.schema.json",
    MANIFEST,
    ".editorconfig",
    ".gitignore",
    ".env.example",
    "configuration/examples/development.env",
    "configuration/quality/yamllint.yml",
    "configuration/quality/secrets.baseline",
    "README.md",
    "Makefile",
    "pyproject.toml",
    "requirements/dev.in",
    "requirements/dev.txt",
    "scripts/bootstrap_dev.sh",
    "scripts/validate_repository.py",
    "scripts/scan_secrets.py",
    "scripts/repository_files.py",
    ".github/workflows/quality.yml",
    "tests/conftest.py",
    "tests/unit/test_repository_structure.py",
    "tests/unit/test_development_configuration.py",
    "docs/development/coding-standards.md",
    "docs/development/developer-setup.md",
    "docs/development/development-status.md",
    "docs/development/phase-01-acceptance.md",
)


REQUIRED_FILES += (
    "docs/development/phase-24-status.md",
    "docs/development/phase-24-acceptance.md",
    "docs/development/phase-24-handover.md",
    "docs/deployment/release-and-recovery.md",
    "docs/operations/platform-handbook.md",
    "docs/dashboard/platform-manual.md",
    "scripts/deployment/manage.py",
    "scripts/deployment/acceptance.py",
    "configuration/deployment/config/configuration.schema.json",
    "configuration/deployment/release/manifest.schema.json",
)


# Phase 2 ergänzt die frühere reine Entwicklungsgrundstruktur.
REQUIRED_DIRS += (
    "infrastructure/nginx/conf.d",
    "infrastructure/nginx/snippets",
    "infrastructure/nginx/templates",
    "scripts/development",
    "scripts/infrastructure",
    "tests/infrastructure/fixtures",
)
REQUIRED_FILES += (
    "compose.yml",
    "infrastructure/compose/development.yml",
    "scripts/infrastructure/manage.py",
    "scripts/development/generate-dev-certificates.sh",
    "scripts/infrastructure/preflight.sh",
    "scripts/infrastructure/check-nginx-config.sh",
    "scripts/infrastructure/test-tls.sh",
    "scripts/infrastructure/test-mtls.sh",
    "scripts/infrastructure/test-network-isolation.sh",
    "infrastructure/nginx/nginx.conf",
    "infrastructure/nginx/templates/http.conf.template",
    "infrastructure/nginx/snippets/tls.conf",
    "infrastructure/nginx/snippets/proxy-headers.conf",
    "infrastructure/nginx/snippets/security-headers.conf.template",
    "infrastructure/nginx/snippets/logging.conf",
    "infrastructure/nginx/snippets/errors.conf",
    "tests/infrastructure/fixtures/compose.network-audit.yml",
    "tests/infrastructure/test_compose_configuration.py",
    "tests/infrastructure/test_network_definitions.py",
    "tests/infrastructure/test_nginx_configuration.py",
    "tests/infrastructure/test_ingress_security.py",
    "tests/infrastructure/test_network_isolation.py",
    "tests/infrastructure/conftest.py",
    "tests/infrastructure/client.py",
    "docs/development/phase-02-status.md",
    "docs/development/phase-02-acceptance.md",
    "docs/development/phase-02-handover.md",
    "docs/deployment/docker-compose.md",
    "docs/deployment/environments.md",
    "docs/deployment/nginx.md",
    "docs/deployment/tls-certificates.md",
    "docs/deployment/maintenance.md",
    "docs/security/network-isolation.md",
    "docs/security/ingress-security.md",
    "docs/security/mtls-boundaries.md",
    "docs/testing/phase-02-test-matrix.md",
    "docs/operations/nginx-troubleshooting.md",
    "docs/architecture/decisions/ADR-0020-http-ingress-phase02.md",
) + tuple(
    "infrastructure/nginx/conf.d/" + name + ".conf.template"
    for name in (
        "00-default",
        "10-dashboard",
        "20-api",
        "30-inventory",
        "40-n8n",
    )
)


# Phase 3: ausführbare DDL, PostgreSQL-Härtung und isolierte Wiederherstellung.
REQUIRED_DIRS += ("infrastructure/postgres", "database/migrations/versions", "tests/database")
REQUIRED_FILES += (
    "database/alembic.ini",
    "database/migrations/env.py",
    "scripts/database/manage.py",
    "scripts/database/tls.py",
    "infrastructure/images.lock.json",
    "infrastructure/postgres/postgresql.conf",
    "infrastructure/postgres/pg_hba.conf",
    "infrastructure/postgres/pg_ident.conf",
    "infrastructure/postgres/initdb/01-bootstrap.sh",
    "infrastructure/postgres/health/check-ready.sh",
    "docs/deployment/postgresql.md",
    "docs/operations/postgresql-backup-restore.md",
    "docs/development/phase-03-status.md",
    "docs/development/phase-03-acceptance.md",
    "docs/development/phase-03-handover.md",
    "docs/architecture/decisions/ADR-0021-postgresql-phase03.md",
)


REQUIRED_DIRS += (
    "infrastructure/envoy",
    "infrastructure/envoy/policies",
    "tests/infrastructure/envoy",
)
REQUIRED_FILES += (
    "infrastructure/envoy/envoy.yaml",
    "infrastructure/mail/init.sh",
    "infrastructure/mail/rsyslog.conf",
    "infrastructure/envoy/policies/egress-policy.yml",
    "infrastructure/envoy/policies/egress-policy.schema.json",
    "scripts/infrastructure/envoy.py",
    "scripts/infrastructure/check-envoy-config.sh",
    "scripts/infrastructure/check-egress-policies.py",
    "docs/deployment/envoy.md",
    "docs/security/egress-security.md",
    "docs/security/dns-ssrf-protection.md",
    "docs/security/smtp-proxy-security.md",
    "docs/testing/phase-04-test-matrix.md",
    "docs/operations/envoy-troubleshooting.md",
    "docs/architecture/decisions/ADR-0022-envoy-phase04.md",
    "docs/development/phase-04-status.md",
    "docs/development/phase-04-acceptance.md",
    "docs/development/phase-04-handover.md",
)


# Phase 15: source worker and complete operational/source contracts.
REQUIRED_DIRS += (
    "services/importer/src/cve_importer",
    "scripts/cve_importer",
    "tests/cve_importer",
    "docs/sources",
)
REQUIRED_FILES += (
    "services/importer/pyproject.toml",
    "services/application/Dockerfile",
    "database/migrations/versions/00020_cve_importer.py",
    "contracts/events/cve-import-v1.schema.json",
    "docs/architecture/cve-importer.md",
    "docs/database/cve-source-records.md",
    "docs/database/cve-revisions.md",
    "docs/security/cve-importer-security.md",
    "docs/operations/cve-importer.md",
    "docs/operations/cve-import-recovery.md",
    "docs/operations/cve-source-reconciliation.md",
    "docs/testing/phase-15-test-matrix.md",
    "docs/development/phase-15-status.md",
    "docs/development/phase-15-acceptance.md",
    "docs/development/phase-15-handover.md",
    "docs/sources/cveproject.md",
    "docs/sources/nvd.md",
    "docs/sources/cisa-kev.md",
    "docs/sources/ubuntu.md",
    "docs/sources/osv.md",
)


# Phase 16: enrichment, provenance and separate EPSS publication.
REQUIRED_DIRS += (
    "services/enricher/src/cve_enricher",
    "scripts/cve_enricher",
    "tests/cve_enricher",
)
REQUIRED_FILES += (
    "contracts/events/cve-enrichment-v1.schema.json",
    "database/migrations/versions/00021_cve_enrichment.py",
    "docs/architecture/cve-enricher.md",
    "docs/database/cve-enrichment-revisions.md",
    "docs/database/epss-history.md",
    "docs/development/phase-16-acceptance.md",
    "docs/development/phase-16-analysis.md",
    "docs/development/phase-16-handover.md",
    "docs/development/phase-16-status.md",
    "docs/operations/cve-enricher.md",
    "docs/operations/cve-enrichment-recovery.md",
    "docs/operations/epss-sync.md",
    "docs/security/cve-enricher-security.md",
    "docs/sources/cve-enrichment-source-policy.md",
    "docs/sources/cvss.md",
    "docs/sources/epss.md",
    "docs/sources/kev.md",
    "docs/sources/osv-enrichment.md",
    "docs/sources/ubuntu-enrichment.md",
    "docs/testing/phase-16-test-matrix.md",
    "services/application/Dockerfile",
    "services/enricher/pyproject.toml",
)


REQUIRED_FILES += (
    "database/migrations/versions/00022_enrichment_observability.py",
    "contracts/cve/enrichment-v1.schema.json",
)


def validate_structure(root: Path) -> list[str]:
    """Liefere alle fehlenden Pflichtpfade statt nur des ersten Fehlers."""
    errors = [f"Verzeichnis fehlt: {name}" for name in REQUIRED_DIRS if not (root / name).is_dir()]
    errors.extend(f"Datei fehlt: {name}" for name in REQUIRED_FILES if not (root / name).is_file())
    return errors


def validate_configuration(path: Path) -> list[str]:
    """Prüfe Syntax und Schema-Definitionen; lade YAML ohne ausführbare Tags."""
    try:
        content = path.read_text(encoding="utf-8")
        if path.suffix.lower() in {".yml", ".yaml"}:
            list(yaml.safe_load_all(content))
        else:
            # These three byte-identical upstream CVSS resources define scoreType twice.
            # Preserve the reviewed upstream bytes/last-definition semantics, while all
            # source records and all other repository JSON retain strict duplicate rejection.
            pinned_cvss = any(
                path.as_posix().endswith(
                    "services/importer/src/cve_importer/data/"
                    + version
                    + "/imports/cvss/cvss-v3.1.json"
                )
                for version in ("cve-5.1", "cve-5.1.1", "cve-5.2.0")
            )
            if pinned_cvss and "sha256:" + hashlib.sha256(content.encode()).hexdigest() == (
                "sha256:9b0a73323ad9821390af2a446572bee9169f861db073b64cc820b0b49ea2fd29"
            ):
                document = json.loads(content)
            else:
                document = load_json(path)
            is_schema = path.name.endswith(".schema.json") or (
                isinstance(document, dict) and "$schema" in document
            )
            if is_schema:
                if not isinstance(document, (dict, bool)):
                    raise ValueError("JSON-Schema muss ein Objekt oder Boolean sein")
                if isinstance(document, bool):
                    return []
                if "$schema" in document and not isinstance(document["$schema"], str):
                    raise ValueError("JSON-Schema-Dialekt muss eine URI als String sein")
                # Unbekannte Dialekte erzeugen sonst nur eine Warnung mit stillem Fallback.
                with warnings.catch_warnings():
                    warnings.simplefilter("error", DeprecationWarning)
                    validator_for(document).check_schema(document)
    except (
        OSError,
        UnicodeError,
        ValueError,
        DeprecationWarning,
        yaml.YAMLError,
        SchemaError,
    ) as exc:
        return [f"{path}: {exc}"]
    return []


def validate_configurations(root: Path) -> list[str]:
    """Prüfe auch später hinzugefügte YAML-/JSON-Dateien einschließlich Yamllint."""
    errors: list[str] = []
    files = repository_files(root)
    yaml_files = [path for path in files if path.suffix.lower() in {".yaml", ".yml"}]
    for path in files:
        if path.suffix.lower() in {".json", ".yaml", ".yml"} or path.name == "secrets.baseline":
            errors.extend(validate_configuration(path))
    for path in yaml_files:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "yamllint",
                "-c",
                str(root / "configuration/quality/yamllint.yml"),
                str(path),
            ],
            capture_output=True,
            text=True,
            check=False,
            cwd=root,
        )
        if result.returncode:
            errors.append(result.stdout + result.stderr)
    print(f"Konfiguration: {len(yaml_files)} YAML-Dateien; JSON und Schemas geprüft.")
    return errors


def main() -> int:
    """Melde Fehler gesammelt und liefere einen verlässlichen Exit-Code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        errors = (
            validate_structure(root)
            + validate_configurations(root)
            + validate_contracts(root)
            + validate_compose_files(root)
        )
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Validierung fehlgeschlagen: {exc}", file=sys.stderr)
        return 1
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(
        "Repositorystruktur, Konfiguration und beide Compose-Modelle gültig (kein Containerstart)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
