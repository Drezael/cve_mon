"""Prüfe Phase-0-Verträge, Beispiele und Sicherheitsinvarianten ohne Laufzeitdienste."""

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import yaml
from jsonschema import Draft202012Validator, FormatChecker, SchemaError

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.repository_files import repository_files

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "contracts/phase-00-manifest.json"
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
EXPECTED_SERVICES = {
    "cve-nginx",
    "cve-postgres",
    "cve-n8n",
    "cve-mailhog",
    "cve-mail-relay",
    "cve-api",
    "cve-dashboard",
    "cve-importer",
    "cve-enricher",
    "cve-inventory",
    "cve-matcher",
    "cve-findings",
    "cve-reporter",
    "cve-event-dispatcher",
    "cve-notification",
    "cve-service-status",
}


def load_json(path: Path) -> Any:
    """Lade striktes JSON ohne doppelte Schlüssel, NaN oder Infinity."""

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"Doppelter JSON-Schlüssel: {key}")
            result[key] = value
        return result

    def constant(value: str) -> None:
        raise ValueError(f"Ungültige JSON-Konstante: {value}")

    return json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=pairs, parse_constant=constant
    )


def walk(value: Any) -> Iterator[dict[str, Any]]:
    """Besuche Objektknoten einer begrenzten Vertragsdatei."""
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def local_references(path: Path, root: Path, visited: set[Path] | None = None) -> list[str]:
    """Verweigere Remote-/Pfadflucht-Refs vor Aufruf des OpenAPI-Resolvers."""
    visited = set() if visited is None else visited
    path = path.resolve()
    if not path.is_relative_to(root.resolve()):
        return [f"{path}: Referenz außerhalb des Repositorys"]
    if path in visited:
        return []
    visited.add(path)
    document = load_json(path) if path.suffix == ".json" else yaml.safe_load(path.read_text())
    errors: list[str] = []
    for node in walk(document):
        for key in ("$ref", "$dynamicRef"):
            if key not in node:
                continue
            reference = node[key]
            if not isinstance(reference, str):
                errors.append(f"{path}: {key} muss ein String sein")
                continue
            parts = urlsplit(reference)
            if parts.scheme or parts.netloc or parts.query:
                errors.append(f"{path}: Nur lokale Vertragsreferenzen erlaubt: {reference}")
                continue
            target = (path.parent / unquote(parts.path)).resolve() if parts.path else path
            if not target.is_relative_to(root.resolve()) or not target.is_file():
                errors.append(f"{path}: Fehlende oder externe Referenz: {reference}")
                continue
            # OpenAPI prüft anschließend JSON-Pointer; Dateien zunächst rekursiv absichern.
            if target != path:
                errors.extend(local_references(target, root, visited))
    return errors


def validate_openapi(path: Path, root: Path) -> list[str]:
    """Validiere OpenAPI semantisch, mit lokalen Ref-Dateien und ohne Netzwerkresolver."""
    errors = local_references(path, root)
    if errors:
        return errors
    result = subprocess.run(
        [sys.executable, "-m", "openapi_spec_validator", str(path)],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        return [f"{path}: OpenAPI ungültig\n{result.stdout}{result.stderr}"]
    return []


def security_invariants(spec: dict[str, Any]) -> list[str]:
    """Prüfe konkrete Auth-Grenzen zusätzlich zur OpenAPI-Standardvalidierung."""
    errors: list[str] = []
    expected: dict[str, dict[str, list[str]]] = {
        "/api/v1/inventories": {"MutualTLS": [], "UploadToken": []},
        "/api/v1/dashboard/inventories/upload": {"DashboardSession": [], "CsrfToken": []},
    }
    for path, schemes in expected.items():
        operation = spec.get("paths", {}).get(path, {}).get("post", {})
        if operation.get("security") != [schemes]:
            errors.append(f"{path}: Pflicht-Authentifizierung muss UND-verknüpft sein")
        permission = (
            "inventory:submit" if path == "/api/v1/inventories" else ("inventory:upload:dashboard")
        )
        if operation.get("x-permission") != permission:
            errors.append(f"{path}: Upload-Berechtigung stimmt nicht mit dem Kanal überein")
        body = operation.get("requestBody", {}).get("content", {})
        mime = "application/json" if path == "/api/v1/inventories" else "multipart/form-data"
        schema = "Inventory" if mime == "application/json" else "DashboardUpload"
        if body.get(mime, {}).get("schema") != {"$ref": f"#/components/schemas/{schema}"}:
            errors.append(f"{path}: Unerwarteter Uploadvertrag")
    inventory = spec.get("components", {}).get("schemas", {}).get("Inventory", {})
    if inventory != {"$ref": "../inventory/inventory-v1.schema.json"}:
        errors.append("OpenAPI muss dasselbe Inventarschema referenzieren")
    for path, item in spec.get("paths", {}).items():
        for method, operation in item.items():
            if method not in HTTP_METHODS:
                continue
            for field in ("x-permission", "x-object-scope", "x-owner", "x-ingress", "security"):
                if field not in operation:
                    errors.append(f"{method.upper()} {path}: {field} fehlt")
            if path.startswith("/api/v1/dashboard/admin/"):
                required: dict[str, list[str]] = {"DashboardSession": []}
                if method not in {"get", "head"}:
                    required["CsrfToken"] = []
                if operation.get("security") != [required]:
                    errors.append(f"{path}: Administration erfordert menschliche Sitzung/CSRF")
            if path.startswith("/internal/") and operation.get("security") != [
                {"InternalMTLS": [], "ServiceIdentity": []}
            ]:
                errors.append(f"{path}: Interner Dienstnachweis fehlt")
    status = spec.get("paths", {}).get("/api/v1/dashboard/deployment/status", {}).get("get", {})
    if status.get("parameters") or status.get("x-permission") != "deployment:status:read":
        errors.append("Statuspage darf keine frei wählbaren Prüfparameter akzeptieren")
    if status.get("security") != [{"DashboardSession": []}]:
        errors.append("Statuspage erfordert eine menschliche Sitzung")
    header = status.get("responses", {}).get("200", {}).get("headers", {}).get("Cache-Control", {})
    if header.get("schema", {}).get("const") != "no-store":
        errors.append("Statuspage muss no-store spezifizieren")
    return errors


def validate_examples(root: Path, manifest: dict[str, Any]) -> list[str]:
    """Prüfe nicht nur Ablehnung, sondern den vorgesehenen Ablehnungsgrund."""
    schema_path = root / manifest["schema"]
    schema = load_json(schema_path)
    Draft202012Validator.check_schema(schema)
    checker = FormatChecker()
    if checker.conforms("invalid", "date-time") or checker.conforms("invalid", "uuid"):
        return ["UUID-/RFC3339-Formatprüfung fehlt in der Entwicklungsumgebung"]
    validator = Draft202012Validator(schema, format_checker=checker)
    errors: list[str] = []
    listed = {item["path"] for item in manifest["examples"]}
    discovered = {
        str(path.relative_to(root))
        for path in (root / "contracts/inventory/examples").glob("*.json")
    }
    if listed != discovered or len(listed) != len(manifest["examples"]):
        errors.append("Inventarbeispiele und explizite Manifest-Erwartungen stimmen nicht überein")
    for case in manifest["examples"]:
        path = root / case["path"]
        failures = list(validator.iter_errors(load_json(path)))
        if case["valid"]:
            errors.extend(f"{path}: Erwartet gültig: {error.message}" for error in failures)
        elif not any(
            "/" + "/".join(str(part) for part in error.absolute_path) == case["error_pointer"]
            and error.validator == case["keyword"]
            for error in failures
        ):
            errors.append(f"{path}: Erwarteter Ablehnungsgrund fehlt: {case['error_pointer']}")
    return errors


def validate_policy(root: Path) -> list[str]:
    """Sichere Dienstumfang, Egress-Grenze und administrative DB-Hoheit ab."""
    policy = load_json(root / "contracts/security/service-access-v1.json")
    errors: list[str] = []
    services = policy["services"]
    if set(services) != EXPECTED_SERVICES:
        errors.append("Komponentenkatalog: unerwartete oder fehlende Dienste")
    if policy["group_write_roles"] != ["dashboard_admin"]:
        errors.append("Gruppenschreibrechte sind ausschließlich dashboard_admin vorbehalten")
    if set(policy["inventory_roles"]) & set(policy["group_write_roles"]):
        errors.append("Inventarrollen dürfen keine Gruppen schreiben")
    expected_networks = {
        "cve_ingress": False,
        "cve_internal": True,
        "cve_data": True,
        "cve_outbound": False,
    }
    if {
        name: config["internal"] for name, config in policy["networks"].items()
    } != expected_networks:
        errors.append("Netzwerk-Vertrauenszonen stimmen nicht mit Phase 0 überein")
    if services.get("cve-inventory", {}).get("database_roles") != ["inventory_processor"]:
        errors.append("Inventory Processor darf keine administrativen DB-Rollen erhalten")
    for name, service in services.items():
        if "cve_outbound" in service["networks"] and name not in {
            "cve-importer",
            "cve-enricher",
            "cve-mail-relay",
            "cve-n8n",
            "cve-mailhog",
        }:
            errors.append(f"{name}: Kein konfigurierter direkter Ausgangsdienst")
        if name != "cve-nginx" and "cve_ingress" in service["networks"]:
            errors.append(f"{name}: Öffentlicher Ingress nur für Nginx")
        if set(service["networks"]) - set(policy["networks"]):
            errors.append(f"{name}: Unbekanntes Netzwerk")
    if policy["public_ports"] != {"cve-nginx": [80, 443]}:
        errors.append("Nur Nginx HTTP/80 und HTTPS/443 dürfen öffentlich sein")
    if services.get("cve-dashboard", {}).get("database_roles"):
        errors.append("Dashboard darf keine direkte DB-Rolle erhalten")
    return errors


def validate_document_links(root: Path) -> list[str]:
    """Erkenne kaputte lokale Markdown-Dateiverweise ohne Webzugriff."""
    errors: list[str] = []
    for path in repository_files(root):
        if path.suffix != ".md":
            continue
        for target in re.findall(r"\]\(([^)]+)\)", path.read_text(encoding="utf-8")):
            if "://" in target or target.startswith("#"):
                continue
            target_path = (path.parent / unquote(target.split("#")[0])).resolve()
            if not target_path.is_relative_to(root.resolve()) or not target_path.is_file():
                errors.append(f"{path}: Fehlender lokaler Dokumentverweis: {target}")
    return errors


def validate_contracts(root: Path) -> list[str]:
    """Führe alle vorhandenen Phase-0-Nachweise gesammelt aus."""
    try:
        manifest = load_json(root / MANIFEST)
        errors = [
            f"Phase-0-Pflichtdatei fehlt: {name}"
            for name in manifest["required_files"]
            if not (root / name).is_file()
        ]
        errors.extend(validate_examples(root, manifest))
        openapi = root / manifest["openapi"]
        openapi_errors = validate_openapi(openapi, root)
        errors.extend(openapi_errors)
        spec = yaml.safe_load(openapi.read_text())
        if not openapi_errors:
            errors.extend(security_invariants(spec))
        errors.extend(validate_policy(root))
        errors.extend(validate_document_links(root))
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        yaml.YAMLError,
        RecursionError,
        SchemaError,
        subprocess.SubprocessError,
    ) as exc:
        return [f"Vertragsprüfung fehlgeschlagen: {exc}"]
    count = len(manifest["examples"])
    print(f"Phase-0-Verträge: OpenAPI, Inventarschema und {count} Beispiele geprüft.")
    return errors


def main() -> int:
    """Biete den lokalen und CI-Einstieg ohne produktive Dienste."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    errors = validate_contracts(args.root.resolve())
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("Alle Phase-0-Verträge und lokalen Dokumentverweise gültig.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
