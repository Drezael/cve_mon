"""Controller-only normalization. Never connects to a host or executes commands."""

from __future__ import annotations

import contextlib
import json
import re
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

from jsonschema import Draft202012Validator, FormatChecker

MAX_BYTES = 10485760
ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = {
    "1.0": "inventory-v1.schema.json",
    "1.1": "inventory-v1.1.schema.json",
    "1.2": "inventory-v1.2.schema.json",
    "1.3": "inventory-v1.3.schema.json",
}


class InventoryError(ValueError):
    """Safe fixed error codes; no remote output or secrets in diagnostics."""


def server_uuid(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value
    ):
        raise InventoryError("invalid_server_uuid")
    if UUID(value).int == 0:
        raise InventoryError("invalid_server_uuid")
    return value


def field(value: Any, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value)
    ):
        raise InventoryError("invalid_collected_field")
    return value


def schema(version: str) -> dict[str, Any]:
    if not isinstance(version, str) or version not in SCHEMAS:
        raise InventoryError("unsupported_schema")
    return cast(
        dict[str, Any],
        json.loads(files("cve_inventory").joinpath("data/" + SCHEMAS[version]).read_text()),
    )


def validate(value: Any) -> None:
    if not isinstance(value, dict):
        raise InventoryError("invalid_inventory")
    validator = Draft202012Validator(
        schema(value.get("schema_version", "")), format_checker=FormatChecker()
    )
    if not validator.is_valid(value):
        raise InventoryError("inventory_schema")
    server_uuid(value["host"]["monitoring_id"] if "host" in value else value["server_id"])
    captured = datetime.fromisoformat(value["captured_at"].replace("Z", "+00:00"))
    if captured.timestamp() > datetime.now(UTC).timestamp() + 300:
        raise InventoryError("future_timestamp")
    if len(encode(value)) > MAX_BYTES:
        raise InventoryError("inventory_size")


def encode(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in items:
        if key in result:
            raise InventoryError("duplicate_json_key")
        result[key] = value
    return result


def decode(raw: bytes, maximum: int = MAX_BYTES) -> Any:
    if len(raw) > maximum:
        raise InventoryError("inventory_size")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(InventoryError("invalid_json")),
        )
        encode(value)
        return value
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise InventoryError("invalid_json") from None


def unique(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [json.loads(row) for row in sorted({encode(row) for row in rows})]


def packages(result: dict[str, Any], fallback: dict[str, Any], manager: str) -> dict[str, Any]:
    if manager not in ("apt", "dpkg", "dnf", "dnf5", "yum", "rpm", "zypper"):
        return {"status": "failed", "error_code": "unsupported_package_manager"}
    kind = "dpkg" if manager in ("apt", "dpkg") else "rpm"
    entries = []
    invalid = False
    if not result.get("failed") and isinstance(
        result.get("ansible_facts", {}).get("packages"), dict
    ):
        for rows in result["ansible_facts"]["packages"].values():
            if not isinstance(rows, list):
                invalid = True
                continue
            entries.extend(rows)
    elif fallback.get("rc", 1) == 0:
        for line in fallback.get("stdout", "").splitlines():
            parts = line.split("\t")
            if kind == "dpkg" and len(parts) == 4:
                name, version, arch, state = parts
                if state != "installed":
                    continue
                entries.append({"name": name, "version": version, "arch": arch})
            elif kind == "rpm" and len(parts) == 5:
                name, epoch, version, release, arch = parts
                entries.append(
                    {
                        "name": name,
                        "epoch": epoch,
                        "version": version,
                        "release": release,
                        "arch": arch,
                    }
                )
            else:
                invalid = True
    else:
        return {"status": "failed", "error_code": "package_query_failed"}
    rows = []
    for entry in entries:
        try:
            version = field(entry["version"], 512)
            row: dict[str, Any] = {
                "name": field(entry["name"]),
                "architecture": field(entry.get("arch"), 64),
                "package_manager": kind,
            }
            if kind == "rpm":
                release = entry.get("release")
                epoch = entry.get("epoch")
                if release not in (None, ""):
                    row["release"] = field(str(release))
                    version += "-" + row["release"]
                if epoch not in (None, "", "(none)", "(null)"):
                    row["epoch"] = field(str(epoch), 32)
                    version = row["epoch"] + ":" + version
            row["version"] = field(version, 512)
            rows.append(row)
        except (KeyError, TypeError, InventoryError):
            invalid = True
    return section(rows, invalid, "invalid_package_record")


def section(rows: list[dict[str, Any]], invalid: bool, code: str) -> dict[str, Any]:
    if invalid and not rows:
        return {"status": "failed", "error_code": code}
    value: dict[str, Any] = {"status": "partial" if invalid else "complete", "items": unique(rows)}
    if invalid:
        value["error_code"] = code
    return value


def services(result: dict[str, Any]) -> dict[str, Any]:
    row: dict[str, Any]
    data = result.get("ansible_facts", {}).get("services")
    if result.get("failed") or not isinstance(data, dict):
        return {"status": "failed", "error_code": "service_query_failed"}
    rows = []
    invalid = False
    for entry in data.values():
        try:
            row = {
                "name": field(entry["name"]),
                "state": {"running": "running", "stopped": "stopped", "failed": "failed"}.get(
                    entry.get("state"), "unknown"
                ),
            }
            if entry.get("source"):
                row["manager"] = field(entry["source"], 64)
            row["enabled"] = {"enabled": True, "enabled-runtime": True, "disabled": False}.get(
                entry.get("status")
            )
            rows.append(row)
        except (KeyError, TypeError, InventoryError):
            invalid = True
    return section(rows, invalid, "invalid_service_record")


def docker_section(result: dict[str, Any], kind: str) -> dict[str, Any]:
    if result.get("failed"):
        return {"status": "failed", "error_code": kind + "_query_failed"}
    rows = []
    invalid = False
    row: dict[str, Any]
    for item in result.get("results", []):
        try:
            if item.get("failed") or item.get("rc", 1) != 0:
                raise InventoryError("docker_query_failed")
            data = decode(item["stdout"].encode())
            if kind == "containers":
                row = {
                    k: field(data[k], n)
                    for k, n in [
                        ("container_id", 128),
                        ("name", 256),
                        ("image_reference", 512),
                        ("image_id", 71),
                        ("created_at", 40),
                    ]
                }
                row["name"] = row["name"].removeprefix("/")
                row["status"] = field(data["state"], 128)
                row["state"] = {
                    "running": "running",
                    "exited": "stopped",
                    "created": "stopped",
                    "dead": "stopped",
                    "paused": "paused",
                }.get(data["state"], "unknown")
                row["collection_status"] = "complete"
            else:
                row = {
                    "image_id": field(data["image_id"], 71),
                    "references": sorted(set(data.get("references") or [])),
                    "repo_digests": sorted(set(data.get("repo_digests") or [])),
                }
                for key in ("architecture", "created_at"):
                    if data.get(key):
                        row[key] = field(data[key])
            # Validate each projected record before publishing it. Never carry extra keys.
            contract = schema("1.1")
            validator = Draft202012Validator(
                {
                    "$ref": "#/$defs/" + ("container" if kind == "containers" else "image"),
                    "$defs": contract["$defs"],
                },
                format_checker=FormatChecker(),
            )
            if not validator.is_valid(row):
                raise InventoryError("docker_record")
            rows.append(row)
        except (KeyError, TypeError, InventoryError):
            invalid = True
    return section(rows, invalid, "invalid_" + kind + "_record")


def normalize(source: dict[str, Any]) -> dict[str, Any]:
    host = source.get("host")
    sid = server_uuid(host["monitoring_id"] if host else source.get("server_id"))
    system = source.get("system", {})
    facts = system.get("ansible_facts", {}) if not system.get("failed") else {}
    data = {}
    for old, new, limit in [
        ("distribution", "distribution", 128),
        ("distribution_version", "release", 128),
        ("architecture", "architecture", 64),
        ("kernel", "kernel", 256),
        ("os_family", "family", 256),
        ("distribution_release", "codename", 256),
        ("kernel_version", "kernel_version", 256),
        ("system", "platform", 256),
    ]:
        value = facts.get("ansible_" + old, facts.get(old))
        if value:
            with contextlib.suppress(InventoryError):
                data[new] = field(value, limit)
    complete = {"distribution", "release", "architecture", "kernel"} <= data.keys()
    os_section: dict[str, Any] = {
        "status": "complete" if complete else "partial" if data else "failed"
    }
    if data:
        os_section["data"] = data
    if not complete:
        os_section["error_code"] = "system_facts_incomplete"
    manager = facts.get("ansible_pkg_mgr", facts.get("pkg_mgr", "unsupported"))
    value = {
        "schema_version": "1.2" if host else "1.1",
        **({"host": host} if host else {"server_id": sid}),
        "inventory_id": str(uuid4()),
        "captured_at": datetime.now(UTC).isoformat(),
        "collector": {"name": "ansible", "version": field(source.get("ansible_version"), 64)},
        "os": os_section,
        "packages": packages(
            source.get("packages", {}), source.get("package_fallback", {}), manager
        ),
        "services": services(source.get("services", {})),
    }
    hardware: dict[str, Any] = {}
    for old, new in [("processor_vcpus", "cpu_count"), ("memtotal_mb", "memory_mb")]:
        v = facts.get("ansible_" + old, facts.get(old))
        if isinstance(v, int) and not isinstance(v, bool) and v > 0:
            hardware[new] = v
    for old in ("virtualization_type", "virtualization_role"):
        v = facts.get("ansible_" + old, facts.get(old))
        if v:
            with contextlib.suppress(InventoryError):
                hardware[old] = field(v, 64 if old.endswith("role") else 128)
    if hardware:
        value["hardware"] = hardware
    docker = source.get("docker", {})
    available = docker.get("cli", False)
    reachable = docker.get("engine", {}).get("rc", 1) == 0
    value["docker"] = {
        "status": "not_installed" if not available else "available" if reachable else "unreachable"
    }
    for kind in ("containers", "images"):
        if not available:
            value[kind] = {"status": "not_collected"}
        elif not reachable:
            value[kind] = {"status": "failed", "error_code": "docker_unreachable"}
        elif docker.get(kind + "_list", {}).get("rc", 1) != 0:
            value[kind] = {"status": "failed", "error_code": kind + "_list_failed"}
        else:
            value[kind] = docker_section(docker.get(kind, {}), kind)
    if "container_software" in source:
        value["schema_version"] = "1.3"
        value["container_software"] = source["container_software"]
    sections = ["os", "packages", "services", "containers", "images"]
    states = [value[k]["status"] for k in sections]
    value["collection_status"] = (
        "complete"
        if all(s in ("complete", "not_collected") for s in states)
        else "partial"
        if any(s in ("complete", "partial") for s in states)
        else "failed"
    )
    value["diagnostics"] = [
        {"section": k, "code": value[k]["error_code"]} for k in sections if "error_code" in value[k]
    ]
    validate(value)
    return value


def host_id(value: dict[str, Any]) -> str:
    return server_uuid(value["host"]["monitoring_id"] if "host" in value else value["server_id"])
