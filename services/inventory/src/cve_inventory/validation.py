"""Resource-bounded schema and persisted provenance verification, independent of HTTP."""

import asyncio
import hashlib
import json
import multiprocessing
import resource
from datetime import datetime, timedelta
from importlib.resources import files
from multiprocessing.connection import Connection
from typing import Any
from uuid import UUID

from cve_common.container_inventory import validate_links
from jsonschema import Draft202012Validator, FormatChecker

from cve_inventory.normalization import encoded, normalize


class InvalidInventory(ValueError):
    """Only finite codes, never validator text or payload fragments."""


def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in items:
        if key in result:
            raise InvalidInventory("duplicate_json_key")
        result[key] = item
    return result


def invalid_constant(_value: str) -> Any:
    raise InvalidInventory("nonstandard_json")


def validate(row: dict[str, Any]) -> dict[str, Any]:
    raw = bytes(row["payload_raw"])
    if not 0 < len(raw) <= 10485760:
        raise InvalidInventory("payload_size")
    if hashlib.sha256(raw).digest() != bytes(row["payload_sha256"]):
        raise InvalidInventory("raw_hash_mismatch")
    version = row["schema_version"]
    if version not in {"1.0", "1.1", "1.2", "1.3"}:
        raise InvalidInventory("unsupported_schema")
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid_constant
        )
    except (UnicodeError, ValueError, RecursionError):
        raise InvalidInventory("invalid_json") from None
    queue = [(value, 0)]
    nodes = 0
    while queue:
        item, depth = queue.pop()
        nodes += 1
        if depth > 32 or nodes > 750000:
            raise InvalidInventory("structure_limit")
        if isinstance(item, dict):
            if len(item) > 128 or any(len(k) > 128 for k in item):
                raise InvalidInventory("key_limit")
            queue.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            if len(item) > 100000:
                raise InvalidInventory("array_limit")
            queue.extend((v, depth + 1) for v in item)
        elif isinstance(item, str) and (
            len(item) > 65536 or "\x00" in item or any(0xD800 <= ord(c) <= 0xDFFF for c in item)
        ):
            raise InvalidInventory("string_limit")
    name = "inventory-v1.schema.json" if version == "1.0" else f"inventory-v{version}.schema.json"
    schema = json.loads(files("cve_inventory").joinpath("data/" + name).read_text())
    if not Draft202012Validator(schema, format_checker=FormatChecker()).is_valid(value):
        raise InvalidInventory("invalid_contract")
    if value != row["payload_json"] or hashlib.sha256(encoded(value).encode()).digest() != bytes(
        row["canonical_sha256"]
    ):
        raise InvalidInventory("canonical_hash_mismatch")
    if (
        value["schema_version"] != version
        or ("host" not in value and UUID(value["server_id"]) != row["server_id"])
        or (
            "host" in value
            and UUID(value["host"]["monitoring_id"]) != row.get("host_monitoring_id")
        )
        or UUID(value["inventory_id"]) != row["inventory_id"]
    ):
        raise InvalidInventory("identity_mismatch")
    try:
        validate_links(value)
    except ValueError:
        raise InvalidInventory("container_software_binding") from None
    captured = datetime.fromisoformat(value["captured_at"].replace("Z", "+00:00"))
    if captured != row["collected_at"] or captured > row["received_at"] + timedelta(minutes=5):
        raise InvalidInventory("invalid_timestamp")
    if row["source"] == "ansible_api":
        valid = (
            row["source_identity"] == row["technical_principal_id"]
            and row["token_id"] is not None
            and row["certificate_id"] is not None
            and row["certificate_fingerprint"] is not None
            and len(row["certificate_fingerprint"]) == 32
            and row["actor_user_id"] is None
        )
    elif row["source"] == "managed_ansible":
        valid = (
            row["source_identity"] == row["ansible_run_id"]
            and row["actor_user_id"] is not None
            and row["technical_principal_id"] is None
        )
    else:
        valid = (
            row["source"] == "dashboard_file"
            and row["source_identity"] == row["actor_user_id"]
            and row["session_reference"] is not None
            and row["technical_principal_id"] is None
        )
    if not valid:
        raise InvalidInventory("invalid_provenance")
    return normalize(value, row["received_at"])


def child(pipe: Connection, row: dict[str, Any]) -> None:
    try:
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        pipe.send((True, validate(row)))
    except InvalidInventory as error:
        pipe.send((False, str(error)))
    except Exception:
        pipe.send((False, "normalization_failed"))
    finally:
        pipe.close()


async def prepare(row: dict[str, Any], seconds: float = 35) -> dict[str, Any]:
    ctx = multiprocessing.get_context("spawn")
    parent, writer = ctx.Pipe(duplex=False)
    process = ctx.Process(target=child, args=(writer, row), daemon=True)
    process.start()
    writer.close()
    try:
        async with asyncio.timeout(seconds):
            success, result = await asyncio.to_thread(parent.recv)
        if not success:
            raise InvalidInventory(result)
        assert isinstance(result, dict)
        return result
    except (EOFError, OSError):
        raise InvalidInventory("resource_limit") from None
    finally:
        if process.is_alive():
            process.kill()
        await asyncio.to_thread(process.join, 1)
        parent.close()
        process.close()
