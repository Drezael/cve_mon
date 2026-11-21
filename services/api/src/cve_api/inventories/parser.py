"Hard-bounded isolated JSON/Schema worker; the authoritative v1 schema is packaged verbatim."

import asyncio
import hashlib
import json
import math
import multiprocessing
import resource
import unicodedata
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from multiprocessing.connection import Connection
from typing import Any
from uuid import UUID

from cve_common.container_inventory import validate_links
from jsonschema import Draft202012Validator, FormatChecker

from .errors import UploadError
from .settings import InventorySettings

RESERVED = frozenset(
    {
        "groupid",
        "groupids",
        "groups",
        "servergroups",
        "primarygroupid",
        "groupsortorder",
        "displayorder",
        "sortorder",
        "criticality",
        "exposure",
        "environment",
        "acl",
        "acls",
        "serveracl",
        "serveracls",
        "registerserver",
    }
)


@dataclass(frozen=True)
class Validated:
    server_id: UUID | None
    inventory_id: UUID
    schema_version: str
    collected_at: datetime
    canonical: bytes = field(repr=False)
    canonical_sha256: bytes
    payload_sha256: bytes
    host: dict[str, str] | None = None


def schema(version: str = "1.0") -> dict[str, Any]:
    if version not in {"1.0", "1.1", "1.2", "1.3"}:
        raise UploadError(422, "inventory_schema")
    filename = (
        "inventory-v1.schema.json" if version == "1.0" else f"inventory-v{version}.schema.json"
    )
    value = json.loads(files("cve_api.inventories").joinpath("data/" + filename).read_text())
    Draft202012Validator.check_schema(value)
    return value  # type: ignore[no-any-return]


def depth_check(raw: str, maximum: int) -> None:
    depth = 0
    quoted = False
    escaped = False
    for char in raw:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "{[":
            depth += 1
            if depth > maximum:
                raise UploadError(422, "json_depth")
        elif char in "}]":
            depth -= 1


def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in items:
        if key in result:
            raise UploadError(400, "duplicate_json_key")
        result[key] = value
    return result


def integer(value: str) -> int:
    if len(value) > 20:
        raise UploadError(400, "numeric_limit")
    return int(value)


def floating(value: str) -> float:
    if len(value) > 32:
        raise UploadError(400, "numeric_limit")
    result = float(value)
    if not math.isfinite(result):
        raise UploadError(400, "nonfinite_number")
    return result


def constant(_value: str) -> Any:
    raise UploadError(400, "nonstandard_json")


def validate(raw: bytes, depth: int = 32, nodes: int = 750000) -> Validated:
    if not raw or len(raw) > 10485760:
        raise UploadError(413 if raw else 400, "payload_size")
    try:
        decoded = raw.decode("utf-8", errors="strict")
        depth_check(decoded, depth)
        value = json.loads(
            decoded,
            object_pairs_hook=pairs,
            parse_int=integer,
            parse_float=floating,
            parse_constant=constant,
        )
    except (UnicodeError, ValueError, RecursionError):
        raise UploadError(400, "malformed_json") from None
    queue = [value]
    count = 0
    while queue:
        item = queue.pop()
        count += 1
        if count > nodes:
            raise UploadError(422, "node_limit")
        if isinstance(item, dict):
            if len(item) > 128:
                raise UploadError(422, "key_limit")
            for key in item:
                normalized = "".join(
                    c
                    for c in unicodedata.normalize("NFKC", key).casefold()
                    if c.isascii() and c.isalnum()
                )
                if normalized in RESERVED:
                    raise UploadError(422, "administrative_field")
                if len(key) > 128:
                    raise UploadError(422, "key_limit")
            queue.extend(item.values())
        elif isinstance(item, list):
            if len(item) > 100000:
                raise UploadError(422, "array_limit")
            queue.extend(item)
        elif isinstance(item, str):
            if "\x00" in item:
                raise UploadError(422, "unrepresentable_unicode")
            if len(item) > 65536:
                raise UploadError(422, "string_limit")
            if any(0xD800 <= ord(c) <= 0xDFFF for c in item):
                raise UploadError(400, "invalid_unicode")
    version = value.get("schema_version") if isinstance(value, dict) else None
    if version not in ("1.0", "1.1", "1.2", "1.3"):
        raise UploadError(422, "inventory_schema")
    validator = Draft202012Validator(schema(version), format_checker=FormatChecker())
    if not validator.is_valid(value):
        raise UploadError(422, "inventory_schema")
    try:
        validate_links(value)
    except ValueError:
        raise UploadError(422, "container_software_binding") from None
    captured = datetime.fromisoformat(value["captured_at"].replace("Z", "+00:00"))
    if captured > datetime.now(UTC) + timedelta(minutes=5):
        raise UploadError(422, "future_timestamp")
    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return Validated(
        UUID(value["server_id"]) if "server_id" in value else None,
        UUID(value["inventory_id"]),
        value["schema_version"],
        captured,
        canonical,
        hashlib.sha256(canonical).digest(),
        hashlib.sha256(raw).digest(),
        value.get("host"),
    )


def worker(pipe: Connection, raw: bytes, depth: int, nodes: int) -> None:
    try:
        resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CPU, (12, 12))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        result = validate(raw, depth, nodes)
        pipe.send(("ok", result))
    except UploadError as error:
        pipe.send(("error", error.status, error.reason))
    except (MemoryError, RecursionError):
        pipe.send(("error", 413, "parser_memory"))
    except Exception:
        pipe.send(("error", 422, "invalid_inventory"))
    finally:
        pipe.close()


async def parse(raw: bytes, settings: InventorySettings) -> Validated:
    if len(raw) > settings.max_bytes:
        raise UploadError(413, "payload_size")
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(
        target=worker, args=(child, raw, settings.max_depth, settings.max_nodes), daemon=True
    )
    process.start()
    child.close()
    try:
        async with asyncio.timeout(settings.parser_seconds):
            result = await asyncio.to_thread(parent.recv)
        if result[0] != "ok":
            raise UploadError(result[1], result[2])
        value = result[1]
        assert isinstance(value, Validated)
        return value
    except TimeoutError:
        raise UploadError(422, "parser_timeout") from None
    except (EOFError, OSError):
        raise UploadError(422, "parser_resource_limit") from None
    finally:
        if process.is_alive():
            process.kill()
        await asyncio.to_thread(process.join, 1)
        parent.close()
        process.close()
