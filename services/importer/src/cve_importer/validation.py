"""Offline source validators and bounded, isolated JSON/archive processing."""

import asyncio
import csv
import hashlib
import json
import multiprocessing
import re
import resource
import stat
import time
import zipfile
from datetime import UTC, datetime
from functools import lru_cache
from importlib.resources import files
from multiprocessing.connection import Connection
from pathlib import Path, PurePosixPath
from typing import Any, overload

from jsonschema import FormatChecker
from jsonschema.validators import validator_for
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

from cve_importer.contracts import Configuration, ImportFailure

CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:+-]{0,255}$")
VERSIONS = {
    "5.0": "5.0",
    "5.1": "5.1.1",
    "5.1.0": "5.1.1",
    "5.1.1": "5.1.1",
    "5.2": "5.2.0",
    "5.2.0": "5.2.0",
}


def canonical(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


@overload
def date(value: str) -> datetime: ...


@overload
def date(value: None) -> None: ...


def date(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        # NVD v2 timestamps are UTC despite omitting the offset.
        return result.replace(tzinfo=UTC) if result.tzinfo is None else result
    except (ValueError, AttributeError):
        raise ImportFailure("invalid_timestamp") from None


def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ImportFailure("duplicate_json_key")
        result[key] = value
    return result


def constant(_value: str) -> Any:
    raise ImportFailure("nonfinite_json")


def decode(raw: bytes, maximum: int) -> Any:
    if len(raw) > maximum:
        raise ImportFailure("json_size")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError):
        raise ImportFailure("invalid_json") from None
    stack = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > 64 or nodes > 2000000:
            raise ImportFailure("json_structure_limit")
        if isinstance(item, dict):
            stack.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            if len(item) > 500000:
                raise ImportFailure("json_array_limit")
            stack.extend((v, depth + 1) for v in item)
        elif isinstance(item, str) and (
            len(item) > 1048576 or "\0" in item or any(0xD800 <= ord(c) <= 0xDFFF for c in item)
        ):
            raise ImportFailure("json_string_limit")
    return value


@lru_cache(maxsize=10)
def validator(name: str) -> Any:
    root = files("cve_importer").joinpath("data")
    schema = json.loads(root.joinpath(name + "/root.json").read_text())
    registry: Registry[Any] = Registry()
    for item in json.loads(root.joinpath("schemas.json").read_text()):
        if item["file"].startswith(name + "/"):
            content = json.loads(root.joinpath(item["file"]).read_text())
            resource_value = Resource.from_contents(content, default_specification=DRAFT7)
            for uri in {item.get("registry_uri"), content.get("$id"), content.get("id")} - {None}:
                registry = registry.with_resource(uri, resource_value)
    cls = validator_for(schema)
    cls.check_schema(schema)
    checker = FormatChecker()
    if name == "nvd":

        def nvd_time(value: Any) -> bool:
            if not isinstance(value, str):
                return True
            try:
                return (
                    bool(
                        re.fullmatch(
                            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})?",
                            value,
                        )
                    )
                    and date(value) is not None
                )
            except ImportFailure:
                return False

        checker.checks("date-time")(nvd_time)
    return cls(schema, registry=registry, format_checker=checker)


def check_schema(name: str, value: Any) -> None:
    try:
        if not validator(name).is_valid(value):
            raise ImportFailure("invalid_source_schema")
    except ImportFailure:
        raise
    except Exception:
        raise ImportFailure("source_schema_reference") from None


def identifier(value: Any) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value) or ".." in value:
        raise ImportFailure("invalid_identifier")
    return value


def record(
    source: str, value: Any, *, raw: bytes | None = None, filename: str | None = None
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ImportFailure("record_object_required")
    version = "1"
    state = "active"
    source_state = "active"
    published = modified = None
    aliases: list[str] = []
    if source == "cve_list":
        version = value.get("dataVersion", "")
        if version not in VERSIONS:
            raise ImportFailure("unsupported_cve_version")
        check_schema("cve-" + VERSIONS[version], value)
        metadata = value["cveMetadata"]
        external = metadata["cveId"]
        source_state = metadata["state"]
        state = {"PUBLISHED": "active", "REJECTED": "rejected"}.get(source_state, "reserved")
        published, modified = metadata.get("datePublished"), metadata.get("dateUpdated")
        aliases = [external]
        if filename and PurePosixPath(filename).stem != external:
            raise ImportFailure("record_filename_mismatch")
    elif source == "nvd":
        # Validate the record using the published API envelope and all offline dependencies.
        envelope = {
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "format": "NVD_CVE",
            "version": "2.0",
            "timestamp": "2026-01-01T00:00:00.000",
            "vulnerabilities": [{"cve": value}],
        }
        check_schema("nvd", envelope)
        external = value["id"]
        source_state = value.get("vulnStatus", "unknown")
        state = "rejected" if source_state == "Rejected" else "active"
        published, modified = value.get("published"), value.get("lastModified")
        aliases, version = [external], "2.0"
    elif source == "cisa_kev":
        if "vulnerabilities" in value:
            check_schema("kev", value)
            if value["count"] != len(value["vulnerabilities"]):
                raise ImportFailure("kev_count_mismatch")
            external, state = "catalog", "catalog"
            version = value["catalogVersion"]
            modified = value["dateReleased"]
        else:
            external = value.get("cveID")
            if not isinstance(external, str) or not CVE.fullmatch(external):
                raise ImportFailure("invalid_cve_id")
            aliases = [external]
            published = value.get("dateAdded")
    elif source == "ubuntu":
        check_schema("ubuntu", value)
        external = value.get("id")
        if not isinstance(external, str) or not (
            CVE.fullmatch(external) or re.fullmatch(r"(?:USN|LSN|SSN)-[0-9]+-[0-9]+", external)
        ):
            raise ImportFailure("invalid_ubuntu_id")
        if CVE.fullmatch(external):
            aliases.append(external)
        aliases.extend(
            v for v in value.get("cves_ids", []) if isinstance(v, str) and CVE.fullmatch(v)
        )
        for nested in value.get("cves", []):
            if isinstance(nested, dict) and CVE.fullmatch(str(nested.get("id", ""))):
                aliases.append(nested["id"])
        if "packages" in value and not isinstance(value["packages"], (list, dict)):
            raise ImportFailure("invalid_ubuntu_packages")
        published, modified = (
            value.get("published"),
            value.get("updated_at", value.get("published")),
        )
        source_state = value.get("status") or "active"
        state = "rejected" if source_state == "rejected" else "active"
    elif source == "osv":
        version = value.get("schema_version", "1.0.0")
        if not re.fullmatch(r"1\.[0-7](?:\.[0-9]+)?", version):
            raise ImportFailure("unsupported_osv_version")
        check_schema("osv", value)
        external = value["id"]
        aliases = [external, *value.get("aliases", [])]
        published, modified = value.get("published"), value["modified"]
        state = "withdrawn" if value.get("withdrawn") else "active"
        source_state = state
        if filename and PurePosixPath(filename).stem != external:
            raise ImportFailure("record_filename_mismatch")
    else:
        raise ImportFailure("unknown_source")
    external = identifier(external)
    if source in {"cve_list", "nvd"} and not CVE.fullmatch(external):
        raise ImportFailure("invalid_cve_id")
    return {
        "external_id": external,
        "original_json": value,
        "original_record_sha256": hashlib.sha256(raw).hexdigest() if raw is not None else None,
        "source_version": version,
        "source_status": str(source_state),
        "status": state,
        "published_at": date(published).isoformat() if published else None,
        "modified_at": date(modified).isoformat() if modified else None,
        "identifiers": sorted({identifier(a) for a in aliases}),
    }


def safe_member(info: zipfile.ZipInfo, cfg: Configuration) -> None:
    name = info.filename
    path = PurePosixPath(name)
    if (
        len(name) > 512
        or len(path.parts) > 32
        or not path.parts
        or name.startswith(("/", "\\"))
        or "\\" in name
        or ":" in path.parts[0]
        or ".." in path.parts
        or "\0" in name
        or stat.S_ISLNK(info.external_attr >> 16)
        or info.flag_bits & 1
    ):
        raise ImportFailure("unsafe_archive_member")
    if (
        info.file_size > cfg.max_unpacked
        or info.file_size / max(info.compress_size, 1) > cfg.max_ratio
    ):
        raise ImportFailure("archive_ratio_limit")


def archive_batch(path: Path, source: str, offset: int, cfg: Configuration) -> dict[str, Any]:
    result: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    total_bytes = 0
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > cfg.max_files or sum(e.file_size for e in entries) > cfg.max_unpacked:
            raise ImportFailure("archive_size_limit")
        for entry in entries:
            safe_member(entry, cfg)
        members = sorted(
            (
                e
                for e in entries
                if not e.is_dir()
                and e.filename.endswith(".json")
                and (source != "cve_list" or CVE.fullmatch(PurePosixPath(e.filename).stem))
            ),
            key=lambda e: e.filename,
        )
        if not members:
            raise ImportFailure("archive_has_no_records")
        cursor = offset
        while cursor < len(members) and len(result) + len(errors) < cfg.batch_size:
            entry = members[cursor]
            if entry.file_size > cfg.max_json:
                errors.append({"position": entry.filename[:512], "code": "json_size"})
            else:
                raw = archive.read(entry)
                try:
                    result.append(
                        {
                            **record(
                                source, decode(raw, cfg.max_json), raw=raw, filename=entry.filename
                            ),
                            "position": entry.filename,
                        }
                    )
                except ImportFailure as error:
                    errors.append({"position": entry.filename[:512], "code": str(error)})
                total_bytes += len(raw)
            cursor += 1
            if total_bytes >= 8388608:
                break
    return {
        "records": result,
        "errors": errors,
        "offset": cursor,
        "done": cursor == len(members),
        "total": len(members),
    }


def isolated_worker(pipe: Connection, action: str, path: str, arguments: dict[str, Any]) -> None:
    started = time.monotonic()
    try:
        resource.setrlimit(resource.RLIMIT_AS, (1073741824,) * 2)
        resource.setrlimit(resource.RLIMIT_CPU, (40, 40))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        cfg = Configuration.model_validate(arguments["configuration"])
        if action == "archive":
            result = archive_batch(Path(path), arguments["source"], arguments.get("offset", 0), cfg)
        else:
            with Path(path).open("rb") as handle:
                value = decode(handle.read(cfg.max_json + 1), cfg.max_json)
            if action == "record":
                result = record(arguments["source"], value, filename=arguments.get("filename"))
            elif action == "source":
                source = arguments["source"]
                if source == "nvd":
                    if value.get("version") != "2.0" or value.get("format") != "NVD_CVE":
                        raise ImportFailure("unsupported_nvd_version")
                    check_schema("nvd", {**value, "vulnerabilities": []})
                    entries = value.get("vulnerabilities")
                    if not isinstance(entries, list):
                        raise ImportFailure("invalid_pagination")
                    values = [v.get("cve") if isinstance(v, dict) else None for v in entries]
                elif source == "cisa_kev":
                    check_schema("kev", value)
                    entries = value["vulnerabilities"]
                    if value["count"] != len(entries):
                        raise ImportFailure("kev_count_mismatch")
                    if len({v["cveID"] for v in entries}) != len(entries):
                        raise ImportFailure("kev_duplicate_id")
                    values = [value, *entries]
                else:
                    values = value.get(arguments["key"])
                    if not isinstance(values, list):
                        raise ImportFailure("invalid_pagination")
                rows, errors = [], []
                for index, item in enumerate(values):
                    try:
                        rows.append(
                            {
                                **record(source, item),
                                "position": str(arguments.get("offset", 0) + index),
                            }
                        )
                    except ImportFailure as error:
                        errors.append(
                            {
                                "position": str(arguments.get("offset", 0) + index),
                                "code": str(error),
                            }
                        )
                result = {"value": value, "records": rows, "errors": errors}
            else:
                result = value
        pipe.send((True, result, (time.monotonic() - started) * 1000))
    except ImportFailure as error:
        pipe.send((False, str(error), 0))
    except Exception:
        pipe.send((False, "invalid_source_document", 0))
    finally:
        pipe.close()


async def isolated(
    action: str, path: Path, configuration: Configuration, **arguments: Any
) -> tuple[Any, float]:
    ctx = multiprocessing.get_context("spawn")
    parent, writer = ctx.Pipe(duplex=False)
    process = ctx.Process(
        target=isolated_worker,
        args=(
            writer,
            action,
            str(path),
            {"configuration": configuration.model_dump(), **arguments},
        ),
        daemon=True,
    )
    process.start()
    writer.close()
    try:
        async with asyncio.timeout(50):
            ok, result, milliseconds = await asyncio.to_thread(parent.recv)
        if not ok:
            raise ImportFailure(result)
        return result, milliseconds
    except (EOFError, OSError, TimeoutError):
        raise ImportFailure("parser_resource_limit") from None
    finally:
        if process.is_alive():
            process.kill()
        await asyncio.to_thread(process.join, 1)
        parent.close()
        process.close()


def archive_stream_worker(
    pipe: Connection, path: str, source: str, offset: int, configuration: dict[str, Any]
) -> None:
    """One indexed archive/validator process; bounded batches and explicit backpressure."""
    import tempfile
    from contextlib import ExitStack

    try:
        resource.setrlimit(resource.RLIMIT_AS, (1073741824,) * 2)
        resource.setrlimit(resource.RLIMIT_CPU, (3000, 3000))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        cfg = Configuration.model_validate(configuration)
        with ExitStack() as stack:
            archive = stack.enter_context(zipfile.ZipFile(path))
            for depth in range(2):
                entries = archive.infolist()
                if (
                    len(entries) > cfg.max_files
                    or sum(e.file_size for e in entries) > cfg.max_unpacked
                ):
                    raise ImportFailure("archive_size_limit")
                if len({e.filename for e in entries}) != len(entries):
                    raise ImportFailure("archive_duplicate_member")
                for entry in entries:
                    safe_member(entry, cfg)
                nested = [e for e in entries if not e.is_dir() and e.filename.endswith(".zip")]
                json_entries = [
                    e for e in entries if not e.is_dir() and e.filename.endswith(".json")
                ]
                if source == "cve_list" and len(nested) == 1 and not json_entries and depth == 0:
                    if nested[0].file_size > cfg.max_download:
                        raise ImportFailure("nested_archive_limit")
                    occupied = sum(
                        p.stat().st_size for p in Path(path).parent.parent.rglob("*") if p.is_file()
                    )
                    if occupied + nested[0].file_size > cfg.scratch_limit:
                        raise ImportFailure("scratch_quota")
                    temporary = stack.enter_context(
                        tempfile.NamedTemporaryFile(dir=Path(path).parent)
                    )
                    with archive.open(nested[0]) as handle:
                        total = 0
                        while chunk := handle.read(262144):
                            total += len(chunk)
                            if total > cfg.max_download:
                                raise ImportFailure("nested_archive_limit")
                            temporary.write(chunk)
                    temporary.seek(0)
                    archive = stack.enter_context(zipfile.ZipFile(temporary))
                    continue
                break
            members = sorted(
                (
                    e
                    for e in archive.infolist()
                    if not e.is_dir()
                    and e.filename.endswith(".json")
                    and (source != "cve_list" or CVE.fullmatch(PurePosixPath(e.filename).stem))
                ),
                key=lambda e: e.filename,
            )
            if len({PurePosixPath(e.filename).stem for e in members}) != len(members):
                raise ImportFailure("archive_duplicate_identity")
            if not members:
                raise ImportFailure("archive_has_no_records")
            if offset < 0 or offset > len(members):
                raise ImportFailure("archive_checkpoint_invalid")
            while True:
                started = time.monotonic()
                rows: list[dict[str, Any]] = []
                errors: list[dict[str, str]] = []
                size = 0
                while offset < len(members) and len(rows) + len(errors) < cfg.batch_size:
                    entry = members[offset]
                    if entry.file_size > cfg.max_json:
                        errors.append({"position": entry.filename[:512], "code": "json_size"})
                    else:
                        raw = archive.read(entry)
                        try:
                            rows.append(
                                {
                                    **record(
                                        source,
                                        decode(raw, cfg.max_json),
                                        raw=raw,
                                        filename=entry.filename,
                                    ),
                                    "position": entry.filename,
                                }
                            )
                        except ImportFailure as e:
                            errors.append({"position": entry.filename[:512], "code": str(e)})
                        size += len(raw)
                    offset += 1
                    if size >= 8388608:
                        break
                done = offset == len(members)
                pipe.send(
                    (
                        True,
                        {
                            "records": rows,
                            "errors": errors,
                            "offset": offset,
                            "done": done,
                            "total": len(members),
                        },
                        (time.monotonic() - started) * 1000,
                    )
                )
                if done or pipe.recv() != "next":
                    break
    except ImportFailure as e:
        pipe.send((False, str(e), 0))
    except Exception:
        pipe.send((False, "invalid_archive", 0))
    finally:
        pipe.close()


async def archive_stream(path: Path, source: str, offset: int, configuration: Configuration) -> Any:
    ctx = multiprocessing.get_context("spawn")
    parent, writer = ctx.Pipe()
    process = ctx.Process(
        target=archive_stream_worker,
        args=(writer, str(path), source, offset, configuration.model_dump()),
        daemon=True,
    )
    process.start()
    writer.close()
    try:
        while True:
            # Large valid batches must not force a restart at the same checkpoint.
            async with asyncio.timeout(180):
                ok, result, milliseconds = await asyncio.to_thread(parent.recv)
            if not ok:
                raise ImportFailure(result)
            yield result, milliseconds
            if result["done"]:
                break
            parent.send("next")
    except (EOFError, OSError, TimeoutError):
        raise ImportFailure("parser_resource_limit") from None
    finally:
        if process.is_alive():
            process.kill()
        await asyncio.to_thread(process.join, 1)
        parent.close()
        process.close()


def index_stream_worker(
    pipe: Connection, path: str, offset: int, configuration: dict[str, Any], cutoff: str, upper: str
) -> None:
    """Single-pass OSV CSV with bounded fields, parser isolation and commit backpressure."""
    try:
        resource.setrlimit(resource.RLIMIT_AS, (268435456,) * 2)
        resource.setrlimit(resource.RLIMIT_CPU, (3000, 3000))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        cfg = Configuration.model_validate(configuration)
        csv.field_size_limit(1024)
        low, high = date(cutoff), date(upper)
        previous = None
        selected: list[tuple[int, str]] = []
        following = offset
        with Path(path).open(encoding="utf-8", newline="") as handle:
            for position, row in enumerate(csv.reader(handle)):
                if position >= cfg.max_files or len(row) != 2:
                    raise ImportFailure("invalid_osv_index")
                modified = date(row[0])
                external = identifier(row[1])
                if modified is None or previous is not None and modified > previous:
                    raise ImportFailure("osv_index_order")
                previous = modified
                if modified < low:
                    break
                following = position + 1
                if position >= offset and modified <= high:
                    selected.append((position, external))
                if len(selected) >= cfg.batch_size:
                    pipe.send((True, {"selected": selected, "offset": following, "done": False}, 0))
                    if pipe.recv() != "next":
                        return
                    selected = []
        pipe.send((True, {"selected": selected, "offset": following, "done": True}, 0))
    except ImportFailure as error:
        pipe.send((False, str(error), 0))
    except Exception:
        pipe.send((False, "invalid_osv_index", 0))
    finally:
        pipe.close()


async def index_stream(
    path: Path, offset: int, configuration: Configuration, cutoff: datetime, upper: datetime
) -> Any:
    ctx = multiprocessing.get_context("spawn")
    parent, writer = ctx.Pipe()
    process = ctx.Process(
        target=index_stream_worker,
        args=(
            writer,
            str(path),
            offset,
            configuration.model_dump(),
            cutoff.isoformat(),
            upper.isoformat(),
        ),
        daemon=True,
    )
    process.start()
    writer.close()
    try:
        while True:
            async with asyncio.timeout(60):
                ok, result, milliseconds = await asyncio.to_thread(parent.recv)
            if not ok:
                raise ImportFailure(result)
            yield result, milliseconds
            if result["done"]:
                break
            parent.send("next")
    except (EOFError, OSError, TimeoutError):
        raise ImportFailure("parser_resource_limit") from None
    finally:
        if process.is_alive():
            process.kill()
        await asyncio.to_thread(process.join, 1)
        parent.close()
        process.close()
