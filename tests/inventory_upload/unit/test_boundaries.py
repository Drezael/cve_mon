"Actual streaming byte counts, parser process termination and multipart cleanup."

import json
import multiprocessing
from pathlib import Path
from tempfile import SpooledTemporaryFile
from typing import Any

import httpx
import pytest
from cve_api.inventories import parser
from cve_api.inventories.errors import UploadError
from cve_api.inventories.settings import InventorySettings
from cve_api.inventories.transport import multipart, read
from cve_common.config.settings import DatabaseSettings
from starlette.requests import Request

from .test_parser import valid


def settings() -> InventorySettings:
    return InventorySettings(
        database=DatabaseSettings(
            host="cve-postgres",
            username="api_ingest",
            password_file=Path("/unopened"),
            ca_file=Path("/unopened"),
        ),
        origin="https://inventory.example.test",
        gateway_file=Path("/unopened"),
        token_key_file=Path("/unopened"),
        client_ca_file=Path("/unopened"),
        client_crl_file=Path("/unopened"),
        max_bytes=1024,
        max_request_bytes=2048,
    )


def request(body: bytes, headers: list[tuple[bytes, bytes]] | None = None) -> Request:
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {"type": "http", "method": "POST", "path": "/", "headers": headers or []}, receive
    )


async def test_actual_chunk_bytes_are_bounded_without_content_length() -> None:
    with pytest.raises(UploadError) as e:
        await read(request(b"x" * 1025), 1024)
    assert e.value.status == 413
    with pytest.raises(UploadError) as e:
        await read(request(b"x" * 1025, [(b"content-length", b"1")]), 1024)
    assert e.value.status == 413
    with pytest.raises(UploadError):
        await read(request(b"xx", [(b"content-length", b"3")]), 1024)


async def test_parser_timeout_reaps_its_child_process() -> None:
    before = {p.pid for p in multiprocessing.active_children()}
    limits = settings().model_copy(update={"max_bytes": 10485760, "parser_seconds": 0.001})
    with pytest.raises(UploadError) as e:
        await parser.parse(json.dumps(valid()).encode(), limits)
    assert e.value.reason == "parser_timeout"
    assert not {p.pid for p in multiprocessing.active_children()} - before


async def test_failed_multipart_closes_spooled_files(monkeypatch: pytest.MonkeyPatch) -> None:
    import starlette.formparsers as formparsers

    opened = []
    original = SpooledTemporaryFile

    def tracked(*args: Any, **kwargs: Any) -> Any:
        value = original(*args, **kwargs)
        opened.append(value)
        return value

    monkeypatch.setattr(formparsers, "SpooledTemporaryFile", tracked)
    encoded = httpx.Request(
        "POST",
        "https://example.test",
        data={"server_id": "11111111-1111-4111-8111-111111111111"},
        files={"file": ("bad.py", b"{}", "application/json")},
    )
    body = encoded.read()
    content = encoded.headers["content-type"].encode()
    with pytest.raises(UploadError):
        async with multipart(request(body, [(b"content-type", content)]), settings()):
            raise AssertionError("unreachable")
    assert opened and all(f.closed for f in opened)
