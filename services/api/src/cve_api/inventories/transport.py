"Byte-counted HTTP reads and one bounded multipart file; no filename-based persistence."

import asyncio
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import UUID

from fastapi import Request
from pydantic import ValidationError
from starlette.datastructures import UploadFile
from starlette.formparsers import MultiPartException, MultiPartParser

from cve_api.servers.schemas import Metadata

from .errors import UploadError
from .settings import InventorySettings


def media(request: Request, expected: str) -> None:
    encoding = request.headers.getlist("content-encoding")
    if encoding and encoding != ["identity"]:
        raise UploadError(415, "compressed_upload")
    content = request.headers.getlist("content-type")
    if len(content) != 1 or content[0].split(";")[0].strip().lower() != expected:
        raise UploadError(415, "media_type")


def idempotency(request: Request) -> str | None:
    values = request.headers.getlist("idempotency-key")
    if len(values) > 1 or (values and not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", values[0])):
        raise UploadError(400, "idempotency_key")
    return values[0] if values else None


async def read(request: Request, maximum: int) -> bytes:
    lengths = request.headers.getlist("content-length")
    if len(lengths) > 1 or (lengths and not lengths[0].isdigit()):
        raise UploadError(400, "content_length")
    if lengths and int(lengths[0]) > maximum:
        raise UploadError(413, "request_size")
    import io

    stream = io.BytesIO()
    size = 0
    try:
        async with asyncio.timeout(10):
            async for chunk in request.stream():
                size += len(chunk)
                if size > maximum:
                    raise UploadError(413, "request_size")
                stream.write(chunk)
    except TimeoutError:
        raise UploadError(400, "body_timeout") from None
    if lengths and size != int(lengths[0]):
        raise UploadError(400, "content_length")
    return stream.getvalue()


class BoundedMultipart(MultiPartParser):
    def __init__(self, request: Request, maximum: int) -> None:
        super().__init__(
            request.headers, request.stream(), max_files=1, max_fields=2, max_part_size=16384
        )
        self.maximum = maximum
        self.spool_max_size = maximum
        self.file_size = 0

    def on_part_begin(self) -> None:
        super().on_part_begin()
        self.file_size = 0

    def on_part_data(self, data: bytes, start: int, end: int) -> None:
        if self._current_part.file is not None:
            self.file_size += end - start
            if self.file_size > self.maximum:
                raise MultiPartException("inventory_file_size")
        super().on_part_data(data, start, end)


@asynccontextmanager
async def multipart(
    request: Request, settings: InventorySettings
) -> AsyncIterator[tuple[UUID | None, bytes, Metadata | None]]:
    media(request, "multipart/form-data")
    raw = await read(request, settings.max_request_bytes)

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": raw, "more_body": False}

    bounded = Request(request.scope, receive)
    try:
        form = await BoundedMultipart(bounded, settings.max_bytes).parse()
    except MultiPartException as error:
        raise UploadError(
            413 if error.message == "inventory_file_size" else 400, "multipart_structure"
        ) from None
    try:
        if len(form.multi_items()) != len(set(form)) or set(form) not in (
            {"file"},
            {"server_id", "file"},
            {"file", "server_metadata"},
            {"server_id", "file", "server_metadata"},
        ):
            raise UploadError(400, "multipart_fields")
        file = form["file"]
        server = form.get("server_id")
        if not isinstance(file, UploadFile) or (server is not None and not isinstance(server, str)):
            raise UploadError(400, "multipart_fields")
        if (
            not file.filename
            or len(file.filename) > 128
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.json", file.filename, re.IGNORECASE)
        ):
            raise UploadError(415, "file_type")
        if (file.content_type or "").split(";")[0].lower() != "application/json":
            raise UploadError(415, "file_type")
        try:
            sid = UUID(server) if server else None
        except ValueError:
            raise UploadError(422, "server_id") from None
        content = await file.read(settings.max_bytes + 1)
        if len(content) > settings.max_bytes:
            raise UploadError(413, "file_size")
        metadata = None
        if "server_metadata" in form:
            encoded = form["server_metadata"]
            if not isinstance(encoded, str) or len(encoded.encode("utf-8")) > 16384:
                raise UploadError(422, "server_metadata")
            try:
                metadata = Metadata.model_validate_json(encoded)
            except ValidationError:
                raise UploadError(422, "server_metadata") from None
        yield sid, content, metadata
    finally:
        await form.close()
