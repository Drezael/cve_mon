"""Authenticated, bounded requests to the project-local deployment control socket."""

import asyncio
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any


async def command(base: Path, value: dict[str, Any]) -> dict[str, Any]:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    signature = hmac.new((base / "control.token").read_bytes(), raw, hashlib.sha256).hexdigest()
    value = value | {"signature": signature}
    reader, writer = await asyncio.wait_for(
        asyncio.open_unix_connection(str(base / "control.sock")), 5
    )
    try:
        writer.write(json.dumps(value).encode() + b"\n")
        await writer.drain()
        response = await asyncio.wait_for(reader.readline(), 60)
        result: dict[str, Any] = json.loads(response)
        return result
    finally:
        writer.close()
        await writer.wait_closed()
