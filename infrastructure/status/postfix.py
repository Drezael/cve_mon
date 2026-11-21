"""Fixed local read-only queue adapter. Never retains envelopes, IDs or message content."""

import json
import os
import select
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def aggregate(rows: list[dict[str, Any]], now: float) -> dict[str, int | float]:
    deferred = [r for r in rows if r.get("queue_name") == "deferred"]
    return {
        "queue_size": len(rows),
        "oldest_seconds": max(
            (
                max(0, now - float(r["arrival_time"]))
                for r in rows
                if isinstance(r.get("arrival_time"), (int, float))
            ),
            default=0,
        ),
        "deferred": len(deferred),
        "oldest_deferred_seconds": max(
            (
                max(0, now - float(r["arrival_time"]))
                for r in deferred
                if isinstance(r.get("arrival_time"), (int, float))
            ),
            default=0,
        ),
        "capped": int(len(rows) >= 10001),
    }


def sample() -> dict[str, int | float]:
    process = subprocess.Popen(
        ["postqueue", "-j"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )
    assert process.stdout is not None
    deadline = time.monotonic() + 0.8
    data = bytearray()
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                raise TimeoutError("queue sample timeout")
            chunk = os.read(process.stdout.fileno(), 65536)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > 8 * 1024 * 1024 or data.count(b"\n") > 10001:
                raise ValueError("queue sample capped")
        if process.wait(timeout=0.2) != 0:
            raise ValueError("queue unavailable")
        lines = data.splitlines()
        if any(len(line) > 65536 for line in lines):
            raise ValueError("queue row too large")
        return aggregate([json.loads(line) for line in lines], time.time())
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=1)
        process.stdout.close()


def main() -> None:
    folder = Path("/run/cve-status/postfix")
    if not folder.is_dir():
        return
    state = "healthy" if sys.argv[1:] == ["0"] else "unavailable"
    reason = "LOCAL_READINESS_CONFIRMED" if state == "healthy" else "LOCAL_NOT_READY"
    try:
        metrics = sample()
    except (OSError, ValueError, TimeoutError, subprocess.SubprocessError):
        metrics = {}
        if state == "healthy":
            state, reason = "unknown", "QUEUE_SAMPLE_UNAVAILABLE"
    value = {
        "schema_version": 1,
        "service_id": "postfix",
        "check_id": "readiness",
        "checked_at": datetime.now(UTC).isoformat(),
        "result": state,
        "duration_ms": 0,
        "reason_code": reason,
        "metrics": metrics,
    }
    temporary = folder / "observation.json.new"
    temporary.write_text(json.dumps(value))
    temporary.chmod(0o644)
    temporary.replace(folder / "observation.json")


if __name__ == "__main__":
    main()
