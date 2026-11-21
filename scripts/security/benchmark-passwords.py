"""Local KDF baseline without accounts, secrets, database connections or lower cost settings."""

import asyncio
import json
import resource
import secrets
import statistics
import sys
import time
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cve_api.auth.passwords import Passwords
from cve_api.auth.settings import AuthSettings
from cve_common.config.settings import DatabaseSettings


async def benchmark() -> dict[str, object]:
    policy = AuthSettings(
        database=DatabaseSettings(
            host="cve-postgres",
            username="api_security",
            password_file=Path("/unopened"),
            ca_file=Path("/unopened"),
        ),
        origin="https://dashboard.example.test",
        keyring_file=Path("/unopened"),
        gateway_file=Path("/unopened"),
    )
    passwords = Passwords(policy)
    await passwords.initialize()
    value = secrets.token_urlsafe(32)
    encoded = await passwords.hash(value)
    durations = []
    for _ in range(8):
        started = time.monotonic()
        assert await passwords.verify(encoded, value)
        durations.append((time.monotonic() - started) * 1000)
    started = time.monotonic()
    assert all(await asyncio.gather(*(passwords.verify(encoded, value) for _ in range(4))))
    return {
        "memory_kib": policy.argon_memory,
        "iterations": policy.argon_iterations,
        "parallelism": policy.argon_parallelism,
        "max_concurrent_kdfs": policy.argon_concurrency,
        "median_verify_ms": statistics.median(durations),
        "four_verifications_ms": (time.monotonic() - started) * 1000,
        "process_peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    }


if __name__ == "__main__":
    print(json.dumps(asyncio.run(benchmark()), indent=2))
