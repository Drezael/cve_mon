"""Bounded process-local API aggregates: no paths, actors, payloads or token labels."""

import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Window:
    buckets: deque[list[float]] = field(default_factory=lambda: deque(maxlen=60))

    def record(self, status: int, elapsed_ms: float, now: float) -> None:
        second = int(now)
        if not self.buckets or self.buckets[-1][0] != second:
            self.buckets.append([float(second), 0.0, 0.0, 0.0])
        bucket = self.buckets[-1]
        bucket[1] += 1
        bucket[2] += int(status >= 500)
        bucket[3] += max(0.0, min(elapsed_ms, 60000.0))

    def snapshot(self, now: float) -> dict[str, float | int | None]:
        while self.buckets and self.buckets[0][0] < int(now) - 59:
            self.buckets.popleft()
        count = int(sum(b[1] for b in self.buckets))
        errors = int(sum(b[2] for b in self.buckets))
        return {
            "api_requests": count,
            "api_errors": errors,
            "error_rate": errors / count if count else None,
            "api_mean_latency_ms": sum(b[3] for b in self.buckets) / count if count else None,
        }


WINDOW = Window()


def snapshot() -> dict[str, float | int | None]:
    values = WINDOW.snapshot(time.monotonic())
    values["collector_cpu_seconds"] = time.process_time()
    # Linux reports own-process resident pages. This is not host/container/cluster memory.
    try:
        import os

        raw = Path("/proc/self/statm").read_text()[:128]
        resident = int(raw.split()[1])
        values["collector_rss_bytes"] = resident * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError):
        values["collector_rss_bytes"] = None
    return values
