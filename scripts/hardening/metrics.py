"""Small deterministic summaries; retain samples and never hide errors or small populations."""

import math
from collections.abc import Sequence
from typing import Any


def distribution(samples: Sequence[float]) -> dict[str, Any]:
    if not samples or any(not math.isfinite(v) or v < 0 for v in samples):
        raise ValueError("Nonempty finite nonnegative samples required")
    values = sorted(samples)
    return {
        "count": len(values),
        "method": "nearest-rank; descriptive only for small samples",
        "p50_ms": values[math.ceil(len(values) * 0.50) - 1],
        "p95_ms": values[math.ceil(len(values) * 0.95) - 1],
        "p99_ms": values[math.ceil(len(values) * 0.99) - 1],
        "max_ms": values[-1],
        "samples_ms": list(samples),
    }
