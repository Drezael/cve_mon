"""Bounded exponential equal jitter; authoritative retry timestamps come from PostgreSQL."""

import random
from dataclasses import dataclass


@dataclass(frozen=True)
class RetryPolicy:
    base: float = 5
    cap: float = 3600
    max_attempts: int = 3

    def __post_init__(self) -> None:
        if not 0.1 <= self.base <= self.cap <= 86400 or not 1 <= self.max_attempts <= 100:
            raise ValueError("Bounded retry policy required")

    def delay(self, attempt: int, *, jitter: float | None = None) -> float:
        if not 1 <= attempt <= 100:
            raise ValueError("Invalid attempt")
        fraction = random.random() if jitter is None else jitter
        if not 0 <= fraction <= 1:
            raise ValueError("Invalid jitter")
        return float(min(self.cap, self.base * 2 ** min(attempt - 1, 20)) * (0.8 + 0.2 * fraction))
