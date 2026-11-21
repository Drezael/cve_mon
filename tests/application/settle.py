"""A manually drained test queue can concurrently be owned by a real worker process."""

from typing import Any


def pending(browser: Any, names: list[str]) -> bool:
    with browser.lab.owner() as connection:
        row = connection.execute(
            "SELECT EXISTS(SELECT 1 FROM automation.jobs WHERE job_type=ANY(%s) "
            "AND (status='running' OR (status IN ('queued','retry_pending') "
            "AND scheduled_at<=clock_timestamp()))) AS active",
            (names,),
        ).fetchone()
        return bool(row["active"])
