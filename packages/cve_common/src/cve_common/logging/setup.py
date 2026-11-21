"""Allowlisted JSON events: arbitrary logger messages/tracebacks never reach stdout."""

import datetime
import json
import logging
import re
import sys
from typing import Any

from cve_common.logging.correlation import correlation_id, request_id
from cve_common.logging.redaction import redact

EVENTS = frozenset(
    {
        "startup",
        "shutdown",
        "request",
        "internal_error",
        "dependency_unavailable",
        "worker_started",
        "worker_stopped",
        "job_finished",
        "job_failed",
        "delivery_finished",
        "worker_unavailable",
    }
)


class JSONFormatter(logging.Formatter):
    def __init__(self, service: str) -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        data: dict[str, Any] = {
            "time": datetime.datetime.now(datetime.UTC).isoformat(),
            "level": record.levelname,
            "service": self.service,
            "logger": record.name
            if re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", record.name)
            else "external",
            "event": record.msg
            if isinstance(record.msg, str) and record.msg in EVENTS
            else "diagnostic",
            "request_id": request_id.get(),
            "correlation_id": correlation_id.get(),
        }
        if record.exc_info and record.exc_info[0]:
            data["error_class"] = record.exc_info[0].__name__
        for key in ("error_code", "diagnostic_code", "error_class"):
            value = getattr(record, key, None)
            if isinstance(value, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", value):
                data[key] = value
        for key in ("status", "duration_ms"):
            value = getattr(record, key, None)
            if isinstance(value, (int, float)):
                data[key] = value
        from uuid import UUID

        for key in ("job_id", "event_id", "worker_id", "attempt_id"):
            value = getattr(record, key, None)
            try:
                if value is not None:
                    data[key] = str(UUID(str(value)))
            except ValueError:
                pass
        return json.dumps(redact(data), allow_nan=False)


def configure_logging(service: str, level: str) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter(service))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "sqlalchemy", "httpx", "httpcore"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = True
