"""Task-local IDs; accepts Nginx's 32 hex digits or RFC UUID, never arbitrary text."""

from contextvars import ContextVar
from uuid import UUID, uuid4

request_id: ContextVar[str | None] = ContextVar("request_id", default=None)
correlation_id: ContextVar[str | None] = ContextVar("correlation_id", default=None)


def valid_id(value: str | None) -> str:
    try:
        if value is None or len(value) not in (32, 36):
            raise ValueError
        return str(UUID(value))
    except ValueError:
        return str(uuid4())
