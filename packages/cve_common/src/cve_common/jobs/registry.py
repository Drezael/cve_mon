"""Only code-registered callables; no import strings, eval or shell dispatch."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from pydantic import BaseModel

from cve_common.jobs.contracts import Payload

if TYPE_CHECKING:
    from cve_common.jobs.execution import ExecutionContext

Handler = Callable[["ExecutionContext", BaseModel], Awaitable[BaseModel | None]]


@dataclass(frozen=True)
class JobDefinition:
    name: str
    version: int
    payload_type: type[Payload]
    result_type: type[Payload] | None
    handler: Handler
    max_runtime: float = 300
    max_attempts: int = 3


class Registry:
    def __init__(self) -> None:
        self._definitions: dict[tuple[str, int], JobDefinition] = {}

    def register(self, definition: JobDefinition) -> None:
        key = (definition.name, definition.version)
        if (
            key in self._definitions
            or not callable(definition.handler)
            or not 0 < definition.max_runtime <= 3600
            or not 1 <= definition.max_attempts <= 100
        ):
            raise ValueError("Invalid or duplicate job definition")
        if definition.payload_type.model_config.get("extra") != "forbid":
            raise ValueError("Strict payload model required")
        self._definitions[key] = definition

    def get(self, name: str, version: int) -> JobDefinition:
        try:
            return self._definitions[(name, version)]
        except KeyError:
            raise ValueError("Unregistered job type/version") from None

    @property
    def names(self) -> list[str]:
        return sorted({name for name, _ in self._definitions})
