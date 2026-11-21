"""Source/type/version bindings are code-registered and separately checked by PostgreSQL."""

from dataclasses import dataclass

from cve_common.jobs.contracts import Payload


@dataclass(frozen=True)
class EventDefinition:
    name: str
    version: int
    source: str
    payload_type: type[Payload]


class EventRegistry:
    def __init__(self) -> None:
        self._definitions: dict[tuple[str, int], EventDefinition] = {}

    def register(self, definition: EventDefinition) -> None:
        key = (definition.name, definition.version)
        if (
            key in self._definitions
            or definition.payload_type.model_config.get("extra") != "forbid"
        ):
            raise ValueError("Strict, unique event definition required")
        self._definitions[key] = definition

    def validate(self, name: str, version: int, source: str, payload: dict[str, object]) -> None:
        definition = self._definitions.get((name, version))
        if definition is None or definition.source != source:
            raise ValueError("Unregistered event/source/version")
        definition.payload_type.model_validate(payload)
