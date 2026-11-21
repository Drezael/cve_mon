"""Bounded administrative fields only; technical inventory and identity are excluded."""

import unicodedata
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Criticality = Literal["low", "medium", "high", "critical"]
Exposure = Literal["internal", "restricted", "internet_exposed", "unknown"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, hide_input_in_errors=True)


def clean(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Text required")
    value = unicodedata.normalize("NFKC", value.strip())
    if not value or any(unicodedata.category(c).startswith("C") or c in "<>" for c in value):
        raise ValueError("Printable administrative text required")
    return value


class Metadata(Strict):
    display_name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=2000)
    environment: str | None = Field(default=None, min_length=1, max_length=64)
    criticality: Criticality = "medium"
    exposure: Exposure = "unknown"

    @field_validator("display_name", "description", "environment", mode="before")
    @classmethod
    def safe_text(cls, value: str | None) -> str | None:
        return clean(value) if value is not None else None


class ServerCreate(Metadata):
    request_id: UUID


class ServerPatch(Strict):
    display_name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=2000)
    environment: str | None = Field(default=None, min_length=1, max_length=64)
    criticality: Criticality | None = None
    exposure: Exposure | None = None

    @field_validator("display_name", "description", "environment", mode="before")
    @classmethod
    def safe_text(cls, value: str | None) -> str | None:
        return clean(value) if value is not None else None

    @model_validator(mode="after")
    def fields_present(self) -> "ServerPatch":
        if not self.model_fields_set or any(
            getattr(self, field) is None
            for field in self.model_fields_set & {"display_name", "criticality", "exposure"}
        ):
            raise ValueError("At least one allowed non-null update required")
        return self


class Lifecycle(Strict):
    reason: str = Field(min_length=1, max_length=256)

    @field_validator("reason", mode="before")
    @classmethod
    def safe_reason(cls, value: str) -> str:
        return clean(value)
