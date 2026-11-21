"""Explicit memberships and bounded relative or full ordering commands."""

from uuid import UUID

from pydantic import Field, field_validator, model_validator

from cve_api.servers.schemas import Strict, clean


class GroupCreate(Strict):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=2000)

    @field_validator("name", "description", mode="before")
    @classmethod
    def text(cls, value: str | None) -> str | None:
        return clean(value) if value is not None else None


class Ordering(Strict):
    ids: list[UUID] | None = Field(default=None, max_length=100)
    move_id: UUID | None = None
    before_id: UUID | None = None

    @model_validator(mode="after")
    def valid_command(self) -> "Ordering":
        if self.ids is not None:
            if (
                self.move_id is not None
                or self.before_id is not None
                or len(self.ids) != len(set(self.ids))
            ):
                raise ValueError("Unique full order or relative move required")
        elif self.move_id is None or self.move_id == self.before_id:
            raise ValueError("Relative move requires a distinct target")
        return self
