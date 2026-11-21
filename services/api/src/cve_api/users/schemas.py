"""Explicit user-field allowlists, bounded pagination and optimistic mutation versions."""

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class Version(Input):
    version: int = Field(ge=1, strict=True)
    reason: str = Field(min_length=1, max_length=256)


class UserCreate(Input):
    username: str = Field(min_length=1, max_length=128)
    email: str = Field(min_length=3, max_length=254, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
    display_name: str = Field(min_length=1, max_length=128)

    @field_validator("username", "display_name")
    @classmethod
    def safe_text(cls, value: str) -> str:
        if not value.strip() or any(ord(c) < 32 for c in value):
            raise ValueError("Invalid identity text")
        return value


class UserPatch(Version):
    display_name: str | None = Field(default=None, min_length=1, max_length=128)
    email: str | None = Field(
        default=None, min_length=3, max_length=254, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$"
    )

    @field_validator("display_name")
    @classmethod
    def safe_display_name(cls, value: str | None) -> str | None:
        return UserCreate.safe_text(value) if value is not None else None


class AssignRoles(Version):
    role_ids: list[UUID] = Field(max_length=20)
