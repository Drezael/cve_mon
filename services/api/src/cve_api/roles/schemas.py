"""No dynamic role properties, wildcard rights or system-role metadata."""

from pydantic import Field

from cve_api.users.schemas import Input, Version


class RoleCreate(Input):
    code: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=512)
    permissions: list[str] = Field(max_length=40)


class RolePatch(Version):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=512)
    permissions: list[str] = Field(max_length=40)
