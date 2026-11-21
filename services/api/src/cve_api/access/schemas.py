"""An ACL replacement has its own revision and no server/group metadata fields."""

from typing import Literal
from uuid import UUID

from pydantic import Field

from cve_api.users.schemas import Input


class Grant(Input):
    user_id: UUID
    rights: list[Literal["view", "inventory_upload", "findings_read", "findings_manage"]] = Field(
        min_length=1, max_length=4
    )


class ReplaceAccess(Input):
    version: int = Field(ge=0, strict=True)
    reason: str = Field(min_length=1, max_length=256)
    grants: list[Grant] = Field(max_length=100)
