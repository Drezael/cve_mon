"""Transactional connection audit with an explicit non-secret metadata allowlist."""

import json
from typing import Any
from uuid import UUID

from cve_api.auth.repository import execute


async def audit(
    s: Any, actor: UUID, server: UUID, action: str, version: int, fingerprint: str | None = None
) -> None:
    metadata: dict[str, Any] = {"profile_version": version}
    if fingerprint is not None:
        metadata["fingerprint"] = fingerprint
    await execute(
        s,
        "INSERT INTO security.audit_log(actor_user_id,action,object_type,"
        "object_id,outcome,metadata) VALUES(:actor,:action,'ansible_profile',"
        ":server,'success',CAST(:metadata AS jsonb))",
        actor=actor,
        action="ansible." + action,
        server=str(server),
        metadata=json.dumps(metadata),
    )
