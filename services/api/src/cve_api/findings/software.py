"""Resolve only the already-authorized findings, in one batch and from their historical inputs."""

from typing import Any
from uuid import UUID

from cve_common.database.queries import rows
from sqlalchemy.ext.asyncio import AsyncSession


async def attach_software(session: AsyncSession, findings: list[dict[str, Any]]) -> None:
    if not findings:
        return
    values = await rows(
        session,
        "SELECT result_id,component_id,name,version,location,container_id,container_name,"
        "origin,target,status FROM matching.component_software WHERE result_id=ANY(:ids) "
        "ORDER BY result_id,position",
        ids=list({UUID(str(f["latest_matching_result_id"])) for f in findings}),
    )
    by_result: dict[Any, list[dict[str, Any]]] = {}
    seen = set()
    for row in values:
        key = (row["result_id"], row["component_id"], row["location"], row["status"])
        if key in seen:
            continue
        seen.add(key)
        by_result.setdefault(str(row["result_id"]), []).append(
            {k: v for k, v in row.items() if k != "result_id"}
        )
    for finding in findings:
        finding["affected_software"] = by_result.get(str(finding["latest_matching_result_id"]), [])
