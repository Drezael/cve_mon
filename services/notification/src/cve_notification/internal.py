"""Narrow authenticated service API, isolated from the public browser ingress."""

import asyncio
from typing import Any, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from cve_common.database.transactions import transaction
from cve_common.jobs.contracts import Payload
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy import text

from cve_notification.contracts import Settings
from cve_notification.control import authorized as control_authorized
from cve_notification.control import install as install_control
from cve_notification.files import proof
from cve_notification.orchestration import service_authorized
from cve_notification.repository import enqueue, one


class Command(Payload):
    run_id: UUID
    request_id: UUID


def install(app: FastAPI, config: Settings) -> None:
    install_control(app)

    @app.middleware("http")
    async def boundary(request: Request, call_next: Any) -> Any:
        if request.url.path.startswith("/internal/"):
            if not proof(config.guard_proof_file):
                return JSONResponse({"status": "unavailable"}, status_code=503)
            allowed = (
                control_authorized(
                    config.configuration_dir,
                    request.url.path,
                    request.headers.get("X-CVE-Orchestrator", ""),
                )
                if request.url.path.startswith("/internal/v1/orchestration/")
                else service_authorized(
                    config.configuration_dir, request.headers.get("X-CVE-Service", "")
                )
            )
            if not allowed:
                return JSONResponse({"status": "unauthorized"}, status_code=401)
            chunks = []
            size = 0
            try:
                async with asyncio.timeout(5):
                    async for chunk in request.stream():
                        size += len(chunk)
                        if size > 2048:
                            return JSONResponse({"status": "too_large"}, status_code=413)
                        chunks.append(chunk)
            except TimeoutError:
                return JSONResponse({"status": "request_timeout"}, status_code=400)
            request._body = b"".join(chunks)
        return await call_next(request)

    @app.post("/internal/v1/notifications/workflows/{action}")
    async def workflow(
        action: Literal["claim", "execute", "complete", "fail"], request: Request
    ) -> Any:
        try:
            command = Command.model_validate_json(await request.body())
        except ValidationError:
            return JSONResponse({"status": "invalid_command"}, status_code=422)
        dispatch = request.app.state.dispatch
        if action == "claim":
            return await dispatch.claim(command.run_id, command.request_id)
        if action == "execute":
            from cve_notification.orchestration import runtime

            dispatch.sender = runtime(config.configuration_dir)["sender"]
            return await dispatch.execute(command.run_id, command.request_id)
        async with transaction(dispatch.database) as s:
            run = await one(
                s,
                (
                    "SELECT state FROM automation.notification_workflow_runs WHERE id="
                    ":id AND request_id=:request"
                ),
                id=command.run_id,
                request=command.request_id,
            )
            if action == "fail" and run and run["state"] in {"requested", "executing"}:
                await s.execute(
                    text(
                        "UPDATE automation.notification_workflow_runs SET "
                        "state='failed',completed_at=clock_timestamp() "
                        "WHERE id=:id AND request_id=:request"
                    ),
                    {"id": command.run_id, "request": command.request_id},
                )
                return {"state": "failed"}
        return {"state": run["state"] if run else "unknown"}

    @app.post("/internal/v1/notifications/ticks/{kind}")
    async def tick(
        kind: Literal["digest", "escalation", "exception", "reconciliation", "health"],
        request: Request,
    ) -> Any:
        if (await request.body()).strip() not in {b"", b"{}"}:
            return JSONResponse({"status": "invalid_command"}, status_code=422)
        async with transaction(request.app.state.dispatch.database) as s:
            slot = await one(s, "SELECT floor(extract(epoch FROM clock_timestamp())/60) AS slot")
            assert slot
            reference = uuid5(NAMESPACE_URL, f"cve-notification:{kind}:{slot['slot']}")
            run = await one(
                s,
                "INSERT INTO automation.notification_workflow_runs(workflow,workflow_version,"
                "request_id,state,expires_at,completed_at) VALUES(:kind,1,:reference,'completed',"
                "clock_timestamp()+interval '5 minutes',clock_timestamp()) "
                "ON CONFLICT(request_id) DO NOTHING RETURNING id",
                kind=kind,
                reference=reference,
            )
            if run:
                await enqueue(s, "maintenance", {}, f"n8n-{kind}:{slot['slot']}", run["id"])
        return {"scheduled": True}
