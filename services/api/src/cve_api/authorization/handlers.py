"""Safe conflicts for invariant/version failures, including existing MFA/self-recovery flows."""

import json

from cve_common.http.responses import problem
from fastapi import FastAPI, Request
from sqlalchemy.exc import IntegrityError
from starlette.responses import JSONResponse, Response

from cve_api.auth.sessions import SESSION_COOKIE

from .administration import Administration
from .errors import Denied


def install_authorization_handlers(app: FastAPI) -> None:
    @app.exception_handler(Denied)
    async def denied(_request: Request, error: Denied) -> Response:
        if error.status in {412, 428}:
            # Reuse Phase-0 error codes while making HTTP preconditions explicit.
            response = problem(409 if error.status == 412 else 400)
            payload = json.loads(bytes(response.body))
            payload["status"] = error.status
            payload["title"] = (
                "Precondition failed" if error.status == 412 else "Precondition required"
            )
            return JSONResponse(
                payload,
                status_code=error.status,
                headers={
                    k: v
                    for k, v in response.headers.items()
                    if k not in {"content-length", "content-type"}
                },
                media_type="application/problem+json",
            )
        return problem(error.status)

    @app.exception_handler(IntegrityError)
    async def conflict(request: Request, error: IntegrityError) -> Response:
        constraint = getattr(getattr(error.orig, "diag", None), "constraint_name", None)
        if constraint == "usable_administrator_required":
            auth = getattr(request.app.state, "auth", None)
            if auth:
                await Administration(auth).log_denial(
                    request.cookies.get(SESSION_COOKIE), "last_admin"
                )
        return problem(409)
