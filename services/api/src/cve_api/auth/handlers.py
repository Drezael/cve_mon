"""Fail closed with dependency errors and aggregate validation counters, never SQL details."""

import logging

from cve_common.database.transactions import transaction
from cve_common.http.responses import problem
from fastapi import FastAPI, Request
from sqlalchemy.exc import SQLAlchemyError
from starlette.responses import Response

from .errors import AuthError
from .repository import execute


def install_auth_handlers(app: FastAPI) -> None:
    @app.exception_handler(AuthError)
    async def controlled(request: Request, error: AuthError) -> Response:
        auth = getattr(request.app.state, "auth", None)
        should_count = error.status == 503 or (
            error.status == 401
            and request.method == "GET"
            and request.cookies.get("__Host-cve-session") is not None
        )
        if auth and should_count:
            try:
                async with transaction(auth.database) as session:
                    name = "session_invalid" if error.status == 401 else "dependency_failure"
                    await execute(
                        session, "UPDATE security.auth_counters SET n=n+1 WHERE name=:n", n=name
                    )
            except SQLAlchemyError:
                pass
        return problem(error.status)

    @app.exception_handler(SQLAlchemyError)
    async def database_unavailable(_request: Request, _error: SQLAlchemyError) -> Response:
        logging.getLogger("cve.auth").error("dependency_unavailable")
        return problem(503)
