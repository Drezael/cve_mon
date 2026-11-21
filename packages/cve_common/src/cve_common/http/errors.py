"""Safe error families; messages/input/SQL details are never reflected."""

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException
from starlette.responses import Response

from cve_common.http.responses import problem


class ServiceError(Exception):
    def __init__(self, status: int = 500) -> None:
        self.status = status
        super().__init__("Controlled service error")


def install_handlers(app: FastAPI) -> None:
    @app.exception_handler(HTTPException)
    async def http_error(_request: Request, error: HTTPException) -> Response:
        return problem(error.status_code)

    @app.exception_handler(RequestValidationError)
    async def invalid(_request: Request, _error: RequestValidationError) -> Response:
        return problem(422)

    @app.exception_handler(ServiceError)
    async def known(_request: Request, error: ServiceError) -> Response:
        return problem(error.status)

    @app.exception_handler(Exception)
    async def unknown(_request: Request, _error: Exception) -> Response:
        logging.getLogger("cve.http").error("internal_error", exc_info=True)
        return problem(500)
