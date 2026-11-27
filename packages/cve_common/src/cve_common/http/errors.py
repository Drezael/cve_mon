"""Safe error families; messages/input/SQL details are never reflected."""

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException
from starlette.responses import Response

from cve_common.http.responses import problem


def validation_response(request: Request, error: RequestValidationError) -> Response:
    """Only declared parameter names; never input, nested user keys or validator text."""
    route = request.scope.get("route")
    body_field = getattr(route, "body_field", None)
    annotation = getattr(getattr(body_field, "field_info", None), "annotation", None)
    fields = getattr(annotation, "model_fields", {})
    allowed = {"body": set(fields)}
    dependant = getattr(route, "dependant", None)
    for kind in ("query", "path", "header"):
        allowed[kind] = {field.alias for field in getattr(dependant, kind + "_params", [])}
    pointers = set()
    for item in error.errors():
        loc = item.get("loc", ())
        if len(loc) >= 2 and loc[0] in allowed and loc[1] in allowed[loc[0]]:
            name = str(loc[1]).replace("~", "~0").replace("/", "~1")
            pointers.add("/" + str(loc[0]) + "/" + name)
    return problem(
        422, errors=[{"pointer": p, "message": "Invalid value"} for p in sorted(pointers)[:100]]
    )


class ServiceError(Exception):
    def __init__(self, status: int = 500) -> None:
        self.status = status
        super().__init__("Controlled service error")


def install_handlers(app: FastAPI) -> None:
    @app.exception_handler(HTTPException)
    async def http_error(_request: Request, error: HTTPException) -> Response:
        return problem(error.status_code)

    @app.exception_handler(RequestValidationError)
    async def invalid(request: Request, error: RequestValidationError) -> Response:
        return validation_response(request, error)

    @app.exception_handler(ServiceError)
    async def known(_request: Request, error: ServiceError) -> Response:
        return problem(error.status)

    @app.exception_handler(Exception)
    async def unknown(_request: Request, _error: Exception) -> Response:
        logging.getLogger("cve.http").error(
            "internal_error", exc_info=True, extra={"diagnostic_code": "HTTP_UNHANDLED"}
        )
        return problem(500)
