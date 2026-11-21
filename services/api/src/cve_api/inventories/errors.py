"""Safe upload rejection categories and Phase-0-compatible problem responses."""

import json

from cve_common.http.errors import ServiceError
from cve_common.http.responses import problem
from fastapi import FastAPI, Request
from starlette.responses import JSONResponse, Response


class UploadError(ServiceError):
    def __init__(self, status: int = 422, reason: str = "invalid_inventory") -> None:
        self.reason = reason
        super().__init__(status)


def upload_problem(status: int) -> Response:
    if status != 415:
        return problem(status)
    original = problem(400)
    data = json.loads(bytes(original.body))
    data["status"] = 415
    data["title"] = "Unsupported media type"
    return JSONResponse(
        data,
        status_code=415,
        media_type="application/problem+json",
        headers={
            k: v for k, v in original.headers.items() if k not in {"content-length", "content-type"}
        },
    )


def install_handlers(app: FastAPI) -> None:
    @app.exception_handler(UploadError)
    async def rejected(_request: Request, error: UploadError) -> Response:
        return upload_problem(error.status)
