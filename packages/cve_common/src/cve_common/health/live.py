"""Process liveness does not require PostgreSQL or an external connection."""

from starlette.responses import JSONResponse


def live(service: str) -> JSONResponse:
    return JSONResponse(
        {"status": "alive", "service": service}, headers={"Cache-Control": "no-store"}
    )
