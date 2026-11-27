"""Phase-0 Problem schema: correlation in headers, request UUID in the body."""

from starlette.responses import JSONResponse

from cve_common.logging.correlation import correlation_id, request_id, valid_id

TITLES = {
    400: ("INVALID_INPUT", "Invalid request"),
    401: ("UNAUTHENTICATED", "Authentication required"),
    403: ("FORBIDDEN", "Access denied"),
    404: ("NOT_FOUND", "Not found"),
    405: ("METHOD_NOT_ALLOWED", "Method not allowed"),
    409: ("CONFLICT", "Conflict"),
    413: ("PAYLOAD_TOO_LARGE", "Request too large"),
    422: ("INVALID_INPUT", "Invalid request"),
    429: ("RATE_LIMITED", "Too many requests"),
    503: ("DEPENDENCY_UNAVAILABLE", "Service not ready"),
    500: ("INTERNAL_ERROR", "Internal error"),
}


def problem(status: int, *, errors: list[dict[str, str]] | None = None) -> JSONResponse:
    code, title = TITLES.get(status, TITLES[500])
    rid = request_id.get() or valid_id(None)
    cid = correlation_id.get() or rid
    return JSONResponse(
        {
            "type": "urn:cve:error:" + code.lower(),
            "title": title,
            "status": status,
            "code": code,
            "request_id": rid,
            **({"errors": errors} if errors else {}),
        },
        status_code=status,
        media_type="application/problem+json",
        headers={"Cache-Control": "no-store", "X-Request-ID": rid, "X-Correlation-ID": cid},
    )
