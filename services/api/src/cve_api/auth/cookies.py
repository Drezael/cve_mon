"""Host-only cookies, HTTPS only; no token in a response body or URL."""

from starlette.responses import Response

from .sessions import LOGIN_COOKIE, SESSION_COOKIE


def set_cookie(response: Response, token: str, max_age: int, *, login: bool = False) -> None:
    response.set_cookie(
        LOGIN_COOKIE if login else SESSION_COOKIE,
        token,
        secure=True,
        httponly=True,
        samesite="strict",
        path="/",
        max_age=max_age,
    )


def clear_cookie(response: Response, *, login: bool = False) -> None:
    response.delete_cookie(
        LOGIN_COOKIE if login else SESSION_COOKIE,
        secure=True,
        httponly=True,
        samesite="strict",
        path="/",
    )
