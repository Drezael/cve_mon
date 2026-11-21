"""Only the Phase-8 authentication surface; password reset deliberately has no route."""

from typing import Any

from fastapi import APIRouter, Request
from pydantic import Field, SecretStr
from starlette.responses import JSONResponse, Response

from cve_api.auth.schemas import Input
from cve_api.users.activation import Handoff

from .cookies import clear_cookie, set_cookie
from .dependencies import csrf_for, transport
from .recovery import recover
from .schemas import OTP, Login, PasswordChange, Reauthentication, Recovery
from .sessions import LOGIN_COOKIE, SESSION_COOKIE

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])


def reply(result: dict[str, Any]) -> Response:
    data = dict(result)
    cookie = data.pop("cookie", None)
    login_cookie = data.pop("login_cookie", None)
    max_age = data.pop("max_age", 300)
    response = JSONResponse(data)
    if cookie:
        set_cookie(response, cookie, max_age)
        clear_cookie(response, login=True)
    if login_cookie:
        clear_cookie(response)
        set_cookie(response, login_cookie, max_age, login=True)
    return response


@router.get("/csrf")
async def csrf(request: Request) -> Response:
    service, ip = transport(request)
    return reply(await service.csrf(request.cookies.get(SESSION_COOKIE), ip))


@router.post("/login")
async def login(request: Request, body: Login) -> Response:
    service, ip = transport(request)
    return reply(
        await service.login(
            body.username,
            body.password.get_secret_value(),
            request.cookies.get(LOGIN_COOKIE),
            request.cookies.get(SESSION_COOKIE),
            csrf_for(request),
            ip,
        )
    )


@router.post("/mfa/verify")
async def verify(request: Request, body: OTP) -> Response:
    service, ip = transport(request)
    return reply(
        await service.verify_mfa(
            request.cookies.get(SESSION_COOKIE), csrf_for(request), ip, body.code.get_secret_value()
        )
    )


@router.post("/mfa/enroll/start")
async def enroll(request: Request) -> Response:
    service, ip = transport(request)
    return reply(await service.enroll(request.cookies.get(SESSION_COOKIE), csrf_for(request), ip))


@router.post("/mfa/enroll/cancel", status_code=204)
async def cancel_enrollment(request: Request) -> Response:
    service, _ = transport(request)
    await service.cancel_enrollment(request.cookies.get(SESSION_COOKIE), csrf_for(request))
    return Response(status_code=204)


@router.post("/mfa/disable")
async def disable_mfa(request: Request) -> Response:
    service, _ = transport(request)
    return reply(await service.disable_mfa(request.cookies.get(SESSION_COOKIE), csrf_for(request)))


@router.post("/mfa/enroll/confirm")
async def confirm(request: Request, body: OTP) -> Response:
    service, ip = transport(request)
    return reply(
        await service.confirm(
            request.cookies.get(SESSION_COOKIE), csrf_for(request), ip, body.code.get_secret_value()
        )
    )


@router.post("/mfa/recovery")
async def recovery(request: Request, body: Recovery) -> Response:
    service, ip = transport(request)
    return reply(
        await recover(
            service,
            request.cookies.get(SESSION_COOKIE),
            csrf_for(request),
            ip,
            body.code.get_secret_value(),
        )
    )


@router.get("/session")
async def session_info(request: Request) -> Response:
    service, _ = transport(request)
    return reply(await service.session_info(request.cookies.get(SESSION_COOKIE)))


@router.post("/logout")
async def logout(request: Request) -> Response:
    service, _ = transport(request)
    await service.logout(request.cookies.get(SESSION_COOKIE), csrf_for(request))
    response = Response(status_code=204)
    clear_cookie(response)
    return response


@router.post("/logout-all")
async def logout_all(request: Request) -> Response:
    service, _ = transport(request)
    await service.logout(request.cookies.get(SESSION_COOKIE), csrf_for(request), all_sessions=True)
    response = Response(status_code=204)
    clear_cookie(response)
    return response


@router.post("/reauthenticate")
async def reauthenticate(request: Request, body: Reauthentication) -> Response:
    service, ip = transport(request)
    return reply(
        await service.reauthenticate(
            request.cookies.get(SESSION_COOKIE),
            csrf_for(request),
            ip,
            body.password.get_secret_value(),
            body.code.get_secret_value() if body.code else None,
        )
    )


@router.post("/password/change")
async def change_password(request: Request, body: PasswordChange) -> Response:
    service, ip = transport(request)
    await service.change_password(
        request.cookies.get(SESSION_COOKIE),
        csrf_for(request),
        ip,
        body.password.get_secret_value(),
        body.new_password.get_secret_value(),
        body.code.get_secret_value() if body.code else None,
    )
    response = Response(status_code=204)
    clear_cookie(response)
    return response


class Activation(Input):
    activation_token: SecretStr = Field(min_length=70, max_length=100)
    new_password: SecretStr = Field(min_length=15, max_length=256)


class RecoveryHandoff(Input):
    recovery_token: SecretStr = Field(min_length=70, max_length=100)


@router.post("/activation/redeem", status_code=204)
async def activate(request: Request, body: Activation) -> Response:
    auth, ip = transport(request)
    await Handoff(auth).activate(
        body.activation_token.get_secret_value(),
        body.new_password.get_secret_value(),
        request.cookies.get(LOGIN_COOKIE),
        csrf_for(request),
        ip,
    )
    response = Response(status_code=204)
    clear_cookie(response, login=True)
    return response


@router.post("/mfa/recovery/redeem")
async def recover_handoff(request: Request, body: RecoveryHandoff) -> Response:
    auth, ip = transport(request)
    return reply(
        await Handoff(auth).recover(
            request.cookies.get(SESSION_COOKIE),
            csrf_for(request),
            body.recovery_token.get_secret_value(),
            ip,
        )
    )
