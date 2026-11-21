"""Router dependencies complement mandatory revalidation inside each service transaction."""

from collections.abc import Callable

from fastapi import Request

from cve_api.auth.dependencies import csrf_for, transport
from cve_api.auth.sessions import SESSION_COOKIE
from cve_api.auth.transactions import security_transaction

from .engine import function_decision
from .errors import Denied
from .principal import Principal, load_principal


def require_permission(action: str) -> Callable[..., object]:
    async def dependency(request: Request) -> Principal:
        auth, _ = transport(request)
        csrf = csrf_for(request) if request.method not in {"GET", "HEAD"} else None
        async with security_transaction(auth.database, mutation=False) as session:
            principal, _ = await load_principal(
                auth, session, request.cookies.get(SESSION_COOKIE), csrf
            )
            permitted = function_decision(principal, action).allow
        if not permitted:
            from .administration import Administration

            await Administration(auth).log_denial(
                request.cookies.get(SESSION_COOKIE), "missing_permission"
            )
            raise Denied()
        return principal

    return dependency
