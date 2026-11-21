"""Single-use high-entropy recovery codes; recovery only creates a restricted session."""

from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from cve_api.auth.transactions import security_transaction as transaction

from .audit import record
from .errors import AuthError
from .repository import execute, one
from .sessions import digest, parse_token, random_value


async def generate_codes(session: AsyncSession, user: UUID) -> list[str]:
    await execute(
        session,
        (
            "UPDATE security.recovery_codes SET revoked_at=clock_timestamp() WHERE "
            "user_id=:u AND revoked_at IS NULL"
        ),
        u=user,
    )
    values = [random_value() for _ in range(10)]
    for value in values:
        await execute(
            session,
            "INSERT INTO security.recovery_codes(user_id,verifier) VALUES(:u,:v)",
            u=user,
            v=digest(value),
        )
    return values


async def recover(
    service: "AuthService", cookie: str | None, csrf: str, ip: str, value: str
) -> dict[str, Any]:
    await service.limits.admit(ip, challenge=str(parse_token(cookie)[0]))
    result = None
    async with transaction(service.database) as session:
        current = await service.resolve(session, cookie, csrf)
        if current["auth_state"] != "mfa_pending":
            raise AuthError(403)
        code = await one(
            session,
            (
                "UPDATE security.recovery_codes SET used_at=clock_timestamp() WHERE "
                "user_id=:u AND verifier=:v AND used_at IS NULL AND revoked_at IS NULL "
                "RETURNING id"
            ),
            u=current["user"]["id"],
            v=digest(value),
        )
        if code is None:
            await record(session, "mfa_failure", current["user"]["id"], success=False)
        else:
            await execute(
                session,
                (
                    "UPDATE security.sessions SET revoked_at=clock_timestamp() "
                    "WHERE user_id=:u "
                    "AND revoked_at IS NULL"
                ),
                u=current["user"]["id"],
            )
            await execute(
                session,
                (
                    "UPDATE security.mfa_methods SET revoked_at=clock_timestamp() WHERE "
                    "user_id=:u AND revoked_at IS NULL AND runtime_version=1"
                ),
                u=current["user"]["id"],
            )
            result = await service.create(
                session, current["user"], "mfa_recovery", previous=current["id"]
            )
            await record(session, "recovery_used", current["user"]["id"])
    if result is None:
        raise AuthError()
    return result


# Avoid service construction/import cycles and keep import-time resources absent.

if TYPE_CHECKING:
    from .service import AuthService
