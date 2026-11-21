"""Internal reset primitives. No HTTP issuance, mail promise or MFA reset."""

from uuid import UUID

from cve_api.auth.transactions import security_transaction as transaction

from .audit import record
from .errors import AuthError
from .password_policy import validate_password
from .repository import execute, one
from .service import AuthService
from .sessions import new_token, parse_token


class ResetTokens:
    def __init__(self, service: AuthService) -> None:
        self.service = service

    async def issue(self, user: UUID, ip: str) -> str:
        # Only a future authorized independent delivery integration may call this primitive.
        await self.service.limits.admit(ip, identity=str(user))
        async with transaction(self.service.database) as session:
            await self.service.user(session, user)
            uid, token, verifier = new_token()
            await execute(
                session,
                (
                    "UPDATE security.account_tokens SET revoked_at=clock_timestamp() WHERE "
                    "user_id=:u AND purpose='password_reset' AND used_at IS NULL AND revoked_at "
                    "IS NULL"
                ),
                u=user,
            )
            await execute(
                session,
                (
                    "INSERT INTO "
                    "security.account_tokens(id,user_id,purpose,verifier,expires_at) "
                    "VALUES(:id,:u,'password_reset',:v,clock_timestamp()+interval '15 minutes')"
                ),
                id=uid,
                u=user,
                v=verifier,
            )
            await record(session, "password_reset_prepared", user)
            return token

    async def consume(self, token: str, new_password: str, ip: str) -> None:
        uid, verifier = parse_token(token)
        await self.service.limits.admit(ip, challenge=str(uid))
        replacement = await self.service.passwords.hash(validate_password(new_password))
        async with transaction(self.service.database) as session:
            lookup = await one(
                session, "SELECT user_id FROM security.account_tokens WHERE id=:id", id=uid
            )
            if lookup is None:
                raise AuthError()
            user = await self.service.user(session, lookup["user_id"])
            validate_password(new_password, user["username"])
            consumed = await one(
                session,
                (
                    "UPDATE security.account_tokens SET used_at=clock_timestamp() WHERE id=:id "
                    "AND user_id=:u AND verifier=:v AND purpose='password_reset' AND used_at IS "
                    "NULL AND revoked_at IS NULL AND expires_at>clock_timestamp() RETURNING id"
                ),
                id=uid,
                u=user["id"],
                v=verifier,
            )
            if consumed is None:
                raise AuthError()
            await execute(
                session,
                (
                    "UPDATE security.password_credentials SET password_hash="
                    ":h,changed_at=clock_timestamp(),credential_version=cred"
                    "ential_version+1,must_change=false WHERE user_id=:u"
                ),
                h=replacement,
                u=user["id"],
            )
            await execute(
                session,
                (
                    "UPDATE security.sessions SET revoked_at=clock_timestamp() "
                    "WHERE user_id=:u "
                    "AND revoked_at IS NULL"
                ),
                u=user["id"],
            )
            await execute(
                session,
                (
                    "UPDATE security.account_tokens SET revoked_at=clock_timestamp() WHERE "
                    "user_id=:u AND used_at IS NULL AND revoked_at IS NULL"
                ),
                u=user["id"],
            )
            await execute(
                session,
                (
                    "UPDATE security.users SET auth_version=auth_versio"
                    "n+1,version=version+1 WHERE id=:u"
                ),
                u=user["id"],
            )
            await record(session, "password_reset_completed", user["id"])
