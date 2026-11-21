"""Controlled manual handoff: operators issue private tokens; API never returns them."""

from typing import Any
from uuid import UUID

from cve_api.auth.errors import AuthError
from cve_api.auth.password_policy import validate_password
from cve_api.auth.repository import execute, one
from cve_api.auth.service import AuthService
from cve_api.auth.sessions import new_token, parse_token
from cve_api.auth.transactions import security_transaction
from cve_api.authorization.audit import record
from cve_api.authorization.errors import Denied


class Handoff:
    """Host-operator primitive; issuance deliberately has no HTTP route."""

    def __init__(self, auth: AuthService) -> None:
        self.auth = auth

    async def issue(self, uid: UUID, request_id: UUID | None = None) -> str:
        async with security_transaction(self.auth.database) as s:
            user = await one(
                s, "SELECT id,status FROM security.users WHERE id=:u FOR UPDATE", u=uid
            )
            if user is None:
                raise Denied(404)
            purpose = "mfa_reset" if request_id else "activation"
            actor = None
            if request_id:
                approved = await one(
                    s,
                    (
                        "SELECT requested_by FROM security.recovery_requests WHE"
                        "RE id=:id AND user_id=:u AND expires_at>clock_timestamp"
                        "() AND revoked_at IS NULL AND redeemed_at IS NULL FOR U"
                        "PDATE"
                    ),
                    id=request_id,
                    u=uid,
                )
                if approved is None or user["status"] != "active":
                    raise Denied(409)
                actor = approved["requested_by"]
            elif user["status"] != "pending_activation":
                raise Denied(409)
            sid, token, verifier = new_token()
            await execute(
                s,
                (
                    "UPDATE security.account_tokens SET revoked_at=clock_tim"
                    "estamp() WHERE user_id=:u AND purpose=:p AND used_at IS"
                    " NULL AND revoked_at IS NULL"
                ),
                u=uid,
                p=purpose,
            )
            await execute(
                s,
                (
                    "INSERT INTO security.account_tokens(id,user_id,purpose,"
                    "verifier,expires_at,issued_by,recovery_request_id) VALU"
                    "ES(:id,:u,:p,:v,clock_timestamp()+interval '1 hour',:a,"
                    ":request)"
                ),
                id=sid,
                u=uid,
                p=purpose,
                v=verifier,
                a=actor,
                request=request_id,
            )
            await record(s, "mfa_recovery_issued" if request_id else "activation_issued", None, uid)
            return token

    async def activate(
        self, token: str, password: str, login_cookie: str | None, csrf: str, ip: str
    ) -> None:
        sid, verifier = parse_token(token)
        await self.auth.limits.admit(ip, challenge=str(sid))
        async with security_transaction(self.auth.database) as s:
            await self.auth.preauth(s, login_cookie, csrf)
        encoded = await self.auth.passwords.hash(validate_password(password))
        async with security_transaction(self.auth.database) as s:
            lookup = await one(
                s, "SELECT user_id FROM security.account_tokens WHERE id=:id", id=sid
            )
            if not lookup:
                raise AuthError()
            user = await one(
                s,
                ("SELECT id,status,username FROM security.users WHERE id=:u FOR UPDATE"),
                u=lookup["user_id"],
            )
            if not user or user["status"] != "pending_activation":
                raise AuthError()
            validate_password(password, user["username"])
            consumed = await one(
                s,
                (
                    "UPDATE security.account_tokens SET used_at=clock_timest"
                    "amp() WHERE id=:id AND user_id=:u AND purpose='activati"
                    "on' AND verifier=:v AND expires_at>clock_timestamp() AN"
                    "D revoked_at IS NULL AND used_at IS NULL RETURNING id"
                ),
                id=sid,
                u=user["id"],
                v=verifier,
            )
            if not consumed:
                raise AuthError()
            await execute(
                s,
                (
                    "INSERT INTO security.password_credentials(user_id,passw"
                    "ord_hash) VALUES(:u,:h) ON CONFLICT(user_id) DO UPDATE "
                    "SET password_hash=excluded.password_hash,changed_at=clo"
                    "ck_timestamp(),credential_version=password_credentials."
                    "credential_version+1,revoked_at=NULL,must_change=false"
                ),
                u=user["id"],
                h=encoded,
            )
            await execute(
                s,
                (
                    "UPDATE security.users SET status='active',auth_version="
                    "auth_version+1,version=version+1 WHERE id=:u"
                ),
                u=user["id"],
            )
            await record(s, "activation_completed", None, user["id"])

    async def recover(self, cookie: str | None, csrf: str, token: str, ip: str) -> dict[str, Any]:
        sid, verifier = parse_token(token)
        await self.auth.limits.admit(ip, challenge=str(sid))
        async with security_transaction(self.auth.database) as s:
            current = await self.auth.resolve(s, cookie, csrf)
            if current["auth_state"] != "mfa_pending":
                raise AuthError(403)
            row = await one(
                s,
                (
                    "UPDATE security.account_tokens t SET used_at=clock_time"
                    "stamp() FROM security.recovery_requests r WHERE t.id=:i"
                    "d AND t.user_id=:u AND t.purpose='mfa_reset' AND t.veri"
                    "fier=:v AND t.expires_at>clock_timestamp() AND t.revoke"
                    "d_at IS NULL AND t.used_at IS NULL AND r.id=t.recovery_"
                    "request_id AND r.user_id=t.user_id AND r.redeemed_at IS"
                    " NULL AND r.revoked_at IS NULL AND r.expires_at>clock_t"
                    "imestamp() RETURNING r.id"
                ),
                id=sid,
                u=current["user"]["id"],
                v=verifier,
            )
            if not row:
                raise AuthError()
            await execute(
                s,
                (
                    "UPDATE security.recovery_requests SET redeemed_at=clock"
                    "_timestamp() WHERE id=:id"
                ),
                id=row["id"],
            )
            result = await self.auth.create(
                s, current["user"], "mfa_recovery", previous=current["id"]
            )
            await record(s, "mfa_recovery_redeemed", current["user"]["id"], current["user"]["id"])
            return result
