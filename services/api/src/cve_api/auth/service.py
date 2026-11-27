"""Transactional authentication state machine; secrets never leave authorized enrollment."""

import asyncio
import base64
import hmac
import logging
import unicodedata
from contextlib import suppress
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from cve_common.concurrency import BoundedThreads
from cve_common.config.secrets import read_secret
from cve_common.database.engine import Database
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from cve_api.auth.transactions import security_transaction as transaction

from . import totp
from .audit import record
from .encryption import Keyring
from .errors import AuthError
from .password_policy import validate_password
from .passwords import Passwords
from .rate_limits import RateLimits
from .repository import execute, one
from .sessions import digest, new_token, parse_token, random_value
from .settings import AuthSettings


class AuthService:
    def __init__(self, settings: AuthSettings) -> None:
        self.settings = settings
        self.database = Database(settings.database)
        self.administration_database = (
            Database(settings.administration_database) if settings.administration_database else None
        )
        self.passwords = Passwords(settings)
        self.vault_work = BoundedThreads(settings.argon_concurrency)
        self.keyring = Keyring(settings.keyring_file)
        self.gateway = read_secret(settings.gateway_file).get_secret_value()
        if len(self.gateway) < 43:
            raise AuthError(503)
        self.limits = RateLimits(self.database, settings, self.gateway.encode())
        self.maintenance_task: asyncio.Task[None] | None = None

    async def open(self) -> None:
        self.database.open()
        try:
            if self.administration_database:
                self.administration_database.open()
            await self.passwords.initialize()
            async with transaction(self.database) as session:
                await execute(session, "SELECT security.auth_cleanup()")
            self.maintenance_task = asyncio.create_task(self._maintenance())
        except BaseException:
            if self.administration_database:
                await self.administration_database.close()
            await self.database.close()
            raise

    async def _maintenance(self) -> None:
        task = asyncio.current_task()
        assert task is not None
        # Driver/transaction cleanup can translate a cancellation into SQLAlchemyError.
        # Preserve the cancellation request instead of starting another sleep/transaction.
        while not task.cancelling():
            await asyncio.sleep(self.settings.cleanup_seconds)
            try:
                async with transaction(self.database) as session:
                    await execute(session, "SELECT security.auth_cleanup()")
            except SQLAlchemyError:
                logging.getLogger("cve.auth").error("dependency_unavailable")

    async def ready(self) -> bool:
        return bool(
            self.maintenance_task
            and not self.maintenance_task.done()
            and await self.database.ready(1)
            and (
                self.administration_database is None or await self.administration_database.ready(1)
            )
        )

    async def close(self) -> None:
        if self.maintenance_task:
            self.maintenance_task.cancel()
            with suppress(asyncio.CancelledError):
                await self.maintenance_task
            self.maintenance_task = None
        if self.administration_database:
            await self.administration_database.close()
        await self.database.close()

    async def now(self, session: AsyncSession) -> datetime:
        result = await one(session, "SELECT clock_timestamp() AS ts")
        assert result is not None
        return result["ts"]  # type: ignore[no-any-return]

    async def user(
        self, session: AsyncSession, uid: UUID, *, restricted: bool = False
    ) -> dict[str, Any]:
        user = await one(
            session,
            "SELECT * FROM security.users WHERE id=:id"
            + (" FOR UPDATE" if session.info.get("security_mutation", True) else ""),
            id=uid,
        )
        if user is None:
            raise AuthError()
        credential = await one(
            session,
            "SELECT "
            + ("user_id,credential_version,revoked_at" if restricted else "*")
            + " FROM security.password_credentials WHERE user_id=:id",
            id=uid,
        )
        admin = await one(
            session,
            (
                "SELECT EXISTS(SELECT 1 FROM security.user_roles ur JOIN security.roles r "
                "ON r.id=ur.role_id WHERE ur.user_id=:id AND r.code IN "
                "('admin','user_admin')) AS admin"
            ),
            id=uid,
        )
        if credential is None or user["status"] != "active" or credential["revoked_at"] is not None:
            raise AuthError()
        return {**user, **credential, "id": uid, "admin": bool(admin and admin["admin"])}

    async def resolve(
        self,
        session: AsyncSession,
        cookie: str | None,
        csrf: str | None = None,
        *,
        full: bool = False,
        restricted: bool = False,
    ) -> dict[str, Any]:
        uid, verifier = parse_token(cookie)
        lookup = await one(
            session,
            "SELECT user_id FROM security.sessions WHERE id=:id AND runtime_version=1",
            id=uid,
        )
        if lookup is None:
            raise AuthError()
        user = await self.user(session, lookup["user_id"], restricted=restricted)
        row = await one(
            session,
            "SELECT * FROM security.sessions WHERE id=:id"
            + (" FOR UPDATE" if session.info.get("security_mutation", True) else ""),
            id=uid,
        )
        now = await self.now(session)
        if (
            row is None
            or not hmac.compare_digest(verifier, bytes(row["verifier"]))
            or row["revoked_at"] is not None
            or min(row["expires_at"], row["idle_expires_at"]) <= now
            or row["credential_version"] != user["credential_version"]
            or row["auth_version"] != user["auth_version"]
            or row["origin"] != self.settings.origin
        ):
            raise AuthError()
        if csrf is not None and not hmac.compare_digest(digest(csrf), bytes(row["csrf_verifier"])):
            raise AuthError(403)
        if full and row["auth_state"] != "authenticated":
            raise AuthError(403)
        method = await one(
            session,
            (
                "SELECT "
                + ("id,user_id,runtime_version,verified_at,revoked_at" if restricted else "*")
                + " FROM security.mfa_methods WHERE user_id=:id AND runtime_version=1 "
                "AND revoked_at IS NULL AND verified_at IS NOT NULL"
            ),
            id=user["id"],
        )
        requires = user["mfa_required"] or method is not None
        if (
            row["auth_state"] == "authenticated"
            and requires
            and (method is None or row["mfa_verified_at"] is None)
        ):
            raise AuthError(403)
        idle = self.settings.admin_idle if user["admin"] else self.settings.user_idle
        if row["auth_state"] != "authenticated":
            idle = self.settings.challenge_seconds
        # The shared security gate fences revocation throughout a read transaction.
        # Avoid retaining a session write lock across every dashboard read from each tab.
        if session.info.get("security_mutation", True) or (
            now - row["last_seen_at"]
        ).total_seconds() >= min(30, idle / 4):
            await execute(
                session,
                (
                    "UPDATE security.sessions SET last_seen_at=:now,idle_exp"
                    "ires_at=least(expires_at,:now+make_interval(secs=>:idle"
                    ")) WHERE id=:id"
                ),
                now=now,
                idle=idle,
                id=uid,
            )
        return {**row, "user": user, "method": method, "now": now}

    async def create(
        self,
        session: AsyncSession,
        user: dict[str, Any],
        state: str,
        *,
        previous: UUID | None = None,
        mfa: bool = False,
        reauth: bool = False,
    ) -> dict[str, Any]:
        sid, token, verifier = new_token()
        csrf = self.session_csrf(token)
        full = state == "authenticated"
        absolute = (
            (self.settings.admin_absolute if user["admin"] else self.settings.user_absolute)
            if full
            else self.settings.challenge_seconds
        )
        idle = (
            (self.settings.admin_idle if user["admin"] else self.settings.user_idle)
            if full
            else self.settings.challenge_seconds
        )
        now = await self.now(session)
        await execute(
            session,
            (
                "INSERT INTO security.sessions(id,user_id,verifier,expir"
                "es_at,mfa_verified_at,auth_version,origin,runtime_versi"
                "on,auth_state,credential_version,csrf_verifier,idle_exp"
                "ires_at,correlation_id,reauthenticated_at) VALUES(:id,:"
                "u,:v,:now+make_interval(secs=>:absolute),:mfa,:av,:orig"
                "in,1,:state,:version,:csrf,:now+make_interval(secs=>:id"
                "le),:cid,:reauth)"
            ),
            id=sid,
            av=user["auth_version"],
            origin=self.settings.origin,
            u=user["id"],
            v=verifier,
            now=now,
            absolute=absolute,
            mfa=now if mfa else None,
            state=state,
            version=user["credential_version"],
            csrf=digest(csrf),
            idle=idle,
            cid=uuid4(),
            reauth=now if reauth else None,
        )
        if previous is not None:
            await execute(
                session,
                "UPDATE security.sessions SET revoked_at=:now WHERE id=:id",
                now=now,
                id=previous,
            )
        if full:
            await execute(
                session,
                "UPDATE security.users SET last_login_at=:now,version=version+1 WHERE id=:id",
                now=now,
                id=user["id"],
            )
        return {"cookie": token, "max_age": absolute, "state": state, "csrf_token": csrf}

    def session_csrf(self, cookie: str) -> str:
        """Stable per opaque session, independently keyed and rotated with its cookie."""
        value = hmac.digest(self.gateway.encode(), b"cve:csrf:v1:" + cookie.encode(), "sha256")
        return base64.urlsafe_b64encode(value).decode().rstrip("=")

    async def csrf(self, cookie: str | None, ip: str) -> dict[str, Any]:
        await self.limits.admit(ip)
        if cookie:
            try:
                async with transaction(self.database) as session:
                    current = await self.resolve(session, cookie)
                    csrf = self.session_csrf(cookie)
                    await execute(
                        session,
                        "UPDATE security.sessions SET csrf_verifier=:v WHERE id=:id",
                        v=digest(csrf),
                        id=current["id"],
                    )
                    return {"state": current["auth_state"], "csrf_token": csrf}
            except AuthError:
                pass
        async with transaction(self.database) as session:
            sid, token, verifier = new_token()
            csrf = random_value()
            await execute(
                session,
                (
                    "INSERT INTO security.csrf_contexts(id,verifier,csrf_verifier,expires_at) "
                    "VALUES(:id,:v,:c,clock_timestamp()+interval '5 minutes')"
                ),
                id=sid,
                v=verifier,
                c=digest(csrf),
            )
            return {
                "login_cookie": token,
                "max_age": 300,
                "csrf_token": csrf,
                "state": "unauthenticated",
            }

    async def preauth(self, session: AsyncSession, cookie: str | None, csrf: str) -> None:
        uid, verifier = parse_token(cookie)
        context = await one(
            session, ("SELECT * FROM security.csrf_contexts WHERE id=:id FOR UPDATE"), id=uid
        )
        if (
            context is None
            or context["expires_at"] <= await self.now(session)
            or not hmac.compare_digest(verifier, bytes(context["verifier"]))
            or not hmac.compare_digest(digest(csrf), bytes(context["csrf_verifier"]))
        ):
            raise AuthError(403)
        await execute(session, "DELETE FROM security.csrf_contexts WHERE id=:id", id=uid)

    async def login(
        self,
        username: str,
        password: str,
        login_cookie: str | None,
        session_cookie: str | None,
        csrf: str,
        ip: str,
    ) -> dict[str, Any]:
        normalized = unicodedata.normalize("NFKC", username).strip(" ").casefold()
        await self.limits.admit(ip, identity=normalized)
        async with transaction(self.database) as session:
            if session_cookie:
                await self.resolve(session, session_cookie, csrf)
            else:
                await self.preauth(session, login_cookie, csrf)
            row = await one(
                session,
                (
                    "SELECT u.id,u.status,c.password_hash,c.credential_version,c.revoked_at "
                    "FROM security.users u LEFT JOIN security.password_credentials c ON "
                    "c.user_id=u.id WHERE u.username_normalized=:name"
                ),
                name=normalized,
            )
        verified = await self.passwords.verify(row["password_hash"] if row else None, password)
        if (
            not verified
            or row is None
            or row["status"] != "active"
            or row["revoked_at"] is not None
        ):
            async with transaction(self.database) as session:
                await record(session, "login_failure", row["id"] if row else None, success=False)
            raise AuthError()
        async with transaction(self.database) as session:
            user = await self.user(session, row["id"])
            if (
                user["password_hash"] != row["password_hash"]
                or user["credential_version"] != row["credential_version"]
            ):
                raise AuthError()
            if self.passwords.needs_rehash(user["password_hash"]):
                replacement = await self.passwords.hash(password)
                await execute(
                    session,
                    "UPDATE security.password_credentials SET password_hash=:h WHERE user_id=:id",
                    h=replacement,
                    id=user["id"],
                )
            await execute(
                session,
                (
                    "UPDATE security.password_credentials SET "
                    "last_verified_at=clock_timestamp() WHERE user_id=:id"
                ),
                id=user["id"],
            )
            method = await one(
                session,
                (
                    "SELECT id FROM security.mfa_methods WHERE user_id=:id "
                    "AND runtime_version=1 AND revoked_at IS NULL AND verified_at IS NOT NULL"
                ),
                id=user["id"],
            )
            state = "mfa_pending" if method or user["mfa_required"] else "authenticated"
            previous = parse_token(session_cookie)[0] if session_cookie else None
            result = await self.create(session, user, state, previous=previous)
            await record(
                session, "login_success" if state == "authenticated" else "mfa_required", user["id"]
            )
            return result

    async def verify_factor(
        self, session: AsyncSession, current: dict[str, Any], value: str
    ) -> bool:
        method = current["method"]
        if method is None:
            return False
        secret = self.keyring.decrypt(
            current["user"]["id"], method["key_id"], bytes(method["ciphertext"])
        )
        step = totp.match(
            secret,
            value,
            int(current["now"].timestamp()) // 30,
            (method["last_used_step"] if method["last_used_step"] is not None else -1),
            self.settings.totp_window,
        )
        if step is None:
            return False
        await execute(
            session,
            "UPDATE security.mfa_methods SET last_used_step=:step WHERE id=:id",
            step=step,
            id=method["id"],
        )
        if method["key_id"] != self.keyring.active:
            key, encrypted = self.keyring.encrypt(current["user"]["id"], secret)
            await execute(
                session,
                "UPDATE security.mfa_methods SET key_id=:k,ciphertext=:c WHERE id=:id",
                k=key,
                c=encrypted,
                id=method["id"],
            )
        return True

    async def verify_mfa(
        self, cookie: str | None, csrf: str, ip: str, value: str
    ) -> dict[str, Any]:
        await self.limits.admit(ip, challenge=str(parse_token(cookie)[0]))
        result = None
        async with transaction(self.database) as session:
            current = await self.resolve(session, cookie, csrf)
            if current["auth_state"] != "mfa_pending":
                raise AuthError(403)
            if await self.verify_factor(session, current, value):
                result = await self.create(
                    session, current["user"], "authenticated", previous=current["id"], mfa=True
                )
                await record(session, "login_success", current["user"]["id"])
            else:
                await record(session, "mfa_failure", current["user"]["id"], success=False)
        if result is None:
            raise AuthError()
        return result

    async def consume_reauth(self, session: AsyncSession, current: dict[str, Any]) -> None:
        verified = current["reauthenticated_at"]
        if (
            current["auth_state"] != "authenticated"
            or verified is None
            or current["reauthentication_consumed_at"] is not None
            or (current["now"] - verified).total_seconds() > self.settings.reauth_seconds
        ):
            raise AuthError(403)
        await execute(
            session,
            (
                "UPDATE security.sessions SET "
                "reauthentication_consumed_at=clock_timestamp() WHERE id=:id"
            ),
            id=current["id"],
        )

    async def enroll(self, cookie: str | None, csrf: str, ip: str) -> dict[str, Any]:
        await self.limits.admit(ip, challenge=str(parse_token(cookie)[0]))
        async with transaction(self.database) as session:
            current = await self.resolve(session, cookie, csrf)
            if current["auth_state"] == "authenticated":
                await self.consume_reauth(session, current)
                rotated = {"state": "authenticated"}
                enrollment_id = current["id"]
            elif current["auth_state"] in {"mfa_setup_required", "mfa_recovery"}:
                rotated = {}
                enrollment_id = current["id"]
            else:
                raise AuthError(403)
            secret = totp.new_secret()
            key, ciphertext = self.keyring.encrypt(current["user"]["id"], secret)
            await execute(
                session,
                (
                    "UPDATE security.mfa_methods SET revoked_at=clock_timestamp() WHERE "
                    "user_id=:u AND revoked_at IS NULL AND runtime_version=1 "
                    "AND verified_at IS NULL"
                ),
                u=current["user"]["id"],
            )
            await execute(
                session,
                (
                    "INSERT INTO security.mfa_methods(user_id,kind,ciphertex"
                    "t,key_id,runtime_version,enrollment_session_id,enrollme"
                    "nt_expires_at) VALUES(:u,'totp',:c,:k,1,:sid,clock_time"
                    "stamp()+make_interval(secs=>:ttl))"
                ),
                u=current["user"]["id"],
                c=ciphertext,
                k=key,
                sid=enrollment_id,
                ttl=self.settings.challenge_seconds,
            )
            await record(session, "mfa_enrollment_started", current["user"]["id"])
            return {
                **rotated,
                "provisioning_uri": totp.provisioning(secret, current["user"]["username"]),
            }

    async def confirm(self, cookie: str | None, csrf: str, ip: str, value: str) -> dict[str, Any]:
        from .recovery import generate_codes

        await self.limits.admit(ip, challenge=str(parse_token(cookie)[0]))
        result = None
        async with transaction(self.database) as session:
            current = await self.resolve(session, cookie, csrf)
            method = await one(
                session,
                (
                    "SELECT * FROM security.mfa_methods WHERE user_id=:u AND runtime_version=1 AND "
                    "revoked_at IS NULL AND verified_at IS NULL AND enrollment_session_id=:sid "
                    "AND enrollment_expires_at>clock_timestamp() FOR UPDATE"
                ),
                u=current["user"]["id"],
                sid=current["id"],
            )
            if (
                current["auth_state"] not in {"authenticated", "mfa_setup_required", "mfa_recovery"}
                or method is None
            ):
                raise AuthError(403)
            secret = self.keyring.decrypt(
                current["user"]["id"], method["key_id"], bytes(method["ciphertext"])
            )
            step = totp.match(
                secret,
                value,
                int(current["now"].timestamp()) // 30,
                (method["last_used_step"] if method["last_used_step"] is not None else -1),
                self.settings.totp_window,
            )
            if step is None:
                await record(session, "mfa_failure", current["user"]["id"], success=False)
            else:
                await execute(
                    session,
                    "UPDATE security.mfa_methods SET revoked_at=clock_timestamp() "
                    "WHERE user_id=:u AND runtime_version=1 AND verified_at IS NOT NULL "
                    "AND revoked_at IS NULL",
                    u=current["user"]["id"],
                )
                await execute(
                    session,
                    (
                        "UPDATE security.mfa_methods SET "
                        "verified_at=clock_timestamp(),last_used_step=:step WHERE id=:id"
                    ),
                    step=step,
                    id=method["id"],
                )
                await execute(
                    session,
                    "UPDATE security.users SET mfa_required=true,version=version+1 WHERE id=:u",
                    u=current["user"]["id"],
                )
                codes = await generate_codes(session, current["user"]["id"])
                await execute(
                    session,
                    (
                        "UPDATE security.sessions SET revoked_at=clock_timestamp() "
                        "WHERE user_id=:u "
                        "AND revoked_at IS NULL"
                    ),
                    u=current["user"]["id"],
                )
                result = await self.create(
                    session, current["user"], "authenticated", previous=current["id"], mfa=True
                )
                result["recovery_codes"] = codes
                await record(session, "mfa_enabled", current["user"]["id"])
                await record(session, "login_success", current["user"]["id"])
        if result is None:
            raise AuthError(400 if current["auth_state"] == "authenticated" else 401)
        return result

    async def cancel_enrollment(self, cookie: str | None, csrf: str) -> None:
        async with transaction(self.database) as session:
            current = await self.resolve(session, cookie, csrf, full=True)
            await execute(
                session,
                "UPDATE security.mfa_methods SET revoked_at=clock_timestamp() "
                "WHERE user_id=:u AND enrollment_session_id=:sid AND verified_at IS NULL "
                "AND revoked_at IS NULL AND runtime_version=1",
                u=current["user"]["id"],
                sid=current["id"],
            )
            await record(session, "mfa_enrollment_cancelled", current["user"]["id"])

    async def disable_mfa(self, cookie: str | None, csrf: str) -> dict[str, Any]:
        async with transaction(self.database) as session:
            current = await self.resolve(session, cookie, csrf, full=True)
            await self.consume_reauth(session, current)
            uid = current["user"]["id"]
            await execute(
                session,
                "UPDATE security.users SET mfa_required=false,auth_version=auth_version+1, "
                "version=version+1 WHERE id=:u",
                u=uid,
            )
            for table in ["mfa_methods", "recovery_codes"]:
                await execute(
                    session,
                    "UPDATE security." + table + " SET revoked_at=clock_timestamp() "
                    "WHERE user_id=:u AND revoked_at IS NULL",
                    u=uid,
                )
            await execute(
                session,
                "UPDATE security.sessions SET revoked_at=clock_timestamp() "
                "WHERE user_id=:u AND revoked_at IS NULL",
                u=uid,
            )
            await execute(
                session,
                "UPDATE security.recovery_requests SET revoked_at=clock_timestamp() "
                "WHERE user_id=:u AND redeemed_at IS NULL AND revoked_at IS NULL",
                u=uid,
            )
            await execute(
                session,
                "UPDATE security.account_tokens SET revoked_at=clock_timestamp() "
                "WHERE user_id=:u AND purpose='mfa_reset' AND used_at IS NULL "
                "AND revoked_at IS NULL",
                u=uid,
            )
            user = await self.user(session, uid)
            result = await self.create(session, user, "authenticated")
            await record(session, "mfa_disabled", uid)
            return result

    async def session_info(self, cookie: str | None) -> dict[str, Any]:
        async with transaction(self.database) as session:
            current = await self.resolve(session, cookie)
            info: dict[str, Any] = {"state": current["auth_state"]}
            if current["auth_state"] == "authenticated":
                codes = await one(
                    session,
                    (
                        "SELECT count(*) AS n FROM security.recovery_codes WHERE user_id=:u AND "
                        "used_at IS NULL AND revoked_at IS NULL"
                    ),
                    u=current["user"]["id"],
                )
                info.update(
                    user_id=str(current["user"]["id"]),
                    display_name=current["user"]["display_name"],
                    mfa_verified=current["mfa_verified_at"] is not None,
                    mfa_enabled=current["method"] is not None or current["user"]["mfa_required"],
                    recovery_codes_remaining=codes["n"] if codes else 0,
                )
            return info

    async def logout(self, cookie: str | None, csrf: str, *, all_sessions: bool = False) -> None:
        async with transaction(self.database) as session:
            current = await self.resolve(session, cookie, csrf)
            if all_sessions and current["auth_state"] != "authenticated":
                raise AuthError(403)
            if all_sessions:
                await execute(
                    session,
                    (
                        "UPDATE security.sessions SET revoked_at=clock_timestamp() "
                        "WHERE user_id=:u "
                        "AND revoked_at IS NULL"
                    ),
                    u=current["user"]["id"],
                )
            else:
                await execute(
                    session,
                    "UPDATE security.sessions SET revoked_at=clock_timestamp() WHERE id=:id",
                    id=current["id"],
                )
            await record(session, "session_revoked", current["user"]["id"])

    async def reauthenticate(
        self, cookie: str | None, csrf: str, ip: str, password: str, code: str | None
    ) -> dict[str, Any]:
        await self.limits.admit(ip, challenge=str(parse_token(cookie)[0]))
        async with transaction(self.database) as session:
            current = await self.resolve(session, cookie, csrf, full=True)
            snapshot = current["user"]
        verified = await self.passwords.verify(snapshot["password_hash"], password)
        result = None
        async with transaction(self.database) as session:
            current = await self.resolve(session, cookie, csrf, full=True)
            if (
                verified
                and current["user"]["credential_version"] == snapshot["credential_version"]
                and (
                    current["method"] is None
                    or (code is not None and await self.verify_factor(session, current, code))
                )
            ):
                result = await self.create(
                    session,
                    current["user"],
                    "authenticated",
                    previous=current["id"],
                    mfa=current["method"] is not None,
                    reauth=True,
                )
                await record(session, "reauthenticated", current["user"]["id"])
            else:
                await record(
                    session,
                    "mfa_failure" if current["method"] else "login_failure",
                    current["user"]["id"],
                    success=False,
                )
        if result is None:
            raise AuthError()
        return result

    async def change_password(
        self,
        cookie: str | None,
        csrf: str,
        ip: str,
        password: str,
        new_password: str,
        code: str | None,
    ) -> None:
        # Require fresh session-bound reauthentication and the current password.
        await self.limits.admit(ip, challenge=str(parse_token(cookie)[0]))
        async with transaction(self.database) as session:
            current = await self.resolve(session, cookie, csrf, full=True)
            snapshot = current["user"]
        good = await self.passwords.verify(snapshot["password_hash"], password)
        if not good:
            raise AuthError()
        replacement = await self.passwords.hash(
            validate_password(new_password, snapshot["username"])
        )
        async with transaction(self.database) as session:
            current = await self.resolve(session, cookie, csrf, full=True)
            await self.consume_reauth(session, current)
            if current["user"]["credential_version"] != snapshot["credential_version"]:
                raise AuthError()
            await execute(
                session,
                (
                    "UPDATE security.password_credentials SET password_hash="
                    ":h,changed_at=clock_timestamp(),credential_version=cred"
                    "ential_version+1,must_change=false WHERE user_id=:u"
                ),
                h=replacement,
                u=current["user"]["id"],
            )
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
                    "UPDATE security.users SET auth_version=auth_versio"
                    "n+1,version=version+1 WHERE id=:u"
                ),
                u=current["user"]["id"],
            )
            await record(session, "password_changed", current["user"]["id"])
