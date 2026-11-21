"""Persisted independent admission transactions; failed verification never rolls limits back."""

import hashlib
import hmac

from cve_common.database.engine import Database
from cve_common.database.transactions import transaction

from .audit import record
from .errors import AuthError
from .repository import one
from .settings import AuthSettings


class RateLimits:
    def __init__(self, database: Database, settings: AuthSettings, key: bytes) -> None:
        self.database, self.settings, self.key = database, settings, key

    async def check(self, kind: str, value: str, limit: int, seconds: int = 60) -> None:
        key = hmac.digest(self.key, (kind + ":" + value).encode(), hashlib.sha256)
        async with transaction(self.database) as session:
            result = await one(
                session, "SELECT * FROM security.auth_rate(:k,:n,:s)", k=key, n=limit, s=seconds
            )
            assert result is not None
            if result["first_denial"]:
                await record(session, "rate_limited", success=False)
        if not result["allowed"]:
            raise AuthError(429)

    async def admit(
        self, ip: str, identity: str | None = None, challenge: str | None = None
    ) -> None:
        await self.check("global", "all", self.settings.global_limit)
        await self.check("ip", ip, self.settings.ip_limit)
        if identity is not None:
            await self.check("identity", identity, self.settings.login_limit)
        if challenge is not None:
            await self.check("challenge", challenge, self.settings.challenge_limit, 300)
