"""Bounded threaded Argon2id; cancellation cannot release a still-running KDF slot."""

import asyncio
import secrets

from argon2 import PasswordHasher, Type, extract_parameters
from argon2.exceptions import Argon2Error

from .errors import AuthError
from .password_policy import normalize
from .settings import AuthSettings


class Passwords:
    def __init__(self, settings: AuthSettings) -> None:
        self.hasher = PasswordHasher(
            time_cost=settings.argon_iterations,
            memory_cost=settings.argon_memory,
            parallelism=settings.argon_parallelism,
            type=Type.ID,
        )
        self.slots = asyncio.Semaphore(settings.argon_concurrency)
        self.dummy: str | None = None

    async def _run(self, operation: object, *args: str) -> object:
        from collections.abc import Callable
        from typing import cast

        try:
            async with asyncio.timeout(0.25):
                await self.slots.acquire()
        except TimeoutError:
            raise AuthError(429) from None
        task = asyncio.create_task(asyncio.to_thread(cast(Callable[..., object], operation), *args))
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            await task
            raise
        finally:
            self.slots.release()

    async def initialize(self) -> None:
        self.dummy = await self.hash(secrets.token_urlsafe(32))

    async def hash(self, password: str) -> str:
        return str(await self._run(self.hasher.hash, normalize(password)))

    async def verify(self, encoded: str | None, password: str) -> bool:
        candidate = encoded or self.dummy
        if candidate is None:
            raise RuntimeError("Password verifier not initialized")
        try:
            p = extract_parameters(candidate)
            if (
                p.type is not Type.ID
                or p.memory_cost > 65536
                or p.time_cost > 4
                or p.parallelism > 2
                or p.hash_len > 64
                or p.salt_len > 64
            ):
                candidate = self.dummy
        except (Argon2Error, ValueError):
            candidate = self.dummy
        if candidate is None:
            return False
        try:
            good = bool(await self._run(self.hasher.verify, candidate, normalize(password)))
            return good and encoded is not None and candidate == encoded
        except (Argon2Error, ValueError):
            return False

    def needs_rehash(self, encoded: str) -> bool:
        return self.hasher.check_needs_rehash(encoded)
