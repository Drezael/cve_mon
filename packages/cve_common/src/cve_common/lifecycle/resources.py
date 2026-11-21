"""Resources are allocated on entering lifespan; cleanup also covers partial startup."""

import asyncio
import logging
from contextlib import AsyncExitStack

from cve_common.config.settings import ServiceSettings
from cve_common.database.engine import Database, DatabaseRegistry
from cve_common.http.client import ServiceClient
from cve_common.logging.setup import configure_logging


class Resources:
    def __init__(self, settings: ServiceSettings) -> None:
        self.settings = settings
        self.database = Database(settings.database) if settings.database is not None else None
        self.databases = DatabaseRegistry({"main": self.database} if self.database else {})
        self.http: ServiceClient | None = None
        self.started = False
        self._stack: AsyncExitStack | None = None

    async def __aenter__(self) -> "Resources":
        if self.started:
            raise RuntimeError("Resources already started")
        configure_logging(self.settings.service_name, self.settings.log_level)
        stack = AsyncExitStack()
        await stack.__aenter__()
        self._stack = stack
        try:
            if self.database:
                stack.push_async_callback(self.database.close)
                self.database.open()
            self.started = True
            logging.getLogger("cve.lifecycle").info("startup")
            return self
        except BaseException:
            await stack.aclose()
            self._stack = None
            raise

    async def __aexit__(self, *_args: object) -> None:
        self.started = False
        stack, self._stack = self._stack, None
        if stack is not None:
            # Shield cleanup from the originating cancelled task.
            cleanup = asyncio.create_task(stack.aclose())
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                await cleanup
                raise
        logging.getLogger("cve.lifecycle").info("shutdown")

    def attach_http(self, client: ServiceClient) -> None:
        if self._stack is None:
            raise RuntimeError("Resources not started")
        self._stack.push_async_callback(client.close)
        self.http = client

    async def ready(self) -> bool:
        return self.started and (
            self.database is None or await self.database.ready(self.settings.ready_timeout)
        )
