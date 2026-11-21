"""Bounded loop from the shared library; only a private, explicit target registry is loaded."""

import asyncio
import json
import stat
from pathlib import Path

from cve_common.config.secrets import SecretError
from cve_common.events.delivery import DeliveryRepository, Dispatcher
from cve_common.events.transport import HTTPTransport, Target
from cve_common.lifecycle.resources import Resources

from cve_event_dispatcher.settings import DispatcherSettings


def load_targets(path: Path) -> list[Target]:
    if (
        path.is_symlink()
        or not path.is_file()
        or stat.S_IMODE(path.stat().st_mode) not in (0o400, 0o600)
    ):
        raise SecretError("Private target configuration required")
    if path.stat().st_size > 32768:
        raise ValueError("Target configuration too large")
    data = json.loads(path.read_text())
    if not isinstance(data, list) or len(data) > 32:
        raise ValueError("Bounded target registry required")
    targets = [Target.model_validate(item) for item in data]
    if len({t.id for t in targets}) != len(targets):
        raise ValueError("Duplicate destination")
    return targets


class Runtime:
    def __init__(self, settings: DispatcherSettings, resources: Resources) -> None:
        if resources.database is None:
            raise ValueError("Persistent database required")
        self.transports: list[HTTPTransport] = []
        for target in load_targets(settings.targets_file):
            transport = HTTPTransport(target)
            resources.attach_http(transport.client)
            self.transports.append(transport)
        self.dispatcher = Dispatcher(
            DeliveryRepository(resources.database),
            settings,
            {t.target.id: t.send for t in self.transports},
        )
        self.stop = asyncio.Event()
        self.task: asyncio.Task[None] | None = None

    def start(self) -> None:
        self.task = asyncio.create_task(self.dispatcher.run(self.stop))

    async def close(self) -> None:
        self.stop.set()
        try:
            if self.task is not None:
                await self.task
        finally:
            for transport in self.transports:
                await transport.close()
