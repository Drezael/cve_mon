"""Worker runner waits for an explicit stop event; no jobs or polling side effects."""

import asyncio
import logging
import signal

from cve_common.config.settings import ServiceSettings
from cve_common.lifecycle.resources import Resources


async def run_worker(
    settings: ServiceSettings, stop: asyncio.Event, *, signals: bool = False
) -> None:
    loop = asyncio.get_running_loop()
    installed = []
    try:
        if signals:
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, stop.set)
                installed.append(sig)
        async with Resources(settings):
            logging.getLogger("cve.worker").info("worker_started")
            await stop.wait()
            logging.getLogger("cve.worker").info("worker_stopped")
    finally:
        for sig in installed:
            loop.remove_signal_handler(sig)
