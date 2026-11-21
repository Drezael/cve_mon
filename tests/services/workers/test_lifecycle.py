"""Worker is only a technical lifecycle, with cancellation/partial startup cleanup."""

import asyncio
from pathlib import Path

import pytest
from cve_common.config.settings import DatabaseSettings, ServiceSettings
from cve_common.lifecycle.resources import Resources
from cve_common.lifecycle.worker import run_worker


async def test_stop_and_repeated_lifespan() -> None:
    settings = ServiceSettings(service_name="cve-test", app_env="test")
    resources = Resources(settings)
    for _ in range(2):
        assert not await resources.ready()
        async with resources:
            assert await resources.ready()
        assert not await resources.ready()
    stop = asyncio.Event()
    task = asyncio.create_task(run_worker(settings, stop))
    await asyncio.sleep(0)
    stop.set()
    await asyncio.wait_for(task, 2)


async def test_cancelled_worker_releases_resources() -> None:
    task = asyncio.create_task(
        run_worker(ServiceSettings(service_name="cve-test", app_env="test"), asyncio.Event())
    )
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_failed_start_cleans_engine(db_settings: DatabaseSettings, tmp_path: Path) -> None:
    config = db_settings.model_copy(update={"password_file": tmp_path / "missing"})
    resources = Resources(ServiceSettings(service_name="cve-test", app_env="test", database=config))
    with pytest.raises(ValueError):
        async with resources:
            pass
    assert not resources.started
    assert resources.database is not None and resources.database.engine is None
