"""Single modern lifespan mechanism; no resources allocated while importing."""

from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager

from cve_common.lifecycle.resources import Resources
from fastapi import FastAPI

from cve_api.auth.service import AuthService
from cve_api.cve_data import configuration
from cve_api.cve_data_cache import SnapshotCache
from cve_api.inventories.service import InventoryService
from cve_api.settings import ApiSettings
from cve_api.status.collector import Collector


def lifespan_for(
    settings: ApiSettings, factory: Callable[[ApiSettings], Resources]
) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.cve_configuration_file = settings.cve_configuration_file
        app.state.cve_data_cache = SnapshotCache()
        resources = factory(settings)
        app.state.resources = resources
        async with resources:
            auth = AuthService(settings.auth) if settings.auth else None
            app.state.auth = auth
            inventory = (
                InventoryService(settings.inventory, auth) if settings.inventory and auth else None
            )
            app.state.inventory = inventory
            sources = configuration(settings.cve_configuration_file)
            status = (
                Collector(settings.status, epss_enabled=bool(sources and sources.epss_enabled))
                if settings.status
                else None
            )
            app.state.status_settings = settings.status
            app.state.status_collector = status
            try:
                if auth:
                    await auth.open()
                    from cve_api.smtp_bootstrap import bootstrap

                    await bootstrap(auth)
                    from cve_api.localization import bootstrap as bootstrap_locale

                    await bootstrap_locale(auth)
                if inventory:
                    await inventory.open()
                if status:
                    await status.open()
                yield
            finally:
                if status:
                    await status.close()
                if inventory:
                    await inventory.close()
                app.state.inventory = None
                if auth:
                    await auth.close()
                app.state.auth = None

    return lifespan
