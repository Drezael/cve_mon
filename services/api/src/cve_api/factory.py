"""Factory with replaceable resources for tests and no public generated API contract."""

from collections.abc import Callable

from cve_common.config.validation import load_settings
from cve_common.http.errors import install_handlers
from cve_common.http.middleware import TechnicalMiddleware
from cve_common.lifecycle.resources import Resources
from cve_common.release import VERSION
from fastapi import FastAPI

from cve_api.access.router import router as access_router
from cve_api.ansible.router import router as ansible_router
from cve_api.ansible.vault import router as vault_router
from cve_api.auth.handlers import install_auth_handlers
from cve_api.auth.middleware import AuthBoundary
from cve_api.auth.router import router as auth_router
from cve_api.authorization.handlers import install_authorization_handlers
from cve_api.custom_dashboards.router import router as custom_dashboards_router
from cve_api.cve_data import router as cve_data_router
from cve_api.dashboard.administration import router as administration_ui_router
from cve_api.dashboard.container_inventory import router as container_inventory_router
from cve_api.dashboard.router import router as dashboard_router
from cve_api.findings.router import router as finding_router
from cve_api.groups.personal import router as personal_groups_router
from cve_api.health import router
from cve_api.inventories.collection import router as collection_router
from cve_api.inventories.errors import install_handlers as install_inventory_handlers
from cve_api.inventories.router import router as inventory_router
from cve_api.lifespan import lifespan_for
from cve_api.localization import router as localization_router
from cve_api.notifications.reports import router as report_router
from cve_api.notifications.router import router as notification_router
from cve_api.roles.router import router as roles_router
from cve_api.servers.deletion import router as server_deletion
from cve_api.servers.router_admin import router as server_admin_router
from cve_api.servers.router_read import router as server_read_router
from cve_api.servers.scan import router as server_scan_router
from cve_api.settings import ApiSettings
from cve_api.smtp import router as smtp_router
from cve_api.status.router import router as status_router
from cve_api.technical_auth.router import router as credentials_router
from cve_api.users.router import router as users_router
from cve_api.workflows import router as workflows_router


def create_app(
    settings: ApiSettings | None = None,
    *,
    resource_factory: Callable[[ApiSettings], Resources] = Resources,
) -> FastAPI:
    settings = settings or load_settings(ApiSettings)
    app = FastAPI(
        title="CVE technical API",
        version=VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        redirect_slashes=False,
        lifespan=lifespan_for(settings, resource_factory),
    )
    app.state.deployment_mode = settings.app_env
    app.add_middleware(AuthBoundary)
    app.add_middleware(TechnicalMiddleware, allowed_hosts=settings.allowed_hosts)
    install_handlers(app)
    app.include_router(router)
    if settings.auth:
        app.include_router(status_router)
        app.include_router(smtp_router)
        app.include_router(auth_router)
        app.include_router(localization_router)
        app.include_router(finding_router)
        app.include_router(dashboard_router)
        app.include_router(custom_dashboards_router)
        app.include_router(personal_groups_router)
        app.include_router(container_inventory_router)
        app.include_router(cve_data_router)
        app.include_router(workflows_router)
        app.include_router(administration_ui_router)
        app.include_router(report_router)
        app.include_router(notification_router)
        install_auth_handlers(app)
        app.include_router(users_router)
        app.include_router(roles_router)
        app.include_router(access_router)
        app.include_router(ansible_router)
        app.include_router(vault_router)
        app.include_router(server_deletion)
        app.include_router(server_scan_router)
        app.include_router(server_admin_router)
        app.include_router(server_read_router)
        install_authorization_handlers(app)
    if settings.inventory:
        app.include_router(inventory_router)
        app.include_router(collection_router)
        app.include_router(credentials_router)
        install_inventory_handlers(app)
    return app
