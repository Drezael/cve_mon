"""Export the actual administrative routers without activating any resources."""

import json
from pathlib import Path

from cve_api.access.router import router as access
from cve_api.ansible.router import router as ansible
from cve_api.ansible.vault import router as vault
from cve_api.auth.router import router as auth
from cve_api.custom_dashboards.router import router as custom_dashboards
from cve_api.cve_data import router as cve_data
from cve_api.dashboard.administration import router as administration
from cve_api.findings.router import router as findings
from cve_api.groups.personal import router as personal_groups
from cve_api.inventories.router import router as inventory
from cve_api.localization import router as localization
from cve_api.notifications.reports import router as reports
from cve_api.notifications.router import router as notifications
from cve_api.roles.router import router as roles
from cve_api.servers.deletion import router as server_deletion
from cve_api.servers.router_admin import router as servers
from cve_api.smtp import router as smtp
from cve_api.users.router import router as users
from cve_api.workflows import router as workflows
from cve_common.release import VERSION
from fastapi import FastAPI


def export(root: Path) -> Path:
    app = FastAPI(title="Dashboard administration", version=VERSION)
    for router in [
        ansible,
        vault,
        custom_dashboards,
        personal_groups,
        localization,
        cve_data,
        auth,
        access,
        users,
        roles,
        servers,
        server_deletion,
        findings,
        reports,
        notifications,
        administration,
        smtp,
        inventory,
    ]:
        app.include_router(router)
    app.include_router(workflows)
    target = root / "contracts/api/dashboard-administration.openapi.json"
    target.write_text(json.dumps(app.openapi(), sort_keys=True, indent=2) + "\n")
    return target


if __name__ == "__main__":
    export(Path(__file__).resolve().parents[2])
