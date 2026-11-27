"""Export existing FastAPI read routers locally; no public OpenAPI route or secrets."""

import json
from pathlib import Path

from cve_api.ansible.router import router as ansible
from cve_api.ansible.vault import router as vault
from cve_api.custom_dashboards.router import router as custom_dashboards
from cve_api.cve_data import router as cve_data
from cve_api.dashboard.container_inventory import router as container_inventory
from cve_api.dashboard.router import router as dashboard
from cve_api.findings.router import router as findings
from cve_api.groups.personal import router as personal_groups
from cve_api.localization import router as localization
from cve_api.notifications.reports import router as reports
from cve_api.notifications.router import router as notifications
from cve_api.servers.router_read import router as servers
from cve_api.servers.scan import router as server_scan
from cve_api.workflows import router as workflows
from cve_common.release import VERSION
from fastapi import FastAPI


def export(root: Path) -> Path:
    app = FastAPI(title="CVE Dashboard read contracts", version=VERSION)
    for router in [
        ansible,
        vault,
        custom_dashboards,
        personal_groups,
        localization,
        dashboard,
        container_inventory,
        findings,
        reports,
        notifications,
        servers,
        server_scan,
        cve_data,
    ]:
        app.include_router(router)
    app.include_router(workflows)
    target = root / "contracts/api/dashboard-read.openapi.json"
    target.write_text(json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n")
    return target


if __name__ == "__main__":
    export(Path(__file__).resolve().parents[2])
