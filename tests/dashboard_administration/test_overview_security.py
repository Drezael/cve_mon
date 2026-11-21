"""A non-admin cannot control source imports even if an update permission was granted."""

from uuid import uuid4

import pytest

from tests.authorization.integration.conftest import actor, call
from tests.inventory_upload.integration.conftest import Browser

pytestmark = pytest.mark.dashboard_administration


async def test_overview_update_controls_require_admin(browser: Browser) -> None:
    user = await actor(browser, ("security_analyst",))
    with browser.lab.owner() as db:
        inserted = db.execute(
            "INSERT INTO security.role_permissions(role_id,permission_code) "
            "SELECT id,'cve:update' FROM security.roles WHERE code='security_analyst' "
            "ON CONFLICT DO NOTHING RETURNING role_id"
        ).fetchall()
        before = db.execute(
            "SELECT auto_updates,update_interval FROM automation.workflow_settings WHERE singleton"
        ).fetchone()
    try:
        result = await browser.client.post(
            "/api/v1/dashboard/cve-data/refresh",
            headers={
                "cookie": "__Host-cve-session=" + user.cookie,
                "x-csrf-token": user.csrf,
                "idempotency-key": str(uuid4()),
            },
        )
        assert result.status_code == 403, result.text
        result = await call(
            browser,
            user,
            "PUT",
            "orchestration/settings",
            {"auto_updates": True, "update_interval": 300},
            reauth=False,
        )
        assert result.status_code == 403, result.text
        with browser.lab.owner() as db:
            assert (
                db.execute(
                    "SELECT auto_updates,update_interval FROM automation.workflow_settings "
                    "WHERE singleton"
                ).fetchone()
                == before
            )
    finally:
        if inserted:
            with browser.lab.owner() as db:
                db.execute(
                    "DELETE FROM security.role_permissions "
                    "WHERE role_id=(SELECT id FROM security.roles WHERE code='security_analyst') "
                    "AND permission_code='cve:update'"
                )
