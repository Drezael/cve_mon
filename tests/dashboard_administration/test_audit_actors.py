"""Audit projection preserves human actors and exposes service attribution under existing RBAC."""

from uuid import uuid4

import pytest

from scripts.database import manage as db
from tests.authorization.integration.conftest import actor, call
from tests.inventory_upload.integration.conftest import Browser

pytestmark = pytest.mark.dashboard_administration


async def test_service_actor_projection_preserves_humans_history_and_reader_scope(
    browser: Browser,
) -> None:
    admin = await actor(browser)
    reader = await actor(browser, ("user_admin",))
    service_id, human_id, technical_id, principal = (uuid4() for _ in range(4))
    with browser.lab.owner() as s:
        s.execute(
            "INSERT INTO security.technical_principals(id,name,status) VALUES(%s,%s,'active')",
            (principal, "inventory-adapter-" + str(principal)),
        )
        s.execute(
            "INSERT INTO security.audit_log(id,actor_user_id,action,object_type,outcome,metadata) "
            "VALUES(%s,%s,'cve.source.completed','cve_import','success','{}')",
            (human_id, reader.id),
        )
    with db.connect(browser.lab.config, "importer") as s:
        s.execute(
            "INSERT INTO security.audit_log(id,action,object_type,outcome,metadata) "
            "VALUES(%s,'cve.source.completed','cve_import','success','{}')",
            (service_id,),
        )
        s.execute(
            "INSERT INTO security.audit_log(id,technical_principal_id,action,object_type,"
            "outcome,metadata) VALUES(%s,%s,'cve.source.completed','cve_import','success','{}')",
            (technical_id, principal),
        )
    identities = [service_id, human_id, technical_id]
    with browser.lab.owner() as s:
        before = s.execute(
            "SELECT * FROM security.audit_log WHERE id=ANY(%s) ORDER BY id", (identities,)
        ).fetchall()
    response = await call(
        browser, admin, "GET", "administration/audit?action=cve.source.completed&limit=100"
    )
    assert response.status_code == 200, response.text
    rows = {r["id"]: r for r in response.json()["items"]}
    assert rows[str(service_id)]["actor_user_id"] is None
    assert rows[str(service_id)]["actor_service"] == "importer"
    assert rows[str(human_id)]["actor_user_id"] == str(reader.id)
    assert rows[str(human_id)]["actor_service"] is None
    assert rows[str(human_id)]["actor_username"] == reader.name
    assert rows[str(service_id)]["actor_username"] is None
    assert rows[str(technical_id)]["actor_service"] == "inventory-adapter-" + str(principal)
    own = await call(
        browser, reader, "GET", "administration/audit?action=cve.source.completed&limit=100"
    )
    assert own.status_code == 200, own.text
    assert {r["id"] for r in own.json()["items"]} == {str(human_id)}
    assert own.json()["items"][0]["actor_username"] == reader.name
    with browser.lab.owner() as s:
        after = s.execute(
            "SELECT * FROM security.audit_log WHERE id=ANY(%s) ORDER BY id", (identities,)
        ).fetchall()
        assert before == after
