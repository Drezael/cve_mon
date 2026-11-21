"""The ingress must forward current group operations and retire shared-group paths."""

import re
from dataclasses import replace
from pathlib import Path

from scripts.infrastructure.manage import load_config
from scripts.security.manage import render_auth_route


def test_personal_group_routes_reach_api(tmp_path: Path) -> None:
    config = replace(
        load_config(overrides={"MOUNT_BASE": "./.runtime", "SECRETS_BASE": "./.runtime"}),
        root=tmp_path,
    )
    (config.directory / "snippets").mkdir(parents=True)
    gateway = tmp_path / ".runtime/services" / config.project / "auth-gateway.key"
    gateway.parent.mkdir(parents=True)
    gateway.write_text("test-only-gateway-credential-" + "x" * 32)
    gateway.chmod(0o600)
    render_auth_route(config)
    content = (config.directory / "snippets/administration-routes.conf").read_text()
    patterns = re.findall(r'location ~ "([^"\n]+)"', content)
    server = "134c9b9c-9c32-4f01-94ff-9f9737128fc5"
    for path in (
        "custom-dashboards",
        "custom-dashboards/validate",
        f"custom-dashboards/{server}",
        "groups",
        f"groups/{server}",
        f"servers/{server}/groups",
        f"servers/{server}",
        f"servers/{server}/ansible/test",
    ):
        assert any(re.fullmatch(pattern, "/api/v1/dashboard/" + path) for pattern in patterns), path
    for path in (
        "admin/groups",
        "admin/groups/order",
        f"admin/servers/{server}/group-assignment",
        f"groups/{server}/servers",
        f"security/groups/{server}",
    ):
        assert not any(
            re.fullmatch(pattern, "/api/v1/dashboard/" + path) for pattern in patterns
        ), path
    assert "client_max_body_size 128k" in content
    assert "client_max_body_size 32k" in content


def test_custom_dashboard_deep_links_serve_the_dashboard(tmp_path: Path) -> None:
    from scripts.dashboard.manage import render_static

    config = replace(
        load_config(overrides={"MOUNT_BASE": "./.runtime", "SECRETS_BASE": "./.runtime"}),
        root=tmp_path,
    )
    (config.directory / "snippets").mkdir(parents=True)
    dist = config.directory / "dashboard"
    dist.mkdir()
    (dist / "index.html").write_text("<!doctype html><title>Test dashboard</title>")
    render_static(config)
    content = (config.directory / "snippets/dashboard-static-routes.conf").read_text()
    patterns = re.findall(r'location ~ "([^"\n]+)"', content)
    for path in (
        "/dashboard",
        "/dashboards",
        "/dashboards/new",
        "/dashboards/123/edit",
        "/dashboards/123",
    ):
        assert any(re.fullmatch(pattern, path) for pattern in patterns), path
    assert not any(re.fullmatch(pattern, "/dashboards-unrecognized") for pattern in patterns)
