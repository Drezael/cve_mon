"""Reale Forward-Proxy-Requests und exakte Methoden-/Hostgrenzen."""

import pytest

from tests.infrastructure.envoy.conftest import Lab

pytestmark = [pytest.mark.egress, pytest.mark.security]


def test_allowed_http(envoy_lab: Lab) -> None:
    result = envoy_lab.request(kind="http", target="http://http.allowed.test/")
    assert result == {"status": 200, "body": "controlled-egress-target", "location": None}


@pytest.mark.parametrize(
    "target",
    [
        "http://forbidden.example.test/",
        "http://sub.http.allowed.test/",
        "http://http.allowed.test.evil.invalid/",
        "http://http.allowed.test:81/",
        "http://127.0.0.1/",
        "http://169.254.169.254/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://http.allowed.test./",
        "http://2130706433/",
        "http://0x7f000001/",
        "http://http.allowed.test@forbidden.example.test/",
    ],
)
def test_denied_http_never_reaches_sink(envoy_lab: Lab, target: str) -> None:
    before = envoy_lab.counters().get("tcp_80", 0)
    result = envoy_lab.request(kind="http", target=target)
    assert result.get("status") != 200
    assert envoy_lab.counters().get("tcp_80", 0) == before


def test_method_and_service_separation(envoy_lab: Lab) -> None:
    assert (
        envoy_lab.request(kind="http", target="http://http.allowed.test/", method="POST").get(
            "status"
        )
        == 403
    )
    assert (
        envoy_lab.request("enricher", kind="http", target="http://http.allowed.test/").get("status")
        == 403
    )
    assert (
        envoy_lab.request("n8n", kind="http", target="http://http.allowed.test/").get("status")
        == 403
    )


def test_redirect_needs_new_authorization(envoy_lab: Lab) -> None:
    result = envoy_lab.request(kind="http", target="http://http.allowed.test/redirect")
    assert result["status"] == 302
    assert envoy_lab.request(kind="http", target=result["location"]).get("status") == 403


def test_forged_headers_do_not_change_static_upstream(envoy_lab: Lab) -> None:
    result = envoy_lab.request(
        kind="http",
        target="http://forbidden.example.test/",
        headers={
            "X-Forwarded-Host": "http.allowed.test",
            "X-Envoy-Original-Dst-Host": "93.184.216.34:80",
            "X-Envoy-Internal": "true",
            "X-Envoy-Upstream-Rq-Timeout-Ms": "9999999",
        },
    )
    assert result.get("status") == 403


def test_untrusted_proxy_client_and_body_limit(envoy_lab: Lab) -> None:
    assert "error" in envoy_lab.request("intruder", kind="http", target="http://http.allowed.test/")
    result = envoy_lab.request(kind="http", target="http://http.allowed.test/", body="x" * 1048577)
    assert result.get("status") == 413


def test_environment_proxy_and_no_fallback(envoy_lab: Lab) -> None:
    assert envoy_lab.request(kind="variables", target="http://http.allowed.test/")["status"] == 200
    assert "error" in envoy_lab.request(
        kind="http", target="http://http.allowed.test/", proxy_port=3199
    )
    assert "error" in envoy_lab.request(kind="direct", target="93.184.216.34", target_port=80)


def test_missing_proxy_variable_cannot_fall_back(envoy_lab: Lab) -> None:
    import json

    from scripts.infrastructure.manage import docker_command, run

    result = run(
        [
            *docker_command(),
            "exec",
            "-i",
            "-e",
            "HTTP_PROXY=",
            "-e",
            "HTTPS_PROXY=",
            envoy_lab.clients["importer"],
            "python",
            "/fixture/client.py",
        ],
        input=json.dumps({"kind": "variables", "target": "http://http.allowed.test/"}),
    )
    assert json.loads(result.stdout)["error"] == "ValueError"
    assert "error" in envoy_lab.request(kind="direct", target="93.184.216.34", target_port=80)


def test_combined_sources_profile_uses_its_explicit_allowlist(envoy_lab: Lab) -> None:
    assert (
        envoy_lab.request("sources", kind="http", target="http://http.allowed.test/")["status"]
        == 200
    )
    assert envoy_lab.request("sources", kind="https", target="tls.allowed.test")["status"] == 200
    assert (
        envoy_lab.request("sources", kind="http", target="http://forbidden.example.test/")["status"]
        == 403
    )
