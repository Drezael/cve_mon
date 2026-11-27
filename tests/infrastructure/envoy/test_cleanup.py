"""A failed proxy start releases its own sinks and networks without touching existing labs."""

from typing import Any

import pytest

from scripts.infrastructure.manage import docker_command, run
from tests.infrastructure.envoy import conftest

pytestmark = [pytest.mark.egress, pytest.mark.security]


def resources(kind: str) -> set[str]:
    args = [*docker_command(), *(["network", "ls", "-q"] if kind == "network" else ["ps", "-aq"])]
    return set(run([*args, "--filter", "label=org.cve-monitoring.egress-test"]).stdout.split())


def test_failed_setup_preserves_foreign_labs_and_cleans_own_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = {kind: resources(kind) for kind in ("network", "container")}

    def fail(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("injected before proxy startup")

    monkeypatch.setattr(conftest, "start", fail)
    lab = conftest.isolated_envoy_lab()
    with pytest.raises(RuntimeError, match="injected before proxy startup"):
        next(lab)
    assert {kind: resources(kind) for kind in before} == before
