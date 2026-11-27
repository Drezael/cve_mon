"""One isolated staged release for the entire Phase-24 campaign."""

import asyncio
import fcntl
import secrets
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest

from scripts.deployment import orchestration, release
from scripts.deployment.contracts import Environment, atomic
from scripts.security import manage as auth
from tests.authentication.integration.conftest import Lab
from tests.inventory_upload.integration.conftest import browser

__all__ = ["browser", "stage", "upload_lab"]


@pytest.fixture(scope="session")
def stage() -> Iterator[tuple[Environment, Path, dict[str, Any]]]:
    root = Path(__file__).resolve().parents[2]
    target_dir = root / ".runtime/phase24-tests" / uuid4().hex
    with (root / ".runtime/hardening/laboratory.lock").open("a") as guard:
        fcntl.flock(guard, fcntl.LOCK_EX)
        bundle = target_dir / "release"
        manifest = release.create("0.24.0-dev.1", bundle)
        target = orchestration.stage(target_dir / "stage")
        target = orchestration.pinned(target, bundle)
        orchestration.prepare(target, bundle)
        try:
            result = orchestration.rollout(target, bundle)
            atomic(target.control / "native-install.json", result)
            yield target, bundle, manifest
        finally:
            orchestration.cleanup_stage(target)


@pytest.fixture(scope="session")
def upload_lab(stage: tuple[Environment, Path, dict[str, Any]]) -> Iterator[Lab]:
    target, _, _ = stage
    assert target.config.project.startswith("cve-db-test-phase24-")
    password = secrets.token_urlsafe(32)
    identity = asyncio.run(
        auth.bootstrap(target.config, "phase24-initial", "initial@example.test", password)
    )
    from tests.inventory_upload.integration.technical_gateway import gateway

    with gateway(target.config):
        yield Lab(target.config, password, UUID(identity))
